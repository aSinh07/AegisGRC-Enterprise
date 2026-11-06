import {pool} from './db-pool.js';
import crypto from 'node:crypto';import pg from 'pg';import {requireOrgPermission} from './grc-organizations.js';

const key=(p:string)=>p+'-'+new Date().getUTCFullYear()+'-'+crypto.randomBytes(3).toString('hex').toUpperCase();
export function riskBand(score:number){return score>=20?'CRITICAL':score>=15?'HIGH':score>=8?'MEDIUM':score>=4?'LOW':'VERY_LOW'}
export async function initIssueRiskCapa(){await pool.query(`
ALTER TABLE grc_issues ADD COLUMN IF NOT EXISTS scope_control_id uuid REFERENCES grc_scope_controls(id) ON DELETE SET NULL;
ALTER TABLE grc_issues ADD COLUMN IF NOT EXISTS created_by uuid REFERENCES app_users(id) ON DELETE SET NULL;
ALTER TABLE grc_issues ADD COLUMN IF NOT EXISTS closed_by uuid REFERENCES app_users(id) ON DELETE SET NULL;
ALTER TABLE grc_issues ADD COLUMN IF NOT EXISTS closed_at timestamptz;
CREATE TABLE IF NOT EXISTS grc_enterprise_risks(
 id uuid PRIMARY KEY,organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,risk_key text UNIQUE NOT NULL,
 title text NOT NULL,description text NOT NULL DEFAULT '',likelihood int NOT NULL CHECK(likelihood BETWEEN 1 AND 10),impact int NOT NULL CHECK(impact BETWEEN 1 AND 10),
 inherent_score int NOT NULL,inherent_rating text NOT NULL,treatment text NOT NULL CHECK(treatment IN ('MITIGATE','ACCEPT','TRANSFER','AVOID')),
 residual_likelihood int CHECK(residual_likelihood BETWEEN 1 AND 10),residual_impact int CHECK(residual_impact BETWEEN 1 AND 10),residual_score int,residual_rating text,
 owner_user_id uuid REFERENCES app_users(id) ON DELETE SET NULL,status text NOT NULL DEFAULT 'OPEN' CHECK(status IN ('OPEN','TREATMENT','ACCEPTANCE_PENDING','ACCEPTED','CLOSED')),
 methodology_id uuid REFERENCES grc_risk_methodologies(id) ON DELETE SET NULL,acceptance_rationale text,
 acceptance_expires_at timestamptz,accepted_by uuid REFERENCES app_users(id) ON DELETE SET NULL,accepted_at timestamptz,created_by uuid REFERENCES app_users(id) ON DELETE SET NULL,
 created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS grc_issue_risks(issue_id uuid NOT NULL REFERENCES grc_issues(id) ON DELETE CASCADE,risk_id uuid NOT NULL REFERENCES grc_enterprise_risks(id) ON DELETE CASCADE,PRIMARY KEY(issue_id,risk_id));
CREATE INDEX IF NOT EXISTS grc_issue_risks_issue_idx ON grc_issue_risks(issue_id);
CREATE TABLE IF NOT EXISTS grc_capa(
 id uuid PRIMARY KEY,organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,capa_key text UNIQUE NOT NULL,
 issue_id uuid NOT NULL REFERENCES grc_issues(id) ON DELETE CASCADE,root_cause text NOT NULL,corrective_action text NOT NULL,preventive_action text NOT NULL DEFAULT '',
 owner_user_id uuid REFERENCES app_users(id) ON DELETE SET NULL,priority text NOT NULL DEFAULT 'P2',status text NOT NULL DEFAULT 'OPEN' CHECK(status IN ('OPEN','IN_PROGRESS','EVIDENCE_SUBMITTED','RETEST_PENDING','VALIDATION','CHANGES_REQUESTED','CLOSED','OVERDUE')),
 due_at timestamptz NOT NULL,retest_run_id uuid REFERENCES grc_control_test_runs(id) ON DELETE SET NULL,submitted_by uuid REFERENCES app_users(id) ON DELETE SET NULL,
 approved_by uuid REFERENCES app_users(id) ON DELETE SET NULL,closed_at timestamptz,created_by uuid REFERENCES app_users(id) ON DELETE SET NULL,
 created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS grc_capa_issue_idx ON grc_capa(issue_id);
CREATE TABLE IF NOT EXISTS grc_capa_evidence(capa_id uuid NOT NULL REFERENCES grc_capa(id) ON DELETE CASCADE,evidence_version_id uuid NOT NULL REFERENCES grc_evidence_versions(id) ON DELETE RESTRICT,linked_by uuid REFERENCES app_users(id) ON DELETE SET NULL,linked_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(capa_id,evidence_version_id));
CREATE TABLE IF NOT EXISTS grc_record_events(id uuid PRIMARY KEY,organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,record_type text NOT NULL,record_id uuid NOT NULL,event text NOT NULL,actor_user_id uuid REFERENCES app_users(id) ON DELETE SET NULL,reason text,snapshot jsonb NOT NULL DEFAULT '{}'::jsonb,created_at timestamptz NOT NULL DEFAULT now());
ALTER TABLE grc_capa ADD COLUMN IF NOT EXISTS finding_retest_id uuid;
ALTER TABLE grc_enterprise_risks ADD COLUMN IF NOT EXISTS methodology_id uuid REFERENCES grc_risk_methodologies(id) ON DELETE SET NULL;
ALTER TABLE grc_enterprise_risks ADD COLUMN IF NOT EXISTS acceptance_rationale text;
ALTER TABLE grc_enterprise_risks ADD COLUMN IF NOT EXISTS accepted_at timestamptz;
ALTER TABLE grc_enterprise_risks DROP CONSTRAINT IF EXISTS grc_enterprise_risks_likelihood_check;
ALTER TABLE grc_enterprise_risks ADD CONSTRAINT grc_enterprise_risks_likelihood_check CHECK(likelihood BETWEEN 1 AND 10) NOT VALID;
ALTER TABLE grc_enterprise_risks DROP CONSTRAINT IF EXISTS grc_enterprise_risks_impact_check;
ALTER TABLE grc_enterprise_risks ADD CONSTRAINT grc_enterprise_risks_impact_check CHECK(impact BETWEEN 1 AND 10) NOT VALID;
ALTER TABLE grc_enterprise_risks DROP CONSTRAINT IF EXISTS grc_enterprise_risks_residual_likelihood_check;
ALTER TABLE grc_enterprise_risks ADD CONSTRAINT grc_enterprise_risks_residual_likelihood_check CHECK(residual_likelihood IS NULL OR residual_likelihood BETWEEN 1 AND 10) NOT VALID;
ALTER TABLE grc_enterprise_risks DROP CONSTRAINT IF EXISTS grc_enterprise_risks_residual_impact_check;
ALTER TABLE grc_enterprise_risks ADD CONSTRAINT grc_enterprise_risks_residual_impact_check CHECK(residual_impact IS NULL OR residual_impact BETWEEN 1 AND 10) NOT VALID;
CREATE INDEX IF NOT EXISTS grc_capa_org_status_idx ON grc_capa(organization_id,status,due_at);CREATE INDEX IF NOT EXISTS grc_erisk_org_idx ON grc_enterprise_risks(organization_id,status,inherent_score DESC);
CREATE TABLE IF NOT EXISTS grc_remediation_reconciliations(
 id uuid PRIMARY KEY,organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,
 issue_id uuid NOT NULL REFERENCES grc_issues(id) ON DELETE CASCADE,
 canonical_risk_id uuid REFERENCES grc_enterprise_risks(id) ON DELETE SET NULL,
 canonical_capa_id uuid REFERENCES grc_capa(id) ON DELETE SET NULL,
 duplicate_risk_ids jsonb NOT NULL DEFAULT '[]'::jsonb,duplicate_capa_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
 rationale text NOT NULL,reconciled_by uuid REFERENCES app_users(id) ON DELETE SET NULL,reconciled_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(organization_id,issue_id)
);
CREATE INDEX IF NOT EXISTS grc_remediation_reconciliation_org_idx ON grc_remediation_reconciliations(organization_id,reconciled_at DESC);
`)}
type Queryable={query:(text:string,values?:any[])=>Promise<any>};
async function event(org:string,type:string,id:string,eventName:string,actor:string,reason?:string,snapshot:any={},db:Queryable=pool){await db.query('INSERT INTO grc_record_events(id,organization_id,record_type,record_id,event,actor_user_id,reason,snapshot) VALUES($1,$2,$3,$4,$5,$6,$7,$8)',[crypto.randomUUID(),org,type,id,eventName,actor,reason||null,snapshot])}
export async function listIssues(user:string,org:string){await requireOrgPermission(user,org,'read');return (await pool.query('SELECT * FROM grc_issues WHERE organization_id=$1 ORDER BY created_at DESC',[org])).rows}
export async function createRiskFromIssue(user:string,org:string,issueId:string,input:any){
 await requireOrgPermission(user,org,'manageRisk');
 let likelihoodMax=5,impactMax=5,methodologyId:string|null=null,thresholds:any={critical:20,high:15,medium:8,low:4};
 if(input.methodologyId){const m=(await pool.query('SELECT * FROM grc_risk_methodologies WHERE id=$1 AND organization_id=$2',[String(input.methodologyId),org])).rows[0];if(!m)throw Object.assign(new Error('Risk methodology not found in organization'),{statusCode:404});methodologyId=m.id;likelihoodMax=Number(m.likelihood_max);impactMax=Number(m.impact_max);thresholds=m.thresholds||thresholds}
 const l=Number(input.likelihood),i=Number(input.impact);if(!Number.isInteger(l)||!Number.isInteger(i)||l<1||l>likelihoodMax||i<1||i>impactMax)throw new Error('Likelihood and impact exceed the selected risk methodology');
 const score=l*i,band=(s:number)=>s>=Number(thresholds.critical||20)?'CRITICAL':s>=Number(thresholds.high||15)?'HIGH':s>=Number(thresholds.medium||8)?'MEDIUM':s>=Number(thresholds.low||4)?'LOW':'VERY_LOW',t=String(input.treatment||'MITIGATE').toUpperCase();if(!['MITIGATE','ACCEPT','TRANSFER','AVOID'].includes(t))throw new Error('Invalid treatment');
 if(input.ownerUserId)await requireOrgPermission(input.ownerUserId,org,'read');
 const id=crypto.randomUUID(),client=await pool.connect();
 try{
  await client.query('BEGIN');
  const issue=(await client.query('SELECT * FROM grc_issues WHERE id=$1 AND organization_id=$2 FOR UPDATE',[issueId,org])).rows[0];
  if(!issue)throw Object.assign(new Error('Issue not found'),{statusCode:404});
  if(issue.status==='CLOSED')throw Object.assign(new Error('Closed issue cannot create a new risk'),{statusCode:409});
  const existing=(await client.query('SELECT r.* FROM grc_enterprise_risks r JOIN grc_issue_risks ir ON ir.risk_id=r.id WHERE ir.issue_id=$1 ORDER BY r.created_at ASC LIMIT 1',[issueId])).rows[0];if(existing){await client.query('COMMIT');return existing}
  const risk=(await client.query(`INSERT INTO grc_enterprise_risks(id,organization_id,risk_key,title,description,likelihood,impact,inherent_score,inherent_rating,treatment,owner_user_id,status,created_by,methodology_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING *`,[id,org,key('RISK'),String(input.title||issue.title),String(input.description||issue.description||''),l,i,score,band(score),t,input.ownerUserId||null,t==='ACCEPT'?'ACCEPTANCE_PENDING':'TREATMENT',user,methodologyId])).rows[0];
  await client.query('INSERT INTO grc_issue_risks(issue_id,risk_id) VALUES($1,$2)',[issueId,id]);
  await event(org,'RISK',id,'CREATED',user,undefined,{issueId,score,treatment:t},client);
  await client.query('COMMIT');return risk;
 }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}
export async function approveRiskAcceptance(user:string,org:string,riskId:string,input:any){
 await requireOrgPermission(user,org,'review');
 const reason=String(input.reason||'').trim();if(reason.length<10)throw new Error('Risk acceptance requires a meaningful rationale');
 const expiry=new Date(String(input.expiresAt||''));if(!Number.isFinite(expiry.getTime())||expiry<=new Date())throw new Error('Future acceptance expiry required');
 const client=await pool.connect();
 try{
  await client.query('BEGIN');
  const r=(await client.query('SELECT * FROM grc_enterprise_risks WHERE id=$1 AND organization_id=$2 FOR UPDATE',[riskId,org])).rows[0];
  if(!r)throw Object.assign(new Error('Risk not found'),{statusCode:404});
  if(r.treatment!=='ACCEPT'||r.status!=='ACCEPTANCE_PENDING')throw Object.assign(new Error('Risk is not awaiting acceptance'),{statusCode:409});
  if(r.created_by===user||r.owner_user_id===user)throw Object.assign(new Error('Risk creator/owner cannot approve own acceptance'),{statusCode:409});
  const out=(await client.query(`UPDATE grc_enterprise_risks SET status='ACCEPTED',acceptance_expires_at=$2,accepted_by=$3,acceptance_rationale=$5,accepted_at=now(),updated_at=now() WHERE id=$1 AND organization_id=$4 AND status='ACCEPTANCE_PENDING' RETURNING *`,[riskId,expiry,user,org,reason])).rows[0];
  if(!out)throw Object.assign(new Error('Risk state changed before acceptance'),{statusCode:409});
  await event(org,'RISK',riskId,'RISK_ACCEPTED',user,reason,{expiresAt:expiry.toISOString()},client);
  await client.query('COMMIT');return out;
 }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}
export async function createCapa(user:string,org:string,issueId:string,input:any){
 await requireOrgPermission(user,org,'manageRisk');
 const root=String(input.rootCause||'').trim(),action=String(input.correctiveAction||'').trim();if(root.length<5||action.length<5)throw new Error('Root cause and corrective action are required');
 const due=new Date(String(input.dueAt||''));if(!Number.isFinite(due.getTime())||due<=new Date())throw new Error('Future CAPA due date required');
 if(input.ownerUserId)await requireOrgPermission(input.ownerUserId,org,'read');
 const id=crypto.randomUUID(),client=await pool.connect();
 try{
  await client.query('BEGIN');
  const issue=(await client.query('SELECT * FROM grc_issues WHERE id=$1 AND organization_id=$2 FOR UPDATE',[issueId,org])).rows[0];
  if(!issue)throw Object.assign(new Error('Issue not found'),{statusCode:404});
  if(issue.status==='CLOSED')throw Object.assign(new Error('Closed issue cannot create CAPA'),{statusCode:409});
  const existing=(await client.query('SELECT * FROM grc_capa WHERE organization_id=$1 AND issue_id=$2 ORDER BY created_at ASC LIMIT 1',[org,issueId])).rows[0];if(existing){await client.query('COMMIT');return existing}
  const row=(await client.query(`INSERT INTO grc_capa(id,organization_id,capa_key,issue_id,root_cause,corrective_action,preventive_action,owner_user_id,priority,due_at,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *`,[id,org,key('CAPA'),issueId,root,action,String(input.preventiveAction||''),input.ownerUserId||null,String(input.priority||issue.priority||'P2'),due,user])).rows[0];
  await event(org,'CAPA',id,'CREATED',user,undefined,{issueId},client);
  await client.query('COMMIT');return row;
 }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}
export async function submitCapaEvidence(user:string,org:string,capaId:string,evidenceVersionId:string){
 const m=await requireOrgPermission(user,org,'manageControl');const client=await pool.connect();
 try{
  await client.query('BEGIN');
  const c=(await client.query('SELECT * FROM grc_capa WHERE id=$1 AND organization_id=$2 FOR UPDATE',[capaId,org])).rows[0];
  if(!c)throw Object.assign(new Error('CAPA not found'),{statusCode:404});
  if(!['OPEN','IN_PROGRESS','EVIDENCE_SUBMITTED','CHANGES_REQUESTED'].includes(c.status))throw Object.assign(new Error('CAPA is not accepting evidence in its current state'),{statusCode:409});
  if(c.owner_user_id&&c.owner_user_id!==user&&!['ORG_ADMIN','GRC_MANAGER','GRC_ANALYST'].includes(m.role))throw Object.assign(new Error('CAPA owner required'),{statusCode:403});
  const issue=(await client.query('SELECT scope_control_id FROM grc_issues WHERE id=$1 AND organization_id=$2 FOR UPDATE',[c.issue_id,org])).rows[0];
  const ev=(await client.query(`SELECT v.id,r.scope_control_id FROM grc_evidence_versions v JOIN grc_evidence_requests r ON r.id=v.evidence_request_id WHERE v.id=$1 AND r.organization_id=$2 AND r.status='VALID' AND v.integrity_status='SERVER_VERIFIED' AND v.validated_at IS NOT NULL AND v.valid_until>now() FOR UPDATE OF v,r`,[evidenceVersionId,org])).rows[0];
  if(!ev)throw new Error('Current validated evidence version required');
  if(issue?.scope_control_id&&ev.scope_control_id!==issue.scope_control_id)throw Object.assign(new Error('CAPA evidence must belong to the affected control'),{statusCode:409});
  await client.query('INSERT INTO grc_capa_evidence(capa_id,evidence_version_id,linked_by) VALUES($1,$2,$3) ON CONFLICT DO NOTHING',[capaId,evidenceVersionId,user]);
  const out=(await client.query(`UPDATE grc_capa SET status='RETEST_PENDING',submitted_by=$2,updated_at=now() WHERE id=$1 AND status = ANY($3::text[]) RETURNING *`,[capaId,user,['OPEN','IN_PROGRESS','EVIDENCE_SUBMITTED','CHANGES_REQUESTED']])).rows[0];
  if(!out)throw Object.assign(new Error('CAPA state changed before evidence submission'),{statusCode:409});
  await event(org,'CAPA',capaId,'EVIDENCE_SUBMITTED',user,undefined,{evidenceVersionId},client);
  await client.query('COMMIT');return out;
 }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}
export async function attachRetest(user:string,org:string,capaId:string,testRunId:string){
 await requireOrgPermission(user,org,'review');const client=await pool.connect();
 try{
  await client.query('BEGIN');
  const c=(await client.query('SELECT * FROM grc_capa WHERE id=$1 AND organization_id=$2 FOR UPDATE',[capaId,org])).rows[0];
  if(!c)throw Object.assign(new Error('CAPA not found'),{statusCode:404});
  if(c.status!=='RETEST_PENDING'&&c.status!=='CHANGES_REQUESTED')throw Object.assign(new Error('CAPA is not ready for retest'),{statusCode:409});
  const run=(await client.query(`SELECT r.*,d.scope_control_id FROM grc_control_test_runs r JOIN grc_control_test_definitions d ON d.id=r.test_definition_id WHERE r.id=$1 AND r.organization_id=$2 FOR UPDATE OF r,d`,[testRunId,org])).rows[0];
  if(!run)throw new Error('Retest run not found');
  const issue=(await client.query('SELECT scope_control_id FROM grc_issues WHERE id=$1 AND organization_id=$2 FOR UPDATE',[c.issue_id,org])).rows[0];
  if(issue?.scope_control_id&&run.scope_control_id!==issue.scope_control_id)throw Object.assign(new Error('CAPA retest must test the affected control'),{statusCode:409});
  if(run.result!=='PASS'&&run.result!=='FAIL')throw Object.assign(new Error('Retest must have a deterministic PASS or FAIL result'),{statusCode:409});
  const status=run.result==='PASS'?'VALIDATION':'CHANGES_REQUESTED';
  const out=(await client.query(`UPDATE grc_capa SET retest_run_id=$2,status=$3,updated_at=now() WHERE id=$1 AND status = ANY($4::text[]) RETURNING *`,[capaId,testRunId,status,['RETEST_PENDING','CHANGES_REQUESTED']])).rows[0];
  if(!out)throw Object.assign(new Error('CAPA state changed before retest attachment'),{statusCode:409});
  await event(org,'CAPA',capaId,'RETEST_'+run.result,user,run.rationale,{testRunId},client);
  await client.query('COMMIT');return out;
 }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}
export async function closeCapa(user:string,org:string,capaId:string,input:any){
 await requireOrgPermission(user,org,'review');
 const client=await pool.connect();
 try{
  await client.query('BEGIN');
  const c=(await client.query(`SELECT c.*,r.result retest_result,fr.id finding_retest_proof,fr.created_by finding_retest_by FROM grc_capa c LEFT JOIN grc_control_test_runs r ON r.id=c.retest_run_id LEFT JOIN finding_retests fr ON fr.id=c.finding_retest_id WHERE c.id=$1 AND c.organization_id=$2 FOR UPDATE OF c`,[capaId,org])).rows[0];
  if(!c)throw Object.assign(new Error('CAPA not found'),{statusCode:404});
  const validatedByControlTest=c.retest_result==='PASS',validatedByFindingRetest=Boolean(c.finding_retest_proof);
  if(c.status!=='VALIDATION'||(!validatedByControlTest&&!validatedByFindingRetest))throw Object.assign(new Error('Validated control-test or targeted finding-retest proof required'),{statusCode:409});
  if(c.created_by===user||c.owner_user_id===user||c.submitted_by===user||c.finding_retest_by===user)throw Object.assign(new Error('Independent reviewer required for CAPA closure; creator, owner, submitter or targeted-retest operator cannot approve'),{statusCode:409});
  const out=(await client.query(`UPDATE grc_capa SET status='CLOSED',approved_by=$2,closed_at=now(),updated_at=now() WHERE id=$1 AND status='VALIDATION' RETURNING *`,[capaId,user])).rows[0];
  if(!out)throw Object.assign(new Error('CAPA state changed before closure'),{statusCode:409});
  await client.query(`UPDATE grc_issues SET status='CLOSED',closed_by=$2,closed_at=now(),updated_at=now() WHERE id=$1`,[c.issue_id,user]);
  // Lifecycle: the independently reviewed closure becomes control evidence on the affected scoped control.
  const issueRow=(await client.query('SELECT scope_control_id,finding_id,assessment_id FROM grc_issues WHERE id=$1',[c.issue_id])).rows[0];
  if(issueRow?.scope_control_id){
   const retestEv=c.finding_retest_id?(await client.query('SELECT fr.evidence_id,e.sha256 FROM finding_retests fr LEFT JOIN evidence e ON e.id=fr.evidence_id WHERE fr.id=$1',[c.finding_retest_id])).rows[0]:null;
   const ref={type:c.finding_retest_id?'CAPA_CLOSURE_FINDING_RETEST':'CAPA_CLOSURE_CONTROL_TEST',capaId,issueId:c.issue_id,findingId:issueRow.finding_id||null,assessmentId:issueRow.assessment_id||null,findingRetestId:c.finding_retest_id||null,controlTestRunId:c.retest_run_id||null,evidenceId:retestEv?.evidence_id||null,evidenceSha256:retestEv?.sha256||null,independentReviewer:user,closedAt:new Date().toISOString()};
   await client.query(`UPDATE grc_scope_controls SET evidence_refs=evidence_refs||jsonb_build_array($2::jsonb),updated_at=now() WHERE id=$1`,[issueRow.scope_control_id,ref]);
   await event(org,'CAPA',capaId,'CONTROL_EVIDENCE_LINKED',user,undefined,{scopeControlId:issueRow.scope_control_id,...ref},client);
  }
  await event(org,'CAPA',capaId,'CLOSED',user,String(input.reason||''),{retestRunId:c.retest_run_id,findingRetestId:c.finding_retest_id,validationSource:c.finding_retest_id?'TARGETED_FINDING_RETEST':'CONTROL_TEST'},client);
  await client.query('COMMIT');return out;
 }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}
export async function listCapa(user:string,org:string){await requireOrgPermission(user,org,'read');return (await pool.query(`SELECT c.*,CASE WHEN c.status<>'CLOSED' AND c.due_at<now() THEN true ELSE false END AS overdue FROM grc_capa c WHERE organization_id=$1 ORDER BY due_at ASC`,[org])).rows}
export async function listEnterpriseRisks(user:string,org:string){await requireOrgPermission(user,org,'read');return (await pool.query('SELECT * FROM grc_enterprise_risks WHERE organization_id=$1 ORDER BY inherent_score DESC,created_at DESC',[org])).rows}

export async function remediationIntegrity(user:string,org:string){
 await requireOrgPermission(user,org,'read');
 const rows=(await pool.query(`SELECT i.id issue_id,i.issue_key,i.title,
 array_agg(DISTINCT ir.risk_id) FILTER(WHERE ir.risk_id IS NOT NULL) risk_ids,
 array_agg(DISTINCT c.id) FILTER(WHERE c.id IS NOT NULL) capa_ids,
 rr.id reconciliation_id,rr.canonical_risk_id,rr.canonical_capa_id,rr.reconciled_at
 FROM grc_issues i
 LEFT JOIN grc_issue_risks ir ON ir.issue_id=i.id
 LEFT JOIN grc_capa c ON c.issue_id=i.id AND c.organization_id=i.organization_id
 LEFT JOIN grc_remediation_reconciliations rr ON rr.issue_id=i.id AND rr.organization_id=i.organization_id
 WHERE i.organization_id=$1 GROUP BY i.id,rr.id
 HAVING count(DISTINCT ir.risk_id)>1 OR count(DISTINCT c.id)>1
 ORDER BY i.created_at ASC`,[org])).rows;
 return {issues:rows,unresolved:rows.filter((x:any)=>!x.reconciliation_id).length,boundary:'Reconciliation preserves all historical Risk/CAPA records. It designates canonical records for duplicate legacy issue links and never deletes governance history.'};
}
export async function reconcileRemediationDuplicates(user:string,org:string,issueId:string,input:any){
 await requireOrgPermission(user,org,'review');
 const rationale=String(input?.rationale||'').trim();if(rationale.length<10)throw Object.assign(new Error('Meaningful reconciliation rationale required'),{statusCode:400});
 const client=await pool.connect();
 try{
  await client.query('BEGIN');
  const issue=(await client.query('SELECT id FROM grc_issues WHERE id=$1 AND organization_id=$2 FOR UPDATE',[issueId,org])).rows[0];if(!issue)throw Object.assign(new Error('Issue not found'),{statusCode:404});
  const risks=(await client.query('SELECT r.id FROM grc_enterprise_risks r JOIN grc_issue_risks ir ON ir.risk_id=r.id WHERE ir.issue_id=$1 AND r.organization_id=$2 ORDER BY r.created_at ASC,r.id ASC',[issueId,org])).rows.map((x:any)=>x.id);
  const capas=(await client.query('SELECT id FROM grc_capa WHERE issue_id=$1 AND organization_id=$2 ORDER BY created_at ASC,id ASC',[issueId,org])).rows.map((x:any)=>x.id);
  if(risks.length<=1&&capas.length<=1)throw Object.assign(new Error('No duplicate Risk/CAPA records require reconciliation'),{statusCode:409});
  const canonicalRiskId=risks[0]||null,canonicalCapaId=capas[0]||null;
  const row=(await client.query(`INSERT INTO grc_remediation_reconciliations(id,organization_id,issue_id,canonical_risk_id,canonical_capa_id,duplicate_risk_ids,duplicate_capa_ids,rationale,reconciled_by)
   VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
   ON CONFLICT(organization_id,issue_id) DO UPDATE SET canonical_risk_id=EXCLUDED.canonical_risk_id,canonical_capa_id=EXCLUDED.canonical_capa_id,duplicate_risk_ids=EXCLUDED.duplicate_risk_ids,duplicate_capa_ids=EXCLUDED.duplicate_capa_ids,rationale=EXCLUDED.rationale,reconciled_by=EXCLUDED.reconciled_by,reconciled_at=now() RETURNING *`,
   [crypto.randomUUID(),org,issueId,canonicalRiskId,canonicalCapaId,JSON.stringify(risks.slice(1)),JSON.stringify(capas.slice(1)),rationale,user])).rows[0];
  await event(org,'ISSUE',issueId,'REMEDIATION_DUPLICATES_RECONCILED',user,rationale,{canonicalRiskId,canonicalCapaId,duplicateRiskIds:risks.slice(1),duplicateCapaIds:capas.slice(1),historyPreserved:true},client);
  await client.query('COMMIT');return row;
 }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}

export async function reconcileAllRemediationDuplicates(user:string,org:string,input:any={}){
 await requireOrgPermission(user,org,'review');
 const rationale=String(input?.rationale||'Legacy duplicate remediation records reconciled in bulk; earliest governed records retained as canonical and all historical records preserved.').trim();
 if(rationale.length<10)throw Object.assign(new Error('Meaningful reconciliation rationale required'),{statusCode:400});
 const integrity=await remediationIntegrity(user,org),pending=(integrity.issues||[]).filter((x:any)=>!x.reconciliation_id),results:any[]=[];
 for(const issue of pending)results.push(await reconcileRemediationDuplicates(user,org,String(issue.issue_id),{rationale}));
 const after=await remediationIntegrity(user,org);
 return {reconciled:results.length,unresolved:after.unresolved,issues:after.issues,boundary:after.boundary};
}
