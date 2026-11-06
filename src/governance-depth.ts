import crypto from 'node:crypto';
import PDFDocument from 'pdfkit';
import * as XLSX from 'xlsx';
import {pool} from './db-pool.js';
import {requireOrgPermission} from './grc-organizations.js';
import {soaWithGates} from './soa-gates.js';

// Phase 2 "GRC depth": policy version history, asset ↔ control/risk/finding links, the
// compliance dashboard, SoA exports with the five gates, scan schedules and notifications.

export async function initGovernanceDepth(){await pool.query(`
 CREATE TABLE IF NOT EXISTS grc_policy_versions(
  id uuid PRIMARY KEY,organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,
  policy_id uuid NOT NULL REFERENCES grc_policies(id) ON DELETE CASCADE,version text NOT NULL,title text NOT NULL,
  content_ref text NOT NULL,approved_by uuid REFERENCES app_users(id) ON DELETE SET NULL,approved_at timestamptz,
  superseded_at timestamptz NOT NULL DEFAULT now(),change_summary text,created_by uuid REFERENCES app_users(id) ON DELETE SET NULL,
  UNIQUE(policy_id,version)
 );
 CREATE TABLE IF NOT EXISTS grc_asset_links(
  organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,
  asset_id uuid NOT NULL REFERENCES assessment_assets(id) ON DELETE CASCADE,
  link_type text NOT NULL CHECK(link_type IN ('SCOPE_CONTROL','RISK','FINDING','ISSUE','THIRD_PARTY')),
  record_id uuid NOT NULL,created_by uuid REFERENCES app_users(id) ON DELETE SET NULL,created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(asset_id,link_type,record_id)
 );
 CREATE TABLE IF NOT EXISTS grc_scan_schedules(
  id uuid PRIMARY KEY,organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,
  assessment_id uuid NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,profile text NOT NULL CHECK(profile IN ('QUICK','STANDARD','DEEP')),
  interval_days int NOT NULL CHECK(interval_days BETWEEN 1 AND 365),next_run_at timestamptz NOT NULL,enabled boolean NOT NULL DEFAULT true,
  last_run_at timestamptz,last_result text,created_by uuid NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,created_at timestamptz NOT NULL DEFAULT now()
 );
 CREATE INDEX IF NOT EXISTS grc_scan_schedules_due_idx ON grc_scan_schedules(enabled,next_run_at);
 CREATE TABLE IF NOT EXISTS grc_reminder_outbox(
  id uuid PRIMARY KEY,organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,
  kind text NOT NULL CHECK(kind IN ('EVIDENCE_EXPIRING','EVIDENCE_EXPIRED','ISSUE_SLA_BREACHED','CAPA_DUE_SOON','CAPA_OVERDUE','POLICY_REVIEW_DUE','SCAN_SCHEDULE_FAILED','DEEP_SCAN_APPROVAL_PENDING')),
  recipient_user_id uuid REFERENCES app_users(id) ON DELETE CASCADE,record_type text NOT NULL,record_id uuid NOT NULL,
  subject text NOT NULL,body text NOT NULL,dedupe_key text NOT NULL UNIQUE,
  status text NOT NULL DEFAULT 'PENDING' CHECK(status IN ('PENDING','SENT','FAILED','SKIPPED')),attempts int NOT NULL DEFAULT 0,error text,
  created_at timestamptz NOT NULL DEFAULT now(),sent_at timestamptz
 );
 CREATE INDEX IF NOT EXISTS grc_reminder_outbox_status_idx ON grc_reminder_outbox(status,created_at);
 CREATE INDEX IF NOT EXISTS grc_reminder_outbox_org_idx ON grc_reminder_outbox(organization_id,created_at DESC);
`)}

const err=(m:string,statusCode:number)=>Object.assign(new Error(m),{statusCode});
async function recordEvent(org:string,type:string,id:string,event:string,actor:string,snapshot:Record<string,unknown>){
 await pool.query(`INSERT INTO grc_record_events(id,organization_id,record_type,record_id,event,actor_user_id,snapshot) VALUES($1,$2,$3,$4,$5,$6,$7)`,[crypto.randomUUID(),org,type,id,event,actor,snapshot]);
}

// ── Policy versioning ───────────────────────────────────────────────────────
export function nextPolicyVersion(v:string){const m=/^(\d+)\.(\d+)$/.exec(String(v||'').trim());return m?m[1]+'.'+(Number(m[2])+1):'1.1'}
/** Start a new draft of an APPROVED policy. The approved text is frozen in grc_policy_versions; staff must acknowledge the new version again. */
export async function revisePolicy(user:string,org:string,policyId:string,input:{contentRef?:string;changeSummary?:string;version?:string}){
 await requireOrgPermission(user,org,'manageControl');
 const summary=String(input.changeSummary||'').trim();if(summary.length<5)throw err('A change summary is required',400);
 const c=await pool.connect();
 try{
  await c.query('BEGIN');
  const p=(await c.query('SELECT * FROM grc_policies WHERE id=$1 AND organization_id=$2 FOR UPDATE',[policyId,org])).rows[0];
  if(!p)throw err('Policy not found',404);
  if(p.status!=='APPROVED')throw err('Only an APPROVED policy can be revised (current: '+p.status+')',409);
  const version=String(input.version||nextPolicyVersion(p.version));
  if(version===p.version)throw err('The new version must differ from the approved one',400);
  await c.query(`INSERT INTO grc_policy_versions(id,organization_id,policy_id,version,title,content_ref,approved_by,approved_at,change_summary,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,[crypto.randomUUID(),org,policyId,p.version,p.title,p.content_ref,p.approved_by,p.approved_at,summary,user]);
  const out=(await c.query(`UPDATE grc_policies SET version=$3,status='DRAFT',content_ref=COALESCE($4,content_ref),approved_by=NULL,approved_at=NULL,updated_at=now() WHERE id=$1 AND organization_id=$2 RETURNING *`,[policyId,org,version,input.contentRef?String(input.contentRef):null])).rows[0];
  await c.query(`INSERT INTO grc_record_events(id,organization_id,record_type,record_id,event,actor_user_id,snapshot) VALUES($1,$2,'POLICY',$3,'NEW_VERSION_DRAFTED',$4,$5)`,[crypto.randomUUID(),org,policyId,user,{from:p.version,to:version,changeSummary:summary}]);
  await c.query('COMMIT');return out;
 }catch(e){await c.query('ROLLBACK');throw e}finally{c.release()}
}
export async function policyVersionHistory(user:string,org:string,policyId:string){
 await requireOrgPermission(user,org,'read');
 const current=(await pool.query('SELECT id,policy_key,title,version,status,approved_by,approved_at,next_review_at FROM grc_policies WHERE id=$1 AND organization_id=$2',[policyId,org])).rows[0];
 if(!current)throw err('Policy not found',404);
 const history=(await pool.query('SELECT version,title,content_ref,approved_by,approved_at,superseded_at,change_summary FROM grc_policy_versions WHERE policy_id=$1 ORDER BY superseded_at DESC',[policyId])).rows;
 const members=Number((await pool.query(`SELECT count(*) c FROM grc_organization_members WHERE organization_id=$1 AND status='ACTIVE'`,[org])).rows[0].c);
 const acks=Number((await pool.query('SELECT count(*) c FROM grc_policy_attestations WHERE policy_id=$1 AND version=$2',[policyId,current.version])).rows[0].c);
 return {current,history,acknowledgement:{version:current.version,acknowledged:acks,members,percent:members?Math.round(acks/members*100):0}};
}

// ── Asset inventory links ───────────────────────────────────────────────────
const LINK_TABLE:Record<string,string>={SCOPE_CONTROL:'grc_scope_controls',RISK:'grc_enterprise_risks',ISSUE:'grc_issues',THIRD_PARTY:'grc_third_parties'};
export async function linkAsset(user:string,org:string,assetId:string,input:{linkType:string;recordId:string}){
 await requireOrgPermission(user,org,'manageControl');
 const type=String(input.linkType||'').toUpperCase(),rid=String(input.recordId||'');
 if(!['SCOPE_CONTROL','RISK','FINDING','ISSUE','THIRD_PARTY'].includes(type))throw err('linkType must be SCOPE_CONTROL, RISK, FINDING, ISSUE or THIRD_PARTY',400);
 if(!(await pool.query('SELECT 1 FROM assessment_assets WHERE id=$1 AND organization_id=$2',[assetId,org])).rowCount)throw err('Asset not found in organization',404);
 const owned=type==='FINDING'
  ?(await pool.query('SELECT 1 FROM findings f JOIN assessments a ON a.id=f.assessment_id WHERE f.id=$1 AND a.organization_id=$2',[rid,org])).rowCount
  :(await pool.query(`SELECT 1 FROM ${LINK_TABLE[type]} WHERE id=$1 AND organization_id=$2`,[rid,org]).catch(()=>({rowCount:0}))).rowCount;
 if(!owned)throw err('Linked record not found in organization',404);
 await pool.query('INSERT INTO grc_asset_links(organization_id,asset_id,link_type,record_id,created_by) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING',[org,assetId,type,rid,user]);
 await recordEvent(org,'ASSET',assetId,'LINKED_'+type,user,{recordId:rid});
 return assetProfile(user,org,assetId);
}
export async function assetProfile(user:string,org:string,assetId:string){
 await requireOrgPermission(user,org,'read');
 const asset=(await pool.query('SELECT * FROM assessment_assets WHERE id=$1 AND organization_id=$2',[assetId,org])).rows[0];if(!asset)throw err('Asset not found',404);
 const links=(await pool.query('SELECT link_type,record_id,created_at FROM grc_asset_links WHERE asset_id=$1 ORDER BY created_at',[assetId])).rows;
 const ids=(t:string)=>links.filter((l:any)=>l.link_type===t).map((l:any)=>l.record_id);
 const q=async(sql:string,a:string[])=>a.length?(await pool.query(sql,[a])).rows:[];
 return {asset,controls:await q(`SELECT sc.id,c.control_key,c.title,sc.implementation FROM grc_scope_controls sc JOIN grc_canonical_controls c ON c.id=sc.control_id WHERE sc.id=ANY($1::uuid[])`,ids('SCOPE_CONTROL')),
  risks:await q('SELECT id,risk_key,title,inherent_rating,status FROM grc_enterprise_risks WHERE id=ANY($1::uuid[])',ids('RISK')),
  issues:await q('SELECT id,issue_key,title,status,due_at FROM grc_issues WHERE id=ANY($1::uuid[])',ids('ISSUE')),
  findings:await q(`SELECT id,severity,source,payload->>'title' AS title,payload->>'status' AS status FROM findings WHERE id=ANY($1::uuid[])`,ids('FINDING')),
  thirdParties:ids('THIRD_PARTY')};
}

// ── Compliance dashboard ────────────────────────────────────────────────────
export async function complianceDashboard(user:string,org:string){
 await requireOrgPermission(user,org,'read');
 const scopes=(await pool.query(`SELECT id,name FROM grc_scopes WHERE organization_id=$1 AND status='ACTIVE' ORDER BY created_at`,[org])).rows;
 const statusByControl=new Map<string,string>();
 for(const s of scopes){const soa=await soaWithGates(user,org,s.id);for(const c of soa.controls){const prev=statusByControl.get(c.controlKey);const rank=(x?:string)=>x==='PASS'?3:x==='NOT_APPLICABLE'?2:x==='CONDITIONAL'?1:0;if(!prev||rank(c.status)<rank(prev))statusByControl.set(c.controlKey,c.status)}}
 const reqs=(await pool.query(`SELECT fr.framework,fr.framework_version,fr.requirement_key,array_agg(c.control_key) AS controls FROM grc_framework_requirements fr JOIN grc_control_framework_mappings m ON m.requirement_id=fr.id JOIN grc_canonical_controls c ON c.id=m.control_id WHERE fr.active GROUP BY fr.id`)).rows;
 const fw=new Map<string,{framework:string;version:string;requirements:number;inScope:number;passing:number}>();
 for(const r of reqs){const k=r.framework+' '+r.framework_version;const e=fw.get(k)||{framework:r.framework,version:r.framework_version,requirements:0,inScope:0,passing:0};e.requirements++;
  const st=(r.controls as string[]).map(c=>statusByControl.get(c)).filter(Boolean) as string[];
  if(st.length){e.inScope++;if(st.every(x=>x==='PASS'||x==='NOT_APPLICABLE'))e.passing++}fw.set(k,e)}
 const frameworks=[...fw.values()].filter(x=>x.inScope>0).map(x=>({...x,coveragePercent:Math.round(x.passing/Math.max(1,x.inScope)*100)})).sort((a,b)=>a.framework.localeCompare(b.framework));
 const freshness=(await pool.query(`SELECT count(*) FILTER (WHERE v.valid_until>now()+interval '30 days') AS current,count(*) FILTER (WHERE v.valid_until BETWEEN now() AND now()+interval '30 days') AS expiring,count(*) FILTER (WHERE v.valid_until<now()) AS expired,count(*) FILTER (WHERE v.valid_until IS NULL) AS no_expiry
  FROM grc_evidence_versions v JOIN grc_evidence_requests r ON r.id=v.evidence_request_id WHERE r.organization_id=$1 AND v.validated_at IS NOT NULL`,[org])).rows[0];
 const risks=(await pool.query(`SELECT inherent_rating AS rating,count(*)::int AS open FROM grc_enterprise_risks WHERE organization_id=$1 AND status NOT IN ('ACCEPTED','CLOSED') GROUP BY 1`,[org])).rows;
 const capa=(await pool.query(`SELECT count(*) FILTER (WHERE age<=30)::int AS d0_30,count(*) FILTER (WHERE age>30 AND age<=60)::int AS d31_60,count(*) FILTER (WHERE age>60 AND age<=90)::int AS d61_90,count(*) FILTER (WHERE age>90)::int AS d90_plus,count(*) FILTER (WHERE overdue)::int AS overdue,count(*)::int AS open
  FROM (SELECT extract(day FROM now()-created_at) AS age,(due_at<now()) AS overdue FROM grc_capa WHERE organization_id=$1 AND status<>'CLOSED') x`,[org])).rows[0];
 const controls={pass:0,conditional:0,actionRequired:0,notApplicable:0};
 for(const s of statusByControl.values()){if(s==='PASS')controls.pass++;else if(s==='CONDITIONAL')controls.conditional++;else if(s==='NOT_APPLICABLE')controls.notApplicable++;else controls.actionRequired++}
 const order=['CRITICAL','HIGH','MEDIUM','LOW','VERY_LOW'];
 return {organizationId:org,generatedAt:new Date().toISOString(),scopes:scopes.length,controls,frameworks,
  evidenceFreshness:{current:Number(freshness.current),expiringIn30Days:Number(freshness.expiring),expired:Number(freshness.expired),noExpiry:Number(freshness.no_expiry)},
  openRisksByRating:order.map(r=>({rating:r,open:Number(risks.find((x:any)=>x.rating===r)?.open||0)})),capaAgeing:capa};
}

// ── SoA exports (signed by the caller through report records) ───────────────
export function soaXlsx(soa:Awaited<ReturnType<typeof soaWithGates>>){
 const wb=XLSX.utils.book_new();
 const rows=soa.controls.map(c=>({Control:c.controlKey,Title:c.title,Status:c.status,Applicability:c.applicability,Justification:c.justification||'',Implementation:c.implementation,
  ...Object.fromEntries(c.gates.map(g=>['G'+g.gate+' '+g.name,(g.passed?'PASS':'FAIL')+' – '+g.reason])),Frameworks:(c.mappings as any[]).map(m=>m.framework+' '+m.key).join(', ')}));
 XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet(rows),'SoA');
 XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet([{Scope:soa.scope.name,Generated:soa.generatedAt,...soa.summary,Note:soa.disclaimer}]),'Summary');
 return XLSX.write(wb,{type:'buffer',bookType:'xlsx'}) as Buffer;
}
export function soaPdf(soa:Awaited<ReturnType<typeof soaWithGates>>){return new Promise<Buffer>((resolve,reject)=>{
 const doc=new PDFDocument({size:'A4',layout:'landscape',margin:36});const chunks:Buffer[]=[];doc.on('data',c=>chunks.push(c));doc.on('end',()=>resolve(Buffer.concat(chunks)));doc.on('error',reject);
 doc.fontSize(16).text('Statement of Applicability · '+soa.scope.name);doc.moveDown(0.3).fontSize(9).fillColor('#444').text('Generated '+soa.generatedAt+' · '+soa.summary.total+' controls · PASS '+soa.summary.pass+' · CONDITIONAL '+soa.summary.conditional+' · ACTION_REQUIRED '+soa.summary.actionRequired+' · N/A '+soa.summary.notApplicable);
 doc.moveDown(0.3).text('Gates: 1 '+soa.gateNames[0]+' · 2 '+soa.gateNames[1]+' · 3 '+soa.gateNames[2]+' · 4 '+soa.gateNames[3]+' · 5 '+soa.gateNames[4]).fillColor('#000').moveDown(0.6);
 for(const c of soa.controls){
  if(doc.y>500)doc.addPage();
  doc.fontSize(10).font('Helvetica-Bold').text(c.controlKey+'  '+c.title+'  ['+c.status+']');
  doc.font('Helvetica').fontSize(8).text('Applicability: '+c.applicability+(c.justification?' – '+c.justification:'')+' · Implementation: '+c.implementation);
  doc.text(c.gates.map(g=>'G'+g.gate+' '+(g.passed?'✓':'✗')+' '+g.reason).join('   '));
  const fw=(c.mappings as any[]).map(m=>m.framework+' '+m.key);if(fw.length)doc.fillColor('#555').text('Maps to: '+fw.slice(0,30).join(', ')+(fw.length>30?' …':'')).fillColor('#000');
  doc.moveDown(0.4);
 }
 doc.moveDown().fontSize(7).fillColor('#666').text(soa.disclaimer);doc.end();
})}
