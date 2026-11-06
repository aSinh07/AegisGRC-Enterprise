import crypto from 'node:crypto';
import {pool} from './db-pool.js';
import {requireOrgPermission} from './grc-organizations.js';
import {promoteFindingToIssue} from './finding-risk.js';
import {createRiskFromIssue,createCapa} from './grc-remediation.js';
import type {Severity} from './models.js';

// Policy-driven Finding → Issue → Risk → CAPA promotion.
//
// When an analyst CONFIRMS a finding at or above the organization's threshold, the
// issue, enterprise risk and CAPA are created automatically. Each step reuses the
// existing idempotent, permission-checked functions. Automation runs under the
// authority of the manager who enabled the policy (the "policy owner"), and that
// owner's manageRisk permission is re-checked on every run. If the owner loses the
// role, automation fails closed and records why. Nothing is promoted that a human
// did not confirm.

const ORDER:Severity[]=['INFO','LOW','MEDIUM','HIGH','CRITICAL'];
export const atOrAbove=(s:Severity,min:Severity)=>ORDER.indexOf(s)>=ORDER.indexOf(min);

/** Severity-derived starting score on the default 5x5 methodology. Owners re-score during treatment. */
export function derivedRiskRating(s:Severity){
 const m:Record<Severity,[number,number]>={CRITICAL:[4,5],HIGH:[4,4],MEDIUM:[3,3],LOW:[2,2],INFO:[1,2]};
 const [likelihood,impact]=m[s]||[3,3];return {likelihood,impact};
}

export async function initFindingPromotion(){await pool.query(`
 CREATE TABLE IF NOT EXISTS grc_promotion_policies(
  organization_id uuid PRIMARY KEY REFERENCES grc_organizations(id) ON DELETE CASCADE,
  enabled boolean NOT NULL DEFAULT false,
  min_severity text NOT NULL DEFAULT 'HIGH' CHECK(min_severity IN ('INFO','LOW','MEDIUM','HIGH','CRITICAL')),
  create_risk boolean NOT NULL DEFAULT true,
  create_capa boolean NOT NULL DEFAULT true,
  owner_user_id uuid REFERENCES app_users(id) ON DELETE SET NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
 );`)}

export async function promotionPolicy(user:string,org:string){
 await requireOrgPermission(user,org,'read');
 const r=(await pool.query('SELECT enabled,min_severity,create_risk,create_capa,owner_user_id,updated_at FROM grc_promotion_policies WHERE organization_id=$1',[org])).rows[0];
 return r||{enabled:false,min_severity:'HIGH',create_risk:true,create_capa:true,owner_user_id:null,updated_at:null};
}
export async function setPromotionPolicy(user:string,org:string,input:any){
 await requireOrgPermission(user,org,'manageRisk');
 const min=String(input?.minSeverity||'HIGH').toUpperCase();if(!ORDER.includes(min as Severity))throw Object.assign(new Error('Invalid minimum severity'),{statusCode:400});
 const row=(await pool.query(`INSERT INTO grc_promotion_policies(organization_id,enabled,min_severity,create_risk,create_capa,owner_user_id) VALUES($1,$2,$3,$4,$5,$6)
  ON CONFLICT(organization_id) DO UPDATE SET enabled=EXCLUDED.enabled,min_severity=EXCLUDED.min_severity,create_risk=EXCLUDED.create_risk,create_capa=EXCLUDED.create_capa,owner_user_id=EXCLUDED.owner_user_id,updated_at=now()
  RETURNING enabled,min_severity,create_risk,create_capa,owner_user_id,updated_at`,[org,Boolean(input?.enabled),min,input?.createRisk!==false,input?.createCapa!==false,user])).rows[0];
 await audit(null,'PROMOTION_POLICY_UPDATED',user,{organizationId:org,...row});
 return row;
}

export type PromotionOutcome={findingId:string;status:'PROMOTED'|'SKIPPED'|'FAILED';reason?:string;issueId?:string;riskId?:string;capaId?:string};

/** Promote one confirmed finding according to the org policy. Never throws; outcomes are audited. */
export async function autoPromoteConfirmedFinding(org:string,assessmentId:string,findingId:string,triggeredBy:string):Promise<PromotionOutcome>{
 try{
  const policy=(await pool.query('SELECT * FROM grc_promotion_policies WHERE organization_id=$1',[org])).rows[0];
  if(!policy?.enabled)return {findingId,status:'SKIPPED',reason:'POLICY_DISABLED'};
  const f=(await pool.query('SELECT payload FROM findings WHERE id=$1 AND assessment_id=$2',[findingId,assessmentId])).rows[0]?.payload;
  if(!f)return {findingId,status:'SKIPPED',reason:'FINDING_NOT_FOUND'};
  if(!atOrAbove(f.severity,policy.min_severity))return {findingId,status:'SKIPPED',reason:'BELOW_THRESHOLD'};
  const done=(await pool.query(`SELECT i.id,(SELECT 1 FROM grc_issue_risks ir WHERE ir.issue_id=i.id LIMIT 1) AS has_risk,(SELECT 1 FROM grc_capa c WHERE c.issue_id=i.id AND c.organization_id=i.organization_id LIMIT 1) AS has_capa FROM grc_issues i WHERE i.organization_id=$1 AND i.finding_id=$2`,[org,findingId])).rows[0];
  if(done&&(!policy.create_risk||done.has_risk)&&(!policy.create_capa||done.has_capa))return {findingId,status:'SKIPPED',reason:'ALREADY_PROMOTED',issueId:done.id};
  const owner=policy.owner_user_id;
  if(!owner)throw new Error('Promotion policy has no owner');
  await requireOrgPermission(owner,org,'manageRisk'); // fail closed if the policy owner lost authority
  const issue=await promoteFindingToIssue(owner,org,assessmentId,findingId,{});
  const out:PromotionOutcome={findingId,status:'PROMOTED',issueId:issue.id};
  if(policy.create_risk&&issue.status!=='CLOSED'){
   const r=derivedRiskRating(f.severity);
   const risk=await createRiskFromIssue(owner,org,issue.id,{...r,treatment:'MITIGATE',description:String(f.description||'')+'\n\nAuto-promoted from confirmed finding '+findingId+'; starting score derived from severity '+f.severity+' and must be reassessed by the risk owner.'});
   out.riskId=risk.id;
  }
  if(policy.create_capa&&issue.status!=='CLOSED'){
   const due=issue.due_at&&new Date(issue.due_at)>new Date()?new Date(issue.due_at):new Date(Date.now()+30*86400e3);
   const capa=await createCapa(owner,org,issue.id,{rootCause:'Pending root-cause analysis for confirmed finding: '+String(f.title).slice(0,300),correctiveAction:String(f.remediation||'Remediate the confirmed finding and attach passing retest evidence.').slice(0,2000),dueAt:due.toISOString(),priority:issue.priority});
   out.capaId=capa.id;
  }
  await audit(assessmentId,'FINDING_AUTO_PROMOTED',triggeredBy,{organizationId:org,findingId,policyOwner:owner,minSeverity:policy.min_severity,issueId:out.issueId,riskId:out.riskId,capaId:out.capaId});
  return out;
 }catch(e:any){
  const reason=String(e?.message||e).slice(0,500);
  await audit(assessmentId,'FINDING_AUTO_PROMOTION_FAILED',triggeredBy,{organizationId:org,findingId,reason}).catch(()=>{});
  return {findingId,status:'FAILED',reason};
 }
}

/** Sweep: promote every analyst-confirmed finding in the org that meets the policy (idempotent). */
export async function runPromotionSweep(user:string,org:string){
 await requireOrgPermission(user,org,'manageRisk');
 const rows=(await pool.query(`SELECT DISTINCT ON (r.finding_id) r.finding_id,r.assessment_id,r.decision FROM finding_reviews r JOIN assessments a ON a.id=r.assessment_id
  WHERE a.organization_id=$1 ORDER BY r.finding_id,r.created_at DESC`,[org])).rows.filter((r:any)=>r.decision==='CONFIRMED');
 const outcomes:PromotionOutcome[]=[];
 for(const r of rows.slice(0,500))outcomes.push(await autoPromoteConfirmedFinding(org,r.assessment_id,r.finding_id,user));
 return {considered:rows.length,promoted:outcomes.filter(x=>x.status==='PROMOTED').length,outcomes};
}

async function audit(assessmentId:string|null,action:string,actor:string,metadata:Record<string,unknown>){
 const id=crypto.randomUUID(),createdAt=new Date().toISOString();
 await pool.query('INSERT INTO audit_events(id,assessment_id,action,created_at,payload) VALUES($1,$2,$3,$4,$5)',[id,assessmentId,action,createdAt,{id,assessmentId:assessmentId||undefined,action,actor,createdAt,metadata}]);
}
