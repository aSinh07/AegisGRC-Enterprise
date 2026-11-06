import {pool} from './db-pool.js';
import crypto from 'node:crypto';
import pg from 'pg';
import type {Finding} from './models.js';
import {findingFingerprint} from './finding-correlation.js';
import {requireAssessmentAccess,requireOrgPermission} from './grc-organizations.js';


export type FindingDecision='CONFIRMED'|'FALSE_POSITIVE'|'ACCEPTED'|'REMEDIATED';
const decisions=new Set<FindingDecision>(['CONFIRMED','FALSE_POSITIVE','ACCEPTED','REMEDIATED']);

// A killed process reports exitCode null and Number(null)===0, so the exit code must be
// strictly the number 0. Timed-out or truncated output is incomplete evidence and can
// never prove that a vulnerability is absent.
export function retestEvidenceIsComplete(payload:any){
 if(!payload||typeof payload!=='object')return false;
 if(typeof payload.exitCode!=='number'||payload.exitCode!==0)return false;
 const m=payload.metadata||{};
 if(m.timedOut===true||m.stdoutTruncated===true||m.stderrTruncated===true||m.incomplete===true)return false;
 if(payload.timedOut===true||payload.stdoutTruncated===true||payload.stderrTruncated===true)return false;
 return true;
}

export async function initFindingReview(){
 await pool.query(`
 CREATE TABLE IF NOT EXISTS finding_reviews(
  id uuid PRIMARY KEY,finding_id uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  assessment_id uuid NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
  decision text NOT NULL CHECK(decision IN ('CONFIRMED','FALSE_POSITIVE','ACCEPTED','REMEDIATED')),
  rationale text NOT NULL,reviewer_id uuid NOT NULL REFERENCES app_users(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now(),
  retest_evidence_id uuid REFERENCES evidence(id) ON DELETE RESTRICT,
  retest_fingerprint text
 );
 ALTER TABLE finding_reviews ADD COLUMN IF NOT EXISTS retest_evidence_id uuid REFERENCES evidence(id) ON DELETE RESTRICT;
 ALTER TABLE finding_reviews ADD COLUMN IF NOT EXISTS retest_fingerprint text;
 CREATE UNIQUE INDEX IF NOT EXISTS findings_id_assessment_uidx ON findings(id,assessment_id);
 CREATE UNIQUE INDEX IF NOT EXISTS evidence_id_assessment_uidx ON evidence(id,assessment_id);
 CREATE TABLE IF NOT EXISTS finding_retests(
  id uuid PRIMARY KEY,finding_id uuid NOT NULL,
  assessment_id uuid NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
  evidence_id uuid NOT NULL UNIQUE,
  fingerprint text NOT NULL,scanner_source text NOT NULL,scanner_id text,
  created_by uuid NOT NULL REFERENCES app_users(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY(finding_id,assessment_id) REFERENCES findings(id,assessment_id) ON DELETE CASCADE,
  FOREIGN KEY(evidence_id,assessment_id) REFERENCES evidence(id,assessment_id) ON DELETE RESTRICT
 );
 CREATE INDEX IF NOT EXISTS finding_retests_finding_idx ON finding_retests(finding_id,created_at DESC);
 ALTER TABLE grc_capa DROP CONSTRAINT IF EXISTS grc_capa_finding_retest_id_fkey;
 ALTER TABLE grc_capa ADD CONSTRAINT grc_capa_finding_retest_id_fkey FOREIGN KEY(finding_retest_id) REFERENCES finding_retests(id) ON DELETE SET NULL;
 CREATE INDEX IF NOT EXISTS finding_reviews_finding_idx ON finding_reviews(finding_id,created_at DESC);
 CREATE INDEX IF NOT EXISTS finding_reviews_assessment_idx ON finding_reviews(assessment_id,created_at DESC);
 `);
}
function statusFor(d:FindingDecision):Finding['status']{
 return d==='CONFIRMED'?'OPEN':d;
}
export async function reviewFinding(userId:string,assessmentId:string,findingId:string,input:{decision:string;rationale:string;retestEvidenceId?:string}){
 const access=await requireAssessmentAccess(userId,assessmentId);
 await requireOrgPermission(userId,access.organization_id,'findingReview');
 const decision=String(input.decision||'').toUpperCase() as FindingDecision;
 const rationale=String(input.rationale||'').trim();
 if(!decisions.has(decision))throw new Error('Decision must be CONFIRMED, FALSE_POSITIVE, ACCEPTED or REMEDIATED');
 if(rationale.length<10||rationale.length>4000)throw new Error('Review rationale must be 10-4000 characters');if(decision==='ACCEPTED'){await requireOrgPermission(userId,access.organization_id,'manageRisk');if(rationale.length<30)throw Object.assign(new Error('Risk acceptance requires a substantive management rationale'),{statusCode:409})}
 const client=await pool.connect();
 try{
  await client.query('BEGIN');
  const row=(await client.query('SELECT id,assessment_id,payload FROM findings WHERE id=$1 AND assessment_id=$2 FOR UPDATE',[findingId,assessmentId])).rows[0];
  if(!row)throw Object.assign(new Error('Finding not found'),{statusCode:404});
  const original=row.payload as Finding;
  const fingerprint=original.fingerprint||findingFingerprint(original);
  let retestEvidenceId:string|null=null;
  if(decision==='REMEDIATED'){
   retestEvidenceId=String(input.retestEvidenceId||'').trim();
   if(!retestEvidenceId)throw Object.assign(new Error('REMEDIATED requires successful retest evidence'),{statusCode:409});
   const ev=(await client.query('SELECT id,source,created_at,payload FROM evidence WHERE id=$1 AND assessment_id=$2 FOR UPDATE',[retestEvidenceId,assessmentId])).rows[0];
   if(!ev)throw Object.assign(new Error('Retest evidence not found in this assessment'),{statusCode:409});
   if(!retestEvidenceIsComplete(ev.payload))throw Object.assign(new Error('Retest evidence must come from a successful tool execution that completed (exit code 0, not timed out, not truncated)'),{statusCode:409});
   if(new Date(ev.created_at).getTime()<=new Date(original.createdAt).getTime())throw Object.assign(new Error('Retest evidence must be newer than the original finding'),{statusCode:409});
   if(String(ev.source)!==String(original.source))throw Object.assign(new Error('Retest evidence must use the same scanner source as the original finding'),{statusCode:409});
   const link=(await client.query('SELECT evidence_id,finding_id,fingerprint,scanner_source FROM finding_retests WHERE evidence_id=$1 AND assessment_id=$2',[retestEvidenceId,assessmentId])).rows[0];
   if(!link||String(link.finding_id)!==findingId||String(link.fingerprint)!==fingerprint||String(link.scanner_source)!==String(original.source))throw Object.assign(new Error('Retest evidence is not bound to this finding fingerprint by the server'),{statusCode:409});
   const stillPresent=(await client.query("SELECT 1 FROM findings WHERE assessment_id=$1 AND id<>$2 AND COALESCE(payload->>'fingerprint','')=$3 AND created_at >= $4 LIMIT 1",[assessmentId,findingId,fingerprint,ev.created_at])).rows[0];
   if(stillPresent)throw Object.assign(new Error('Retest still detects the original vulnerability fingerprint'),{statusCode:409});
  }
  if(decision==='REMEDIATED'){
   const issue=(await client.query('SELECT id,organization_id,status FROM grc_issues WHERE assessment_id=$1 AND finding_id=$2 FOR UPDATE',[assessmentId,findingId])).rows[0];
   if(issue&&issue.status!=='CLOSED'){
    await client.query("UPDATE grc_issues SET status='REMEDIATION_VERIFIED',updated_at=now() WHERE id=$1",[issue.id]);
    await client.query("INSERT INTO grc_record_events(id,organization_id,record_type,record_id,event,actor_user_id,snapshot) VALUES($1,$2,'ISSUE',$3,'TECHNICAL_REMEDIATION_VERIFIED',$4,$5)",[crypto.randomUUID(),issue.organization_id,issue.id,userId,{findingId,retestEvidenceId,fingerprint}]);
    const retest=(await client.query('SELECT id FROM finding_retests WHERE evidence_id=$1 AND assessment_id=$2 AND finding_id=$3',[retestEvidenceId,assessmentId,findingId])).rows[0];
    const capas=(await client.query("UPDATE grc_capa SET status='VALIDATION',finding_retest_id=$2,updated_at=now() WHERE issue_id=$1 AND status IN ('OPEN','IN_PROGRESS','EVIDENCE_SUBMITTED','RETEST_PENDING','CHANGES_REQUESTED') RETURNING id,organization_id",[issue.id,retest.id])).rows;
    for(const capa of capas)await client.query("INSERT INTO grc_record_events(id,organization_id,record_type,record_id,event,actor_user_id,snapshot) VALUES($1,$2,'CAPA',$3,'FINDING_RETEST_VERIFIED',$4,$5)",[crypto.randomUUID(),capa.organization_id,capa.id,userId,{findingId,retestEvidenceId,fingerprint,closure:'INDEPENDENT_REVIEW_REQUIRED'}]);
   }
  }
  const updated:Finding={...original,fingerprint,status:statusFor(decision)};
  await client.query('UPDATE findings SET payload=$1 WHERE id=$2',[updated,findingId]);
  const reviewId=crypto.randomUUID();
  const review=(await client.query(`INSERT INTO finding_reviews(id,finding_id,assessment_id,decision,rationale,reviewer_id,retest_evidence_id,retest_fingerprint)
   VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id,finding_id,assessment_id,decision,rationale,reviewer_id,retest_evidence_id,retest_fingerprint,created_at`,
   [reviewId,findingId,assessmentId,decision,rationale,userId,retestEvidenceId,decision==='REMEDIATED'?fingerprint:null])).rows[0];
  const audit={id:crypto.randomUUID(),assessmentId,action:'FINDING_REVIEWED',actor:userId,createdAt:new Date().toISOString(),metadata:{findingId,reviewId,decision,rationale,retestEvidenceId,fingerprint}};
  await client.query('INSERT INTO audit_events(id,assessment_id,action,created_at,payload) VALUES($1,$2,$3,$4,$5)',[audit.id,assessmentId,audit.action,audit.createdAt,audit]);
  await client.query('COMMIT');return {finding:updated,review};
 }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}
export async function findingReviewHistory(userId:string,assessmentId:string,findingId:string){
 await requireAssessmentAccess(userId,assessmentId);
 return (await pool.query(`SELECT r.id,r.finding_id,r.assessment_id,r.decision,r.rationale,r.created_at,u.email reviewer
 FROM finding_reviews r JOIN app_users u ON u.id=r.reviewer_id
 WHERE r.assessment_id=$1 AND r.finding_id=$2 ORDER BY r.created_at ASC`,[assessmentId,findingId])).rows;
}
