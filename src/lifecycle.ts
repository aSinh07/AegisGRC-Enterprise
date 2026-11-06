import {pool} from './db-pool.js';
import {requireAssessmentAccess,requireOrgPermission} from './grc-organizations.js';
import {verifyEvidenceSignature} from './evidence-signing.js';
import {targetAuthorizationMode} from './target-authorization.js';

// The governed lifecycle from the target architecture, computed from stored records only:
// "No finding closes and no report signs without fresh evidence."
// Every step is DONE only when the backing record exists in the system of record.

export const LIFECYCLE_STEPS=[
 ['TARGET_VERIFIED','Target verified','DNS or file proof, second-person approval'],
 ['SCAN_JOB_APPROVED','Scan job queued','Approver signs off (deep scans per job)'],
 ['WORKER_SCANNED','Worker scans','Pinned IP, fixed profile'],
 ['SIGNED_EVIDENCE','Signed evidence','HMAC, append-only'],
 ['FINDING_CREATED','Finding created','Fingerprint dedupe'],
 ['ANALYST_REVIEW','Analyst review','Confirm or reject'],
 ['ISSUE_RISK','Issue + risk','Auto for High/Critical'],
 ['CAPA','CAPA + fix','Owner, due date'],
 ['FRESH_RETEST','Fresh retest','Same source, newer'],
 ['CLOSURE_REVIEW','Closure review','By a second person'],
 ['CONTROL_EVIDENCE','Control evidence','Linked to controls'],
 ['SIGNED_REPORT','Signed report','Stored, verifiable']
] as const;
export type StepKey=typeof LIFECYCLE_STEPS[number][0];
export type StepState='DONE'|'PENDING'|'BLOCKED'|'NOT_APPLICABLE'|'WARNING';
export type Step={key:StepKey;title:string;detail:string;state:StepState;note?:string;ref?:Record<string,unknown>};

const mk=(key:StepKey,state:StepState,note?:string,ref?:Record<string,unknown>):Step=>{const d=LIFECYCLE_STEPS.find(x=>x[0]===key)!;return {key,title:d[1],detail:d[2],state,...(note?{note}:{}),...(ref?{ref}:{})}};

export async function assessmentLifecycle(userId:string,assessmentId:string){
 const access=await requireAssessmentAccess(userId,assessmentId);await requireOrgPermission(userId,access.organization_id,'read');
 return computeLifecycle(assessmentId);
}

export async function computeLifecycle(assessmentId:string){
 const a=(await pool.query('SELECT id,target,status,organization_id,payload FROM assessments WHERE id=$1',[assessmentId])).rows[0];
 if(!a)throw Object.assign(new Error('Assessment not found'),{statusCode:404});
 const host=(()=>{try{return new URL(a.target).hostname.toLowerCase()}catch{return ''}})();
 const basis=a.payload?.authorizationBasis||null;
 const auth=(await pool.query(`SELECT id,status,expires_at,decided_by,requested_by FROM target_authorizations WHERE organization_id=$1 AND hostname=$2 ORDER BY (status='APPROVED' AND expires_at>now()) DESC,decided_at DESC NULLS LAST LIMIT 1`,[a.organization_id,host])).rows[0]||null;
 const target:Step=basis?.basis==='VERIFIED_AND_APPROVED'||(auth?.status==='APPROVED')
  ?mk('TARGET_VERIFIED','DONE',auth&&auth.status!=='APPROVED'?'Approved at scan time; now '+auth.status:undefined,{targetAuthorizationId:basis?.targetAuthorizationId||auth?.id,approvedBy:basis?.approvedBy||auth?.decided_by})
  :basis?.basis==='SELF_ATTESTED'||targetAuthorizationMode()==='attest'?mk('TARGET_VERIFIED','WARNING','Self-attested (TARGET_AUTHORIZATION_MODE=attest)'):mk('TARGET_VERIFIED','PENDING','No verified, approved target authorization');
 const jobs=(await pool.query('SELECT id,profile,status,requested_by,approved_by,created_at,completed_at,coverage FROM url_scan_jobs WHERE assessment_id=$1 ORDER BY created_at DESC',[assessmentId])).rows;
 const evidence=(await pool.query('SELECT id,sha256,source,created_at,payload FROM evidence WHERE assessment_id=$1',[assessmentId])).rows;
 const evBySha=new Map<string,any>();for(const e of evidence)if(!evBySha.has(e.sha256))evBySha.set(e.sha256,e);
 const findings=(await pool.query('SELECT id,severity,source,created_at,payload FROM findings WHERE assessment_id=$1 ORDER BY created_at',[assessmentId])).rows;
 const ids=findings.map((f:any)=>f.id);
 const reviews=ids.length?(await pool.query('SELECT DISTINCT ON (finding_id) finding_id,decision,reviewer_id,rationale,created_at FROM finding_reviews WHERE finding_id=ANY($1::uuid[]) ORDER BY finding_id,created_at DESC',[ids])).rows:[];
 const issues=ids.length?(await pool.query(`SELECT i.id,i.finding_id,i.status,i.scope_control_id,(SELECT ir.risk_id FROM grc_issue_risks ir WHERE ir.issue_id=i.id LIMIT 1) AS risk_id FROM grc_issues i WHERE i.finding_id=ANY($1::uuid[])`,[ids])).rows:[];
 const capas=issues.length?(await pool.query('SELECT id,issue_id,status,owner_user_id,due_at,approved_by,closed_at,finding_retest_id,created_by FROM grc_capa WHERE issue_id=ANY($1::uuid[]) ORDER BY created_at',[issues.map((i:any)=>i.id)])).rows:[];
 const retests=ids.length?(await pool.query(`SELECT DISTINCT ON (r.finding_id) r.id,r.finding_id,r.evidence_id,r.created_by,r.created_at,(SELECT a.payload->'metadata'->>'stillPresent' FROM audit_events a WHERE a.action='TARGETED_RETEST_COMPLETED' AND a.payload->'metadata'->>'evidenceId'=r.evidence_id::text LIMIT 1) AS still_present FROM finding_retests r WHERE r.finding_id=ANY($1::uuid[]) ORDER BY r.finding_id,r.created_at DESC`,[ids])).rows:[];
 const scopeControls=issues.some((i:any)=>i.scope_control_id)?(await pool.query('SELECT id,evidence_refs FROM grc_scope_controls WHERE id=ANY($1::uuid[])',[issues.filter((i:any)=>i.scope_control_id).map((i:any)=>i.scope_control_id)])).rows:[];
 const reports=(await pool.query('SELECT id,report_type,generated_at,hmac_sha256 IS NOT NULL AS signed FROM report_records WHERE assessment_id=$1 ORDER BY generated_at DESC',[assessmentId])).rows;

 const rows=findings.map((row:any)=>{
  const f=row.payload||{};const steps:Step[]=[target];
  const ev=evBySha.get(f.evidenceHash);const m=ev?.payload?.metadata||{};
  const job=m.scanJobId?jobs.find((j:any)=>j.id===m.scanJobId):null;
  steps.push(job?(job.profile==='DEEP'?(job.approved_by?mk('SCAN_JOB_APPROVED','DONE',undefined,{scanJobId:job.id,profile:job.profile,approvedBy:job.approved_by}):mk('SCAN_JOB_APPROVED','BLOCKED','Deep scan without approver')):mk('SCAN_JOB_APPROVED','DONE',job.profile+' profile covered by the target approval',{scanJobId:job.id,profile:job.profile}))
   :ev?mk('SCAN_JOB_APPROVED','WARNING','Evidence from a direct (non-queued) scan or import'):mk('SCAN_JOB_APPROVED','PENDING'));
  steps.push(m.egress?mk('WORKER_SCANNED','DONE',String((m.egress as any).mode||''),{pinnedAddress:(m.egress as any).pinnedAddress,worker:(m.workerAttestation as any)?.workerId}):ev?mk('WORKER_SCANNED','WARNING','No pinned-egress record (imported or pre-pinning evidence)'):mk('WORKER_SCANNED','PENDING'));
  const sig=ev?verifyEvidenceSignature(ev.payload):null;
  steps.push(!ev?mk('SIGNED_EVIDENCE','PENDING','Evidence record not found'):sig!.status==='VALID'?mk('SIGNED_EVIDENCE','DONE',undefined,{evidenceId:ev.id,sha256:ev.sha256}):sig!.status==='INVALID'?mk('SIGNED_EVIDENCE','BLOCKED','Evidence signature INVALID',{evidenceId:ev.id}):mk('SIGNED_EVIDENCE','WARNING','Signature status '+sig!.status,{evidenceId:ev.id}));
  steps.push(mk('FINDING_CREATED','DONE',f.duplicateOf?'Duplicate of '+f.duplicateOf+' (occurrence '+(f.occurrence||'?')+')':undefined,{fingerprint:f.fingerprint,duplicateOf:f.duplicateOf||null}));
  const rv=reviews.find((r:any)=>r.finding_id===row.id);
  if(rv?.decision==='FALSE_POSITIVE'){
   steps.push(mk('ANALYST_REVIEW','DONE','Rejected as false positive: '+String(rv.rationale||'').slice(0,160),{reviewer:rv.reviewer_id}));
   for(const k of ['ISSUE_RISK','CAPA','FRESH_RETEST','CLOSURE_REVIEW','CONTROL_EVIDENCE','SIGNED_REPORT'] as StepKey[])steps.push(mk(k,'NOT_APPLICABLE','Closed as false positive; never reaches a risk'));
   return {findingId:row.id,title:f.title,severity:row.severity,source:row.source,duplicateOf:f.duplicateOf||null,outcome:'FALSE_POSITIVE',steps};
  }
  steps.push(rv?.decision==='CONFIRMED'||rv?.decision==='REMEDIATED'||rv?.decision==='ACCEPTED'?mk('ANALYST_REVIEW','DONE',rv.decision,{reviewer:rv.reviewer_id}):mk('ANALYST_REVIEW','PENDING','Awaiting analyst confirmation'));
  const is=issues.find((i:any)=>i.finding_id===row.id);
  steps.push(is?(is.risk_id?mk('ISSUE_RISK','DONE',undefined,{issueId:is.id,riskId:is.risk_id}):mk('ISSUE_RISK','PENDING','Issue raised; no risk linked',{issueId:is.id})):mk('ISSUE_RISK','PENDING',rv?.decision==='CONFIRMED'?'Not promoted (below threshold or policy disabled)':undefined));
  const capa=is?capas.find((c:any)=>c.issue_id===is.id):null;
  steps.push(capa?(capa.status==='CHANGES_REQUESTED'?mk('CAPA','BLOCKED','Retest still detected the finding: back to CAPA',{capaId:capa.id}):mk('CAPA','DONE',capa.status,{capaId:capa.id,owner:capa.owner_user_id,dueAt:capa.due_at})):mk('CAPA','PENDING'));
  const rt=retests.find((r:any)=>r.finding_id===row.id);
  steps.push(!rt?mk('FRESH_RETEST','PENDING'):rt.still_present==='true'?mk('FRESH_RETEST','BLOCKED','Still present in the latest retest',{findingRetestId:rt.id,evidenceId:rt.evidence_id}):mk('FRESH_RETEST','DONE',undefined,{findingRetestId:rt.id,evidenceId:rt.evidence_id,operator:rt.created_by}));
  steps.push(capa?.status==='CLOSED'?mk('CLOSURE_REVIEW','DONE',undefined,{closedBy:capa.approved_by,closedAt:capa.closed_at}):mk('CLOSURE_REVIEW','PENDING'));
  const sc=is?.scope_control_id?scopeControls.find((s:any)=>s.id===is.scope_control_id):null;
  const linked=sc&&capa&&(sc.evidence_refs||[]).some((r:any)=>r.capaId===capa.id);
  steps.push(linked?mk('CONTROL_EVIDENCE','DONE',undefined,{scopeControlId:sc.id}):mk('CONTROL_EVIDENCE','PENDING',is&&!is.scope_control_id?'Issue is not linked to a scoped control':undefined));
  const rep=capa?.closed_at?reports.find((r:any)=>r.signed&&new Date(r.generated_at)>=new Date(capa.closed_at)):null;
  steps.push(rep?mk('SIGNED_REPORT','DONE',rep.report_type,{reportRecordId:rep.id}):mk('SIGNED_REPORT','PENDING',capa?.closed_at?'Generate a report after closure':undefined));
  const complete=steps.every(s=>s.state==='DONE');
  return {findingId:row.id,title:f.title,severity:row.severity,source:row.source,duplicateOf:f.duplicateOf||null,outcome:complete?'CLOSED_AND_REPORTED':'IN_PROGRESS',steps};
 });
 return {assessment:{id:a.id,target:a.target,status:a.status,organizationId:a.organization_id},steps:LIFECYCLE_STEPS.map(([key,title,detail])=>({key,title,detail})),
  scanJobs:jobs,reports:reports.slice(0,10),findings:rows,
  summary:{findings:rows.length,canonical:rows.filter(r=>!r.duplicateOf).length,closedAndReported:rows.filter(r=>r.outcome==='CLOSED_AND_REPORTED').length,falsePositives:rows.filter(r=>r.outcome==='FALSE_POSITIVE').length}};
}

/** Phase 1 evidence gate: at least one confirmed finding went through all 12 steps and a signed report followed. */
export async function phaseOneGate(userId:string,orgId:string){
 await requireOrgPermission(userId,orgId,'read');
 const candidates=(await pool.query(`SELECT DISTINCT i.assessment_id FROM grc_capa c JOIN grc_issues i ON i.id=c.issue_id WHERE c.organization_id=$1 AND c.status='CLOSED' AND i.assessment_id IS NOT NULL LIMIT 50`,[orgId])).rows;
 for(const c of candidates){
  const lc=await computeLifecycle(c.assessment_id);
  const done=lc.findings.find(f=>f.outcome==='CLOSED_AND_REPORTED');
  if(done)return {gate:'PHASE_1_FOUNDATION',passed:true,assessmentId:c.assessment_id,findingId:done.findingId,proof:done.steps.map(s=>({key:s.key,ref:s.ref||null})),checkedAt:new Date().toISOString()};
 }
 return {gate:'PHASE_1_FOUNDATION',passed:false,assessmentsChecked:candidates.length,requirement:'One confirmed finding must complete all 12 lifecycle steps, ending in a signed report generated after CAPA closure.',checkedAt:new Date().toISOString()};
}
