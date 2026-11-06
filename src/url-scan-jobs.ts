import crypto from 'node:crypto';
import {pool} from './db-pool.js';
import {requireAssessmentAccess,requireOrgPermission} from './grc-organizations.js';
import {validatePublicHttpTarget} from './network-target.js';
import {assertTargetAuthorized} from './target-authorization.js';
import {scanCoverage,assessmentStatusForCoverage} from './scan-coverage.js';
import type {ScanTaskSpec,RawScanResult,ScanTool} from './scan-runner.js';

// Durable URL scan jobs.
//
// A job is one authorized scan of an assessment target with a fixed profile. It is split into
// one task per tool. Scanner workers (embedded or remote) lease tasks, run them and return raw
// output. Leases expire, so a crashed worker or a restarted server never leaves a scan RUNNING
// forever. DEEP jobs (active attack traffic: ZAP active scan + sqlmap) wait for sign-off by a
// second person with approval rights.

export type ScanProfile='QUICK'|'STANDARD'|'DEEP';
export const SCAN_PROFILES:Record<ScanProfile,{tasks:{tool:ScanTool;options?:Record<string,unknown>}[];requiresApproval:boolean;description:string}>={
 QUICK:{tasks:[{tool:'http'},{tool:'nmap'}],requiresApproval:false,description:'HTTP security posture and bounded TCP service discovery.'},
 STANDARD:{tasks:[{tool:'http'},{tool:'nmap'},{tool:'nuclei'},{tool:'wapiti'},{tool:'zap',options:{zapMode:'passive'}}],requiresApproval:false,description:'Quick plus pinned Nuclei HTTP templates, Wapiti and a passive ZAP crawl. No active attack payloads beyond Wapiti/Nuclei checks.'},
 DEEP:{tasks:[{tool:'http'},{tool:'nmap'},{tool:'nuclei'},{tool:'wapiti'},{tool:'zap',options:{zapMode:'active'}},{tool:'sqlmap'}],requiresApproval:true,description:'Standard plus the ZAP active scanner and sqlmap injection testing. Requires a second approver.'}
};
const TERMINAL_TASK=['SUCCEEDED','FAILED','TIMEOUT','CANCELLED'];
const err=(m:string,statusCode:number)=>Object.assign(new Error(m),{statusCode});

async function audit(c:{query:Function},assessmentId:string|null,action:string,actor:string,metadata:Record<string,unknown>){
 const id=crypto.randomUUID(),createdAt=new Date().toISOString();
 await c.query('INSERT INTO audit_events(id,assessment_id,action,created_at,payload) VALUES($1,$2,$3,$4,$5)',[id,assessmentId,action,createdAt,{id,assessmentId:assessmentId||undefined,action,actor,createdAt,metadata}]);
}

export async function enqueueUrlScanJob(userId:string,assessmentId:string,input:{profile?:string;purpose?:'ASSESSMENT'|'SCHEDULED'},validate=validatePublicHttpTarget){
 const access=await requireAssessmentAccess(userId,assessmentId);await requireOrgPermission(userId,access.organization_id,'manageAssessment');
 const profile=String(input.profile||'STANDARD').toUpperCase() as ScanProfile;
 if(!SCAN_PROFILES[profile])throw err('Profile must be QUICK, STANDARD or DEEP',400);
 const a=(await pool.query('SELECT target,organization_id FROM assessments WHERE id=$1',[assessmentId])).rows[0];
 if(!a?.organization_id)throw err('Assessment has no organization',409);
 const t=await validate(String(a.target));
 const basis=await assertTargetAuthorized(a.organization_id,t.url.hostname);
 const active=(await pool.query(`SELECT id,status,profile FROM url_scan_jobs WHERE assessment_id=$1 AND status IN ('AWAITING_APPROVAL','QUEUED','RUNNING') LIMIT 1`,[assessmentId])).rows[0];
 if(active)return {...active,reused:true};
 const def=SCAN_PROFILES[profile],status=def.requiresApproval?'AWAITING_APPROVAL':'QUEUED',id=crypto.randomUUID();
 const c=await pool.connect();
 try{
  await c.query('BEGIN');
  const job=(await c.query(`INSERT INTO url_scan_jobs(id,organization_id,assessment_id,target_authorization_id,origin,hostname,pinned_addresses,profile,purpose,status,requested_by)
   VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *`,[id,a.organization_id,assessmentId,basis.authorization?.id||null,t.url.origin,t.url.hostname,t.addresses,profile,input.purpose||'ASSESSMENT',status,userId])).rows[0];
  for(const task of def.tasks)await c.query('INSERT INTO url_scan_tasks(id,job_id,tool,options,state) VALUES($1,$2,$3,$4,$5)',[crypto.randomUUID(),id,task.tool,task.options||{},status==='QUEUED'?'QUEUED':'BLOCKED']);
  if(status==='QUEUED')await c.query(`UPDATE assessments SET status='RUNNING',payload=jsonb_set(payload,'{status}','"RUNNING"'),updated_at=now() WHERE id=$1`,[assessmentId]);
  await audit(c,assessmentId,'SCAN_JOB_QUEUED',userId,{scanJobId:id,profile,status,tools:def.tasks.map(x=>x.tool),pinnedAddresses:t.addresses,targetAuthorizationId:basis.authorization?.id||null,authorizationMode:basis.mode});
  await c.query('COMMIT');return {...job,reused:false};
 }catch(e){await c.query('ROLLBACK');throw e}finally{c.release()}
}

export async function decideUrlScanJob(userId:string,jobId:string,input:{decision?:string;note?:string}){
 const job=(await pool.query('SELECT * FROM url_scan_jobs WHERE id=$1',[jobId])).rows[0];if(!job)throw err('Scan job not found',404);
 await requireOrgPermission(userId,job.organization_id,'approveTarget');
 if(job.requested_by===userId)throw err('Separation of duties: the requester cannot approve their own deep scan',403);
 if(job.status!=='AWAITING_APPROVAL')throw err('Only jobs awaiting approval can be decided (current: '+job.status+')',409);
 const decision=String(input.decision||'').toUpperCase();if(decision!=='APPROVE'&&decision!=='REJECT')throw err('Decision must be APPROVE or REJECT',400);
 const note=String(input.note||'').trim().slice(0,2000);if(decision==='REJECT'&&note.length<5)throw err('A rejection reason is required',400);
 if(decision==='APPROVE')await assertTargetAuthorized(job.organization_id,job.hostname);
 const c=await pool.connect();
 try{
  await c.query('BEGIN');
  const status=decision==='APPROVE'?'QUEUED':'REJECTED';
  const out=(await c.query(`UPDATE url_scan_jobs SET status=$2,approved_by=$3,approved_at=now(),decision_note=$4 WHERE id=$1 AND status='AWAITING_APPROVAL' RETURNING *`,[jobId,status,userId,note||null])).rows[0];
  if(!out)throw err('Scan job changed concurrently',409);
  await c.query(`UPDATE url_scan_tasks SET state=$2 WHERE job_id=$1 AND state='BLOCKED'`,[jobId,decision==='APPROVE'?'QUEUED':'CANCELLED']);
  if(decision==='APPROVE')await c.query(`UPDATE assessments SET status='RUNNING',payload=jsonb_set(payload,'{status}','"RUNNING"'),updated_at=now() WHERE id=$1`,[job.assessment_id]);
  await audit(c,job.assessment_id,decision==='APPROVE'?'SCAN_JOB_APPROVED':'SCAN_JOB_REJECTED',userId,{scanJobId:jobId,profile:job.profile,requestedBy:job.requested_by,note});
  await c.query('COMMIT');return out;
 }catch(e){await c.query('ROLLBACK');throw e}finally{c.release()}
}

export async function listUrlScanJobs(userId:string,assessmentId:string){
 const access=await requireAssessmentAccess(userId,assessmentId);await requireOrgPermission(userId,access.organization_id,'read');
 const jobs=(await pool.query('SELECT * FROM url_scan_jobs WHERE assessment_id=$1 ORDER BY created_at DESC LIMIT 50',[assessmentId])).rows;
 const tasks=jobs.length?(await pool.query('SELECT id,job_id,tool,options,state,attempts,lease_owner,evidence_id,evidence_sha256,finding_count,error,started_at,completed_at FROM url_scan_tasks WHERE job_id=ANY($1::uuid[]) ORDER BY created_at',[jobs.map((j:any)=>j.id)])).rows:[];
 return jobs.map((j:any)=>({...j,tasks:tasks.filter((t:any)=>t.job_id===j.id)}));
}
export async function pendingScanApprovals(userId:string,orgId:string){
 const m=await requireOrgPermission(userId,orgId,'read');
 const rows=(await pool.query(`SELECT j.id,j.assessment_id,j.origin,j.profile,j.requested_by,j.created_at FROM url_scan_jobs j WHERE j.organization_id=$1 AND j.status='AWAITING_APPROVAL' ORDER BY j.created_at`,[orgId])).rows;
 return {canApprove:['ORG_ADMIN','GRC_MANAGER'].includes(String((m as any).role)),userId,items:rows};
}

export type LeasedTask={taskId:string;jobId:string;assessmentId:string;leaseToken:string;leaseExpiresAt:string;spec:ScanTaskSpec;profile:ScanProfile};
const leaseSeconds=()=>Math.max(120,Number(process.env.SCAN_TASK_LEASE_SECONDS||900));

/** Lease the next runnable task. Re-checks target authorization at hand-out (revocation stops queued work). */
export async function claimUrlScanTask(workerId:string,opts:{tools?:ScanTool[]}={}):Promise<LeasedTask|null>{
 for(let i=0;i<5;i++){
  const c=await pool.connect();let cancelled:any=null,leased:LeasedTask|null=null;
  try{
   await c.query('BEGIN');
   const row=(await c.query(`SELECT t.id,t.tool,t.options,j.id AS job_id,j.assessment_id,j.organization_id,j.origin,j.hostname,j.pinned_addresses,j.profile FROM url_scan_tasks t JOIN url_scan_jobs j ON j.id=t.job_id
    WHERE t.state='QUEUED' AND j.status IN ('QUEUED','RUNNING') ${opts.tools?.length?'AND t.tool=ANY($1::text[])':''} ORDER BY t.created_at FOR UPDATE OF t SKIP LOCKED LIMIT 1`,opts.tools?.length?[opts.tools]:[])).rows[0];
   if(!row){await c.query('COMMIT');return null}
   try{await assertTargetAuthorized(row.organization_id,row.hostname)}catch(e:any){cancelled={row,reason:String(e.message)}}
   if(cancelled){
    await c.query(`UPDATE url_scan_tasks SET state='CANCELLED',error=$2,completed_at=now() WHERE job_id=$1 AND state IN ('QUEUED','BLOCKED')`,[row.job_id,'Target authorization no longer active: '+cancelled.reason]);
    await audit(c,row.assessment_id,'SCAN_JOB_CANCELLED_AUTHORIZATION_INACTIVE','system:scan-dispatcher',{scanJobId:row.job_id,reason:cancelled.reason});
   }else{
    const token=crypto.randomBytes(24).toString('hex');
    const t=(await c.query(`UPDATE url_scan_tasks SET state='LEASED',lease_owner=$2,lease_token=$3,lease_expires_at=now()+($4::text||' seconds')::interval,attempts=attempts+1,started_at=coalesce(started_at,now()) WHERE id=$1 RETURNING lease_expires_at`,[row.id,workerId,token,String(leaseSeconds())])).rows[0];
    await c.query(`UPDATE url_scan_jobs SET status='RUNNING',started_at=coalesce(started_at,now()) WHERE id=$1 AND status='QUEUED'`,[row.job_id]);
    leased={taskId:row.id,jobId:row.job_id,assessmentId:row.assessment_id,leaseToken:token,leaseExpiresAt:new Date(t.lease_expires_at).toISOString(),profile:row.profile,spec:{tool:row.tool,options:row.options||{},origin:row.origin,pinnedAddresses:row.pinned_addresses}};
   }
   await c.query('COMMIT');
  }catch(e){await c.query('ROLLBACK');throw e}finally{c.release()}
  if(cancelled){await finalizeJobIfDone(cancelled.row.job_id);continue}
  return leased;
 }
 return null;
}

export async function heartbeatUrlScanTask(taskId:string,workerId:string,leaseToken:string){
 const r=(await pool.query(`UPDATE url_scan_tasks SET lease_expires_at=now()+($4::text||' seconds')::interval WHERE id=$1 AND lease_owner=$2 AND lease_token=$3 AND state='LEASED' RETURNING lease_expires_at`,[taskId,workerId,leaseToken,String(leaseSeconds())])).rows[0];
 if(!r)throw err('Lease not held',409);return {leaseExpiresAt:new Date(r.lease_expires_at).toISOString()};
}

export function taskStateFor(raw:Pick<RawScanResult,'exitCode'|'timedOut'|'stdoutTruncated'|'stderrTruncated'>){
 if(raw.timedOut)return 'TIMEOUT' as const;
 return raw.exitCode===0&&!raw.stdoutTruncated&&!raw.stderrTruncated?'SUCCEEDED' as const:'FAILED' as const;
}

export type PersistScanResult=(ctx:{jobId:string;taskId:string;assessmentId:string;profile:ScanProfile;origin:string;pinnedAddresses:string[];requestedBy:string|null},raw:RawScanResult,attestation:Record<string,unknown>)=>Promise<{evidenceId:string;sha256:string;findingCount:number}>;
export type FinalizeAssessment=(assessmentId:string,status:'COMPLETED'|'PARTIAL'|'FAILED',coverage:unknown,actor:string,jobId:string)=>Promise<void>;
let persistHook:PersistScanResult|null=null,finalizeHook:FinalizeAssessment|null=null;
export function configureScanJobPersistence(persist:PersistScanResult,finalize:FinalizeAssessment){persistHook=persist;finalizeHook=finalize}

/** Accept a worker's raw result for a task it holds the lease on, persist evidence + findings, and finalize the job if done. */
export async function completeUrlScanTask(taskId:string,workerId:string,leaseToken:string,raw:RawScanResult|null,attestation:Record<string,unknown>,failure?:string){
 if(!persistHook)throw new Error('Scan job persistence is not configured');
 const row=(await pool.query(`SELECT t.*,j.assessment_id,j.profile,j.origin,j.pinned_addresses,j.requested_by FROM url_scan_tasks t JOIN url_scan_jobs j ON j.id=t.job_id WHERE t.id=$1`,[taskId])).rows[0];
 if(!row)throw err('Task not found',404);
 if(row.state!=='LEASED'||row.lease_owner!==workerId||row.lease_token!==leaseToken)throw err('Lease not held for this task',409);
 if(raw&&raw.tool!==row.tool)throw err('Result tool does not match the leased task',409);
 let state:'SUCCEEDED'|'FAILED'|'TIMEOUT'='FAILED',evidence:{evidenceId:string;sha256:string;findingCount:number}|null=null,error=failure?String(failure).slice(0,2000):null;
 if(raw){evidence=await persistHook({jobId:row.job_id,taskId,assessmentId:row.assessment_id,profile:row.profile,origin:row.origin,pinnedAddresses:row.pinned_addresses,requestedBy:row.requested_by},raw,attestation);state=taskStateFor(raw)}
 const upd=(await pool.query(`UPDATE url_scan_tasks SET state=$4,evidence_id=$5,evidence_sha256=$6,finding_count=$7,error=$8,completed_at=now(),lease_token=NULL WHERE id=$1 AND lease_owner=$2 AND lease_token=$3 AND state='LEASED' RETURNING id`,[taskId,workerId,leaseToken,state,evidence?.evidenceId||null,evidence?.sha256||null,evidence?.findingCount??null,error])).rows[0];
 if(!upd)throw err('Lease lost before completion',409);
 await finalizeJobIfDone(row.job_id);
 return {taskId,state,evidence};
}

/** Expired leases go back to the queue (or FAIL after max attempts); affected jobs are finalized. */
export async function recoverExpiredScanLeases(){
 const rows=(await pool.query(`UPDATE url_scan_tasks SET state=CASE WHEN attempts>=max_attempts THEN 'FAILED' ELSE 'QUEUED' END,error=CASE WHEN attempts>=max_attempts THEN 'Worker lease expired after maximum attempts' ELSE error END,
  lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,completed_at=CASE WHEN attempts>=max_attempts THEN now() ELSE NULL END WHERE state='LEASED' AND lease_expires_at<now() RETURNING job_id,state`)).rows;
 for(const j of new Set(rows.map((r:any)=>r.job_id)))await finalizeJobIfDone(String(j));
 return rows.length;
}

export async function finalizeJobIfDone(jobId:string){
 const job=(await pool.query('SELECT * FROM url_scan_jobs WHERE id=$1',[jobId])).rows[0];
 if(!job||!['QUEUED','RUNNING'].includes(job.status))return null;
 const tasks=(await pool.query('SELECT tool,state,error FROM url_scan_tasks WHERE job_id=$1',[jobId])).rows;
 if(tasks.some((t:any)=>!TERMINAL_TASK.includes(t.state)))return null;
 const coverage=scanCoverage(tasks.map((t:any)=>t.tool),tasks.map((t:any)=>({tool:t.tool,status:t.state==='SUCCEEDED'?'SUCCEEDED':'FAILED',error:t.error||undefined}) as any));
 const status=assessmentStatusForCoverage(coverage);
 const done=(await pool.query(`UPDATE url_scan_jobs SET status=$2,coverage=$3,completed_at=now() WHERE id=$1 AND status IN ('QUEUED','RUNNING') RETURNING id`,[jobId,status,coverage])).rows[0];
 if(!done)return null;
 if(finalizeHook)await finalizeHook(job.assessment_id,status,{...coverage,profile:job.profile,scanJobId:jobId},String(job.requested_by||'system:scan-dispatcher'),jobId);
 return {jobId,status,coverage};
}

export async function activeScanAssessmentIds(){return (await pool.query(`SELECT DISTINCT assessment_id FROM url_scan_jobs WHERE status IN ('QUEUED','RUNNING','AWAITING_APPROVAL')`)).rows.map((r:any)=>String(r.assessment_id))}
