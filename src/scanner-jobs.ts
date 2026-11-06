import {pool} from './db-pool.js';
import crypto from 'node:crypto';
import pg from 'pg';
import {requireAssessmentAccess,requireOrgPermission} from './grc-organizations.js';
import {scanTls,scanHostHardening,scanImageWithGrype,generateSbom,scanKubernetes,scanIac,scanSecrets} from './external-scanners.js';
import {validatePublicHttpTarget,revalidatePublicHttpTarget} from './network-target.js';
import {pinnedAddress} from './pinned-egress.js';

export type ScannerEngine='TESTSSL'|'LYNIS'|'GRYPE'|'SYFT'|'KUBESCAPE'|'CHECKOV'|'GITLEAKS';
export type ScannerJobState='QUEUED'|'RUNNING'|'SUCCEEDED'|'FAILED'|'TIMEOUT'|'TRUNCATED'|'UNAVAILABLE';
const engines=new Set<ScannerEngine>(['TESTSSL','LYNIS','GRYPE','SYFT','KUBESCAPE','CHECKOV','GITLEAKS']);

export const scannerRegistry=Object.freeze({
 TESTSSL:{layer:'WEB',input:'URL_OR_HOST',active:true},LYNIS:{layer:'HOST',input:'WORKSPACE',active:false},
 GRYPE:{layer:'DEPENDENCIES',input:'IMAGE',active:false},SYFT:{layer:'DEPENDENCIES',input:'IMAGE_OR_WORKSPACE',active:false},
 KUBESCAPE:{layer:'CONTAINER',input:'WORKSPACE',active:false},CHECKOV:{layer:'SOURCE_CODE',input:'WORKSPACE',active:false},
 GITLEAKS:{layer:'SOURCE_CODE',input:'WORKSPACE',active:false}
} as const);

export async function initScannerJobs(){await pool.query(`
 CREATE TABLE IF NOT EXISTS scanner_jobs(
  id uuid PRIMARY KEY,organization_id uuid NOT NULL REFERENCES grc_organizations(id) ON DELETE CASCADE,
  assessment_id uuid NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,engine text NOT NULL,target text NOT NULL,
  state text NOT NULL CHECK(state IN ('QUEUED','RUNNING','SUCCEEDED','FAILED','TIMEOUT','TRUNCATED','UNAVAILABLE')),
  requested_by uuid REFERENCES app_users(id) ON DELETE SET NULL,evidence_id uuid,evidence_hash text,error text,
  created_at timestamptz NOT NULL DEFAULT now(),started_at timestamptz,completed_at timestamptz,attempts integer NOT NULL DEFAULT 0
 );ALTER TABLE scanner_jobs ADD COLUMN IF NOT EXISTS attempts integer NOT NULL DEFAULT 0;CREATE INDEX IF NOT EXISTS scanner_jobs_assessment_idx ON scanner_jobs(organization_id,assessment_id,created_at DESC);CREATE UNIQUE INDEX IF NOT EXISTS scanner_jobs_active_unique_idx ON scanner_jobs(organization_id,assessment_id,engine,target) WHERE state IN ('QUEUED','RUNNING');
`)}

export function assertActiveScannerScope(engineName:ScannerEngine,target:string,authorizedTarget:string){
 if(engineName!=='TESTSSL')return;
 let requested:URL,authorized:URL;
 try{requested=new URL(target);authorized=new URL(authorizedTarget)}catch{throw new Error('Active scanner requires an authorized HTTPS origin')}
 if(authorized.protocol!=='https:'||requested.protocol!=='https:'||requested.origin!==authorized.origin||requested.pathname!=='/'||requested.search||requested.hash||requested.username||requested.password||authorized.username||authorized.password)
  throw Object.assign(new Error('Active scanner target is outside the authorized HTTPS assessment origin'),{statusCode:403});
}
function engine(v:string){const e=String(v||'').toUpperCase() as ScannerEngine;if(!engines.has(e))throw new Error('Unsupported defense scanner');return e}
export async function enqueueScannerJob(userId:string,assessmentId:string,input:{engine:string;target:string}){
 const access=await requireAssessmentAccess(userId,assessmentId);await requireOrgPermission(userId,access.organization_id,'manageAssessment');
 const e=engine(input.engine),target=String(input.target||'').trim();if(!target||target.length>500)throw new Error('Scanner target is required');assertActiveScannerScope(e,target,String(access.target||''));
 const id=crypto.randomUUID();return (await pool.query(`INSERT INTO scanner_jobs(id,organization_id,assessment_id,engine,target,state,requested_by)
 VALUES($1,$2,$3,$4,$5,'QUEUED',$6) ON CONFLICT (organization_id,assessment_id,engine,target) WHERE state IN ('QUEUED','RUNNING') DO NOTHING RETURNING id,organization_id,assessment_id,engine,target,state,created_at`,[id,access.organization_id,assessmentId,e,target,userId])).rows[0]|| (await pool.query(`SELECT id,organization_id,assessment_id,engine,target,state,created_at FROM scanner_jobs WHERE organization_id=$1 AND assessment_id=$2 AND engine=$3 AND target=$4 AND state IN ('QUEUED','RUNNING') ORDER BY created_at DESC LIMIT 1`,[access.organization_id,assessmentId,e,target])).rows[0]
}
export async function listScannerJobs(userId:string,assessmentId:string){
 const access=await requireAssessmentAccess(userId,assessmentId);await requireOrgPermission(userId,access.organization_id,'read');
 return (await pool.query(`SELECT id,engine,target,state,evidence_id,evidence_hash,error,created_at,started_at,completed_at
 FROM scanner_jobs WHERE organization_id=$1 AND assessment_id=$2 ORDER BY created_at DESC LIMIT 200`,[access.organization_id,assessmentId])).rows
}
async function execute(e:ScannerEngine,target:string){switch(e){case'TESTSSL':{const checked=await validatePublicHttpTarget(target);const fresh=await revalidatePublicHttpTarget(checked);return scanTls(fresh.url.origin,pinnedAddress(fresh.addresses))}case'LYNIS':return scanHostHardening(target);case'GRYPE':return scanImageWithGrype(target);case'SYFT':return generateSbom(target);case'KUBESCAPE':return scanKubernetes(target);case'CHECKOV':return scanIac(target);case'GITLEAKS':return scanSecrets(target)}}
export async function recoverStaleScannerJobs(){const lease=Math.max(60,Number(process.env.SCANNER_JOB_LEASE_SECONDS||900)),maxAttempts=Math.max(1,Number(process.env.SCANNER_JOB_MAX_ATTEMPTS||2));return (await pool.query(`UPDATE scanner_jobs SET state=CASE WHEN attempts >= $2 THEN 'FAILED' ELSE 'QUEUED' END,error=CASE WHEN attempts >= $2 THEN 'Scanner worker lease expired after maximum attempts' ELSE error END,started_at=NULL,completed_at=CASE WHEN attempts >= $2 THEN now() ELSE NULL END WHERE state='RUNNING' AND started_at < now()-($1::text||' seconds')::interval RETURNING id,state`,[lease,maxAttempts])).rows}
export async function claimScannerJob(){
 const c=await pool.connect();try{await c.query('BEGIN');const row=(await c.query(`SELECT * FROM scanner_jobs WHERE state='QUEUED' ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1`)).rows[0];
 if(!row){await c.query('COMMIT');return null}const claimed=(await c.query(`UPDATE scanner_jobs SET state='RUNNING',started_at=now(),attempts=attempts+1 WHERE id=$1 AND state='QUEUED' RETURNING *`,[row.id])).rows[0];await c.query('COMMIT');return claimed||null
 }catch(e){await c.query('ROLLBACK');throw e}finally{c.release()}
}
export async function executeClaimedScannerJob(job:any,saveEvidence:(x:any)=>Promise<void>,saveAudit:(x:any)=>Promise<void>){
 try{const out=await execute(engine(job.engine),String(job.target));const evidenceId=crypto.randomUUID(),createdAt=new Date().toISOString(),state:ScannerJobState=out.state==='SUCCESS'?'SUCCEEDED':out.state;
  const ownership=(await pool.query(`SELECT id FROM scanner_jobs WHERE id=$1 AND state='RUNNING' AND attempts=$2`,[job.id,job.attempts])).rows[0];
  if(!ownership)throw Object.assign(new Error('Scanner job lease ownership was lost before evidence persistence'),{code:'STALE_SCANNER_LEASE'});
  await saveEvidence({id:evidenceId,assessmentId:job.assessment_id,source:String(job.engine).toLowerCase(),sha256:out.evidence.sha256,exitCode:out.exitCode,stdout:out.stdout,stderr:out.stderr,metadata:{...out.metadata,engine:job.engine,state:out.state,timedOut:out.timedOut,truncated:out.truncated,durationMs:out.durationMs,corroborative:true,scannerJobId:job.id,provenance:{integrationId:String(job.engine).toLowerCase(),integrationKind:'SCANNER',collectorVersion:String(out.metadata?.scannerVersion||out.metadata?.version||'unspecified'),collectedAt:createdAt,sourceRef:String(job.target),sha256:out.evidence.sha256,verified:true,verificationMethod:'LOCAL_EXECUTION',limitations:[]}},createdAt});
  const completed=(await pool.query(`UPDATE scanner_jobs SET state=$2,evidence_id=$3,evidence_hash=$4,completed_at=now() WHERE id=$1 AND state='RUNNING' AND attempts=$5 RETURNING id`,[job.id,state,evidenceId,out.evidence.sha256,job.attempts])).rows[0];
  if(!completed)throw Object.assign(new Error('Scanner job lease ownership was lost during completion'),{code:'STALE_SCANNER_LEASE'});
  await saveAudit({id:crypto.randomUUID(),assessmentId:job.assessment_id,action:'SCANNER_JOB_COMPLETED',actor:job.requested_by||'system',createdAt,metadata:{jobId:job.id,engine:job.engine,state,evidenceHash:out.evidence.sha256}});await saveAudit({id:crypto.randomUUID(),assessmentId:job.assessment_id,action:'CORROBORATIVE_SCANNER_EVIDENCE_CAPTURED',actor:job.requested_by||'system',createdAt,metadata:{jobId:job.id,engine:job.engine,target:job.target,state,evidenceHash:out.evidence.sha256}});
  return {id:job.id,state,evidenceId,evidenceHash:out.evidence.sha256}
 }catch(e:any){if(e?.code!=='STALE_SCANNER_LEASE')await pool.query(`UPDATE scanner_jobs SET state='FAILED',error=$2,completed_at=now() WHERE id=$1 AND state='RUNNING' AND attempts=$3`,[job.id,String(e?.message||e).slice(0,2000),job.attempts]);throw e}
}
