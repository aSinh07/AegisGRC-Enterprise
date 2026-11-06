import crypto from 'node:crypto';
import {db} from './store.js';
import type {Evidence,Finding} from './models.js';
import type {RawScanResult} from './scan-runner.js';
import {httpPostureFindings} from './http-posture.js';
import {zapFindings} from './zap.js';
import {wapitiFindings,nmapFindings} from './parsers.js';
import {nucleiJsonlFindings,sqlmapTextFindings} from './infrastructure-parsers.js';
import {configureScanJobPersistence} from './url-scan-jobs.js';

// System-of-record side of a scan task: evidence is hashed and HMAC-signed here (never on the
// worker), findings are parsed here, and the assessment is finalized from the job coverage.
export async function persistScanTaskResult(ctx:{jobId:string;taskId:string;assessmentId:string;profile:string;origin:string;pinnedAddresses:string[];requestedBy:string|null},raw:RawScanResult,attestation:Record<string,unknown>){
 const url=new URL(ctx.origin),receivedAt=new Date().toISOString();
 const doc=JSON.stringify({tool:raw.tool,target:ctx.origin,startedAt:raw.startedAt,completedAt:raw.completedAt,stdout:raw.stdout,stderr:raw.stderr,exitCode:raw.exitCode,durationMs:raw.durationMs,timedOut:raw.timedOut,stdoutTruncated:raw.stdoutTruncated,stderrTruncated:raw.stderrTruncated});
 const sha256=crypto.createHash('sha256').update(doc).digest('hex');
 // createdAt is the server receipt time (the system of record's clock), worker times stay in metadata.
 const ev:Evidence={id:crypto.randomUUID(),assessmentId:ctx.assessmentId,source:raw.tool,sha256,createdAt:receivedAt,exitCode:raw.exitCode,stdout:raw.stdout,stderr:raw.stderr,metadata:{target:ctx.origin,resolvedAddresses:ctx.pinnedAddresses,egress:raw.egress,...(raw.nucleiTemplates?{nucleiTemplates:raw.nucleiTemplates}:{}),...(raw.zapMode?{zapMode:raw.zapMode}:{}),workerStartedAt:raw.startedAt,workerCompletedAt:raw.completedAt,durationMs:raw.durationMs,timedOut:raw.timedOut,stdoutTruncated:raw.stdoutTruncated,stderrTruncated:raw.stderrTruncated,scanJobId:ctx.jobId,scanTaskId:ctx.taskId,profile:ctx.profile,workerAttestation:attestation,attackSurfaceAssessed:raw.tool==='nmap'||raw.tool==='nuclei',attackSurfaceAssetId:ctx.origin,...(raw.tool==='http'?{mode:'live-http-posture'}:{})}};
 await db.saveEvidence(ev);
 let findings:Finding[]=[];
 try{
  if(raw.tool==='http'){if(raw.exitCode===0)findings=httpPostureFindings(ctx.assessmentId,url,JSON.parse(raw.stdout||'{}').headers||{},sha256,receivedAt) as Finding[]}
  else if(raw.tool==='zap')findings=zapFindings(ctx.assessmentId,ctx.origin,sha256,JSON.parse(raw.stdout||'[]'));
  else if(raw.tool==='wapiti')findings=wapitiFindings(ctx.assessmentId,ctx.origin,sha256,raw.stdout);
  else if(raw.tool==='nmap')findings=nmapFindings(ctx.assessmentId,ctx.origin,sha256,raw.stdout);
  else if(raw.tool==='nuclei')findings=nucleiJsonlFindings(ctx.assessmentId,ctx.origin,sha256,raw.stdout);
  else if(raw.tool==='sqlmap')findings=sqlmapTextFindings(ctx.assessmentId,ctx.origin,sha256,raw.stdout);
 }catch(e:any){console.error('[AEGIS SCAN JOB] parser failed',raw.tool,String(e?.message||e))}
 if(findings.length)await db.saveFindings(findings);
 await db.saveAudit({id:crypto.randomUUID(),assessmentId:ctx.assessmentId,action:'REAL_SCAN_COMPLETED',actor:'worker:'+String(attestation.workerId||'unknown'),createdAt:receivedAt,metadata:{tool:raw.tool,exitCode:raw.exitCode,evidenceHash:sha256,durationMs:raw.durationMs,timedOut:raw.timedOut,stdoutTruncated:raw.stdoutTruncated,stderrTruncated:raw.stderrTruncated,findingCount:findings.length,scanJobId:ctx.jobId,scanTaskId:ctx.taskId,profile:ctx.profile,requestedBy:ctx.requestedBy,workerSignatureVerified:attestation.signatureVerified===true}});
 return {evidenceId:ev.id,sha256,findingCount:findings.length};
}
export async function finalizeAssessmentFromJob(assessmentId:string,status:'COMPLETED'|'PARTIAL'|'FAILED',coverage:any,actor:string,jobId:string){
 const a=await db.assessment(assessmentId);if(!a)return;
 const allFindings=await db.findingsForAssessment(assessmentId),allEvidence=await db.evidenceForAssessment(assessmentId);
 await db.saveAssessment({...a,status,scanCoverage:coverage,findings:allFindings,evidenceIds:allEvidence.map(x=>x.id)});
 await db.saveAudit({id:crypto.randomUUID(),assessmentId,action:'FULL_ASSESSMENT_COMPLETED',actor,createdAt:new Date().toISOString(),metadata:{status,findingCount:allFindings.length,evidenceCount:allEvidence.length,coverage,scanJobId:jobId}});
 console.log('[AEGIS SCAN JOB] '+jobId+' '+status+' | findings='+allFindings.length);
}
export function installScanJobPersistence(){configureScanJobPersistence(persistScanTaskResult as any,finalizeAssessmentFromJob)}
