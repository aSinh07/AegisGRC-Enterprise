import crypto from 'node:crypto';
import {pool} from './db-pool.js';
import {requireOrgPermission} from './grc-organizations.js';

// Persisted, signed report records.
//
// Every governed PDF the platform issues (Offensive, Defensive, Enterprise GRC, audit
// package, readiness and assessment reports) is stored byte-for-byte with its SHA-256
// and an HMAC-SHA256 signature keyed by REPORT_SIGNING_KEY. The download carries the
// record id, digest and signature in response headers, and anyone in the organization
// can later prove that a PDF they hold was issued by AegisGRC and was not altered.

export type ReportType='OFFENSIVE'|'DEFENSIVE'|'ENTERPRISE_GRC'|'COMBINED_ASSURANCE'|'AUDIT_PACKAGE'|'AUDIT_READINESS'|'ASSESSMENT_REPORT';
const SIG_VERSION='AEGISGRC_REPORT_RECORD_V1';
const PLACEHOLDER=/change-me|replace-with|REPLACE_WITH/i;

export function reportRecordKey(env:NodeJS.ProcessEnv=process.env):string|null{
 const k=String(env.REPORT_SIGNING_KEY||'');
 if(k.length>=32&&!(env.NODE_ENV==='production'&&PLACEHOLDER.test(k)))return k;
 if(env.NODE_ENV==='production')throw new Error('REPORT_SIGNING_KEY (32+ non-placeholder characters) is required to issue signed reports');
 return null;
}
export const reportKeyId=(k:string)=>crypto.createHash('sha256').update('aegis-report-key-id|'+k).digest('hex').slice(0,16);

type SignedFields={id:string;organizationId:string|null;assessmentId:string|null;reportType:string;format:string;sha256:string;generatedBy:string|null;generatedAt:string};
export function reportRecordSigningInput(r:SignedFields){
 return [SIG_VERSION,r.id,r.organizationId||'',r.assessmentId||'',r.reportType,r.format,r.sha256,r.generatedBy||'',r.generatedAt].join('|');
}
export function signReportRecord(key:string,r:SignedFields){return crypto.createHmac('sha256',key).update(reportRecordSigningInput(r)).digest('hex')}

export async function recordSignedReport(input:{organizationId?:string|null;assessmentId?:string|null;scopeRef?:string|null;reportType:ReportType;format:string;filename:string;contentType:string;body:Buffer;actor:string}){
 const key=reportRecordKey(),sha256=crypto.createHash('sha256').update(input.body).digest('hex');
 const existing=(await pool.query('SELECT id,sha256,hmac_sha256,key_id,generated_at FROM report_records WHERE sha256=$1 AND report_type=$2',[sha256,input.reportType])).rows[0];
 if(existing)return {id:existing.id as string,sha256,signature:existing.hmac_sha256 as string|null,keyId:existing.key_id as string|null,generatedAt:new Date(existing.generated_at).toISOString(),reused:true};
 const id=crypto.randomUUID(),generatedAt=new Date().toISOString();
 const fields:SignedFields={id,organizationId:input.organizationId||null,assessmentId:input.assessmentId||null,reportType:input.reportType,format:input.format,sha256,generatedBy:input.actor||null,generatedAt};
 const signature=key?signReportRecord(key,fields):null,keyId=key?reportKeyId(key):null;
 const row=(await pool.query(`INSERT INTO report_records(id,organization_id,assessment_id,scope_ref,report_type,format,filename,content_type,sha256,size_bytes,content,hmac_sha256,key_id,generated_by,generated_at)
  VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) ON CONFLICT(sha256,report_type) DO NOTHING RETURNING id`,
  [id,fields.organizationId,fields.assessmentId,input.scopeRef||null,input.reportType,input.format,input.filename,input.contentType,sha256,input.body.length,input.body,signature,keyId,fields.generatedBy,generatedAt])).rows[0];
 if(!row)return recordSignedReport(input); // lost a race with an identical report: return the winner
 const auditId=crypto.randomUUID();
 await pool.query('INSERT INTO audit_events(id,assessment_id,action,created_at,payload) VALUES($1,$2,$3,$4,$5)',[auditId,fields.assessmentId,'SIGNED_REPORT_RECORDED',generatedAt,{id:auditId,assessmentId:fields.assessmentId||undefined,action:'SIGNED_REPORT_RECORDED',actor:input.actor,createdAt:generatedAt,metadata:{reportRecordId:id,organizationId:fields.organizationId,reportType:input.reportType,format:input.format,filename:input.filename,sha256,size:input.body.length,signed:Boolean(signature),keyId}}]);
 return {id,sha256,signature,keyId,generatedAt,reused:false};
}

export function reportHeaders(rec:{id:string;sha256:string;signature:string|null}){
 return {'X-Aegis-Report-Id':rec.id,'X-Aegis-Report-Sha256':rec.sha256,'X-Aegis-Report-Signature':rec.signature||'UNSIGNED','X-Aegis-Report-Verify':'/api/reports/'+rec.id+'/verify'};
}

export type ReportVerification={status:'VERIFIED'|'UNKNOWN_REPORT'|'SIGNATURE_INVALID'|'CONTENT_MISMATCH'|'UNSIGNED'|'KEY_UNAVAILABLE'|'KEY_MISMATCH';record?:Record<string,unknown>};

export function checkSignature(row:any):ReportVerification['status']{
 if(!row.hmac_sha256)return 'UNSIGNED';
 let key:string|null=null;try{key=reportRecordKey()}catch{key=null}
 if(!key)return 'KEY_UNAVAILABLE';
 if(reportKeyId(key)!==row.key_id)return 'KEY_MISMATCH';
 const expected=Buffer.from(signReportRecord(key,{id:row.id,organizationId:row.organization_id,assessmentId:row.assessment_id,reportType:row.report_type,format:row.format,sha256:row.sha256,generatedBy:row.generated_by,generatedAt:new Date(row.generated_at).toISOString()}),'hex'),actual=Buffer.from(String(row.hmac_sha256),'hex');
 return expected.length===actual.length&&crypto.timingSafeEqual(expected,actual)?'VERIFIED':'SIGNATURE_INVALID';
}
const publicRecord=(r:any)=>({id:r.id,organizationId:r.organization_id,assessmentId:r.assessment_id,reportType:r.report_type,format:r.format,filename:r.filename,sha256:r.sha256,size:Number(r.size_bytes),generatedBy:r.generated_by,generatedAt:new Date(r.generated_at).toISOString(),keyId:r.key_id});

/** Verify a stored record: stored bytes must still hash to the signed digest, and the signature must be valid. */
export async function verifyReportRecord(userId:string,id:string):Promise<ReportVerification>{
 const r=(await pool.query('SELECT *,encode(sha256(content),\'hex\') AS content_sha FROM report_records WHERE id=$1',[id])).rows[0];
 if(!r)return {status:'UNKNOWN_REPORT'};
 if(r.organization_id)await requireOrgPermission(userId,r.organization_id,'read');
 if(r.content_sha!==r.sha256)return {status:'CONTENT_MISMATCH',record:publicRecord(r)};
 return {status:checkSignature(r),record:publicRecord(r)};
}

/** Verify bytes someone holds (e.g. an emailed PDF) against the issued records. */
export async function verifyReportBytes(userId:string,body:Buffer):Promise<ReportVerification>{
 const sha256=crypto.createHash('sha256').update(body).digest('hex');
 const rows=(await pool.query('SELECT * FROM report_records WHERE sha256=$1 ORDER BY generated_at ASC',[sha256])).rows;
 for(const r of rows){
  try{if(r.organization_id)await requireOrgPermission(userId,r.organization_id,'read')}catch{continue}
  return {status:checkSignature(r),record:publicRecord(r)};
 }
 return {status:'UNKNOWN_REPORT'};
}
