import crypto from 'node:crypto';
import { promises as fs } from 'node:fs';import path from 'node:path';import pg from 'pg';
import type { Assessment,Evidence,Finding,AuditEvent } from './models.js';
import {findingFingerprint} from './finding-correlation.js';
import {signEvidence} from './evidence-signing.js';
import {assignFingerprintLineage} from './finding-dedupe.js';
import {integrationById,evidenceTrust,provenanceFingerprint,type EvidenceProvenance} from './integration-contract.js';
const dir=process.env.DATA_DIR||'/tmp/aegis-data'; const url=process.env.DATABASE_URL;
const production=process.env.NODE_ENV==='production';
if(production&&!url) throw new Error('DATABASE_URL is required in production');
const pool=url?new pg.Pool({connectionString:url,ssl:process.env.PGSSL==='disable'?false:{rejectUnauthorized:false}}):null;
async function rw<T>(name:string,f:(x:T[])=>T[]){await fs.mkdir(dir,{recursive:true});const p=path.join(dir,name);let a:T[]=[];try{a=JSON.parse(await fs.readFile(p,'utf8'))}catch{};a=f(a);await fs.writeFile(p,JSON.stringify(a,null,2));return a}
async function read<T>(name:string){try{return JSON.parse(await fs.readFile(path.join(dir,name),'utf8')) as T[]}catch{return []}}
const allowedTables={assessments:'authorized_at',evidence:'created_at',findings:'created_at',audit_events:'created_at'} as const;
async function qPayload<T>(table:keyof typeof allowedTables){if(!pool)return null;const order=allowedTables[table];const r=await pool.query(`SELECT payload FROM ${table} ORDER BY ${order} ASC`);return r.rows.map(x=>x.payload as T)}
async function upsertAssessment(x:Assessment){if(!pool)return rw<Assessment>('assessments.json',a=>[...a.filter(v=>v.id!==x.id),x]);const meta=x as Assessment&{createdBy?:string;organizationId?:string};await pool.query(`INSERT INTO assessments(id,target,authorized_at,status,payload,created_by,organization_id) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(id) DO UPDATE SET target=EXCLUDED.target,status=EXCLUDED.status,payload=EXCLUDED.payload,updated_at=now(),created_by=COALESCE(assessments.created_by,EXCLUDED.created_by),organization_id=COALESCE(assessments.organization_id,EXCLUDED.organization_id)`,[x.id,x.target,x.authorizedAt,x.status,x,meta.createdBy||null,meta.organizationId||null]);return []}
async function insert(table:string,x:any,cols:string[],vals:any[]){if(!pool)return null;await pool.query(`INSERT INTO ${table}(${cols.join(',')}) VALUES(${cols.map((_,i)=>'$'+(i+1)).join(',')}) ON CONFLICT(id) DO NOTHING`,vals)}
function withEvidenceProvenance(x:Evidence):Evidence{
 const existing=(x.metadata as any)?.provenance as EvidenceProvenance|undefined;
 if(existing){const trust=evidenceTrust(existing);return {...x,metadata:{...x.metadata,provenance:existing,evidenceTrust:trust,provenanceFingerprint:provenanceFingerprint(existing)}}}
 const integration=integrationById(String(x.source||'').toLowerCase());
 if(!integration)return {...x,metadata:{...x.metadata,evidenceTrust:'UNVERIFIED',provenanceLimitations:['Evidence source is not registered in the integration catalog']}};
 const method:EvidenceProvenance['verificationMethod']=integration.kind==='SCANNER'?'LOCAL_EXECUTION':'IMPORTED_REPORT';
 const verified=false;
 const p:EvidenceProvenance={integrationId:integration.id,integrationKind:integration.kind,collectorVersion:String((x.metadata as any)?.collectorVersion||(x.metadata as any)?.scannerVersion||'unspecified'),collectedAt:x.createdAt,sourceRef:String((x.metadata as any)?.target||(x.metadata as any)?.assetId||x.assessmentId),sha256:x.sha256,verified,verificationMethod:method,limitations:[...integration.limitations,'Trusted provenance was not explicitly supplied by the collection path']};
 return {...x,metadata:{...x.metadata,provenance:p,evidenceTrust:evidenceTrust(p),provenanceFingerprint:provenanceFingerprint(p)}};
}
export const db={
 mode:()=>pool?'postgres':'file',
 ready:async()=>{if(!pool){if(production)throw new Error('PostgreSQL is required in production');return {ok:true,mode:'file'}};await pool.query('SELECT 1');return {ok:true,mode:'postgres'}},
 assessments:async()=>pool?(await qPayload<Assessment>('assessments'))!:read<Assessment>('assessments.json'),
 assessment:async(id:string)=>{if(!pool)return (await read<Assessment>('assessments.json')).find(x=>x.id===id)||null;const r=await pool.query('SELECT payload FROM assessments WHERE id=$1',[id]);return (r.rows[0]?.payload as Assessment)||null},
 assessmentForUser:async(userId:string,id:string)=>{if(!pool)return null;const r=await pool.query(`SELECT a.payload FROM assessments a JOIN grc_organization_members m ON m.organization_id=a.organization_id JOIN grc_organizations o ON o.id=a.organization_id WHERE a.id=$1 AND m.user_id=$2 AND m.status='ACTIVE' AND o.status='ACTIVE'`,[id,userId]);return (r.rows[0]?.payload as Assessment)||null},
 assessmentsForUser:async(userId:string)=>{if(!pool)return [];const r=await pool.query(`SELECT a.payload FROM assessments a JOIN grc_organization_members m ON m.organization_id=a.organization_id JOIN grc_organizations o ON o.id=a.organization_id WHERE m.user_id=$1 AND m.status='ACTIVE' AND o.status='ACTIVE' ORDER BY a.authorized_at DESC`,[userId]);return r.rows.map(x=>x.payload as Assessment)},
 findingsForAssessment:async(assessmentId:string)=>{if(!pool)return (await read<Finding>('findings.json')).filter(x=>x.assessmentId===assessmentId);const r=await pool.query('SELECT payload FROM findings WHERE assessment_id=$1 ORDER BY created_at ASC',[assessmentId]);return r.rows.map(x=>x.payload as Finding)},
 evidenceForAssessment:async(assessmentId:string)=>{if(!pool)return (await read<Evidence>('evidence.json')).filter(x=>x.assessmentId===assessmentId);const r=await pool.query('SELECT payload FROM evidence WHERE assessment_id=$1 ORDER BY created_at ASC',[assessmentId]);return r.rows.map(x=>x.payload as Evidence)},
 auditsForAssessment:async(assessmentId:string)=>{if(!pool)return (await read<AuditEvent>('audit.json')).filter(x=>x.assessmentId===assessmentId);const r=await pool.query('SELECT payload FROM audit_events WHERE assessment_id=$1 ORDER BY created_at ASC',[assessmentId]);return r.rows.map(x=>x.payload as AuditEvent)},
 evidence:async()=>pool?(await qPayload<Evidence>('evidence'))!:read<Evidence>('evidence.json'),
 findings:async()=>pool?(await qPayload<Finding>('findings'))!:read<Finding>('findings.json'),
 audits:async()=>pool?(await qPayload<AuditEvent>('audit_events'))!:read<AuditEvent>('audit.json'),
 saveAssessment:upsertAssessment,
 saveFindingImport:async(evidence:Evidence,findings:Finding[],audit:AuditEvent)=>{
  evidence=signEvidence(withEvidenceProvenance(evidence));
  if(!pool)throw new Error('Atomic finding import requires PostgreSQL');
  if(!/^[0-9a-f]{64}$/.test(evidence.sha256))throw new Error('Evidence SHA-256 must be a server-computed lowercase 64-character digest');
  const byteLength=Buffer.byteLength(JSON.stringify({stdout:evidence.stdout||'',stderr:evidence.stderr||'',metadata:evidence.metadata||{}}));
  const client=await pool.connect();try{await client.query('BEGIN');
   await client.query(`INSERT INTO evidence(id,assessment_id,source,sha256,created_at,payload,byte_length,integrity_verified_at,hmac_sha256,hmac_key_id) VALUES($1,$2,$3,$4,$5,$6,$7,now(),$8,$9) ON CONFLICT(id) DO NOTHING`,[evidence.id,evidence.assessmentId,evidence.source,evidence.sha256,evidence.createdAt,evidence,byteLength,(evidence.metadata as any)?.evidenceSignature?.mac||null,(evidence.metadata as any)?.evidenceSignature?.keyId||null]);
   findings=await assignFingerprintLineage(client,findings.map(x=>({...x,fingerprint:x.fingerprint||findingFingerprint(x)})));
   for(const x of findings)await client.query(`INSERT INTO findings(id,assessment_id,severity,source,created_at,payload) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(id) DO NOTHING`,[x.id,x.assessmentId,x.severity,x.source,x.createdAt,x]);
   await client.query(`INSERT INTO audit_events(id,assessment_id,action,created_at,payload) VALUES($1,$2,$3,$4,$5) ON CONFLICT(id) DO NOTHING`,[audit.id,audit.assessmentId||null,audit.action,audit.createdAt,audit]);
   await client.query('COMMIT');return {evidenceId:evidence.id,findingCount:findings.length,auditId:audit.id};
  }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
 },
 saveFindingRetest:async(x:{id:string;findingId:string;assessmentId:string;evidenceId:string;fingerprint:string;scannerSource:string;scannerId?:string|null;createdBy:string},audit:AuditEvent)=>{if(!pool)throw new Error('Targeted retest binding requires PostgreSQL');const client=await pool.connect();try{await client.query('BEGIN');const finding=(await client.query('SELECT 1 FROM findings WHERE id=$1 AND assessment_id=$2',[x.findingId,x.assessmentId])).rows[0],evidence=(await client.query('SELECT 1 FROM evidence WHERE id=$1 AND assessment_id=$2 AND source=$3',[x.evidenceId,x.assessmentId,x.scannerSource])).rows[0];if(!finding||!evidence)throw new Error('Retest linkage assessment/source integrity check failed');await client.query('INSERT INTO finding_retests(id,finding_id,assessment_id,evidence_id,fingerprint,scanner_source,scanner_id,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8)',[x.id,x.findingId,x.assessmentId,x.evidenceId,x.fingerprint,x.scannerSource,x.scannerId||null,x.createdBy]);
   // Lifecycle loop: a completed retest that still detects the fingerprint sends the remediation back to CAPA.
   const m=(audit.metadata||{}) as any;
   if(m.stillPresent===true&&(m.exitCode===undefined||m.exitCode===0)){
    const capas=(await client.query(`UPDATE grc_capa c SET status='CHANGES_REQUESTED',updated_at=now() FROM grc_issues i WHERE c.issue_id=i.id AND i.finding_id=$1 AND i.assessment_id=$2 AND c.status IN ('OPEN','IN_PROGRESS','EVIDENCE_SUBMITTED','RETEST_PENDING','VALIDATION') RETURNING c.id,c.organization_id`,[x.findingId,x.assessmentId])).rows;
    for(const c of capas)await client.query(`INSERT INTO grc_record_events(id,organization_id,record_type,record_id,event,actor_user_id,snapshot) VALUES($1,$2,'CAPA',$3,'FINDING_RETEST_STILL_PRESENT',$4,$5)`,[crypto.randomUUID(),c.organization_id,c.id,x.createdBy,{findingId:x.findingId,evidenceId:x.evidenceId,fingerprint:x.fingerprint,retestId:x.id}]);
   }await client.query('INSERT INTO audit_events(id,assessment_id,action,created_at,payload) VALUES($1,$2,$3,$4,$5)',[audit.id,audit.assessmentId||null,audit.action,audit.createdAt,audit]);await client.query('COMMIT');return x}catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}},
 saveEvidence:async(x:Evidence)=>{x=signEvidence(withEvidenceProvenance(x));if(!pool)return rw<Evidence>('evidence.json',a=>[...a,x]);if(!/^[0-9a-f]{64}$/.test(x.sha256))throw new Error('Evidence SHA-256 must be a server-computed lowercase 64-character digest');const byteLength=Buffer.byteLength(JSON.stringify({stdout:x.stdout||'',stderr:x.stderr||'',metadata:x.metadata||{}}));await pool.query(`INSERT INTO evidence(id,assessment_id,source,sha256,created_at,payload,byte_length,integrity_verified_at,hmac_sha256,hmac_key_id) VALUES($1,$2,$3,$4,$5,$6,$7,now(),$8,$9) ON CONFLICT(id) DO NOTHING`,[x.id,x.assessmentId,x.source,x.sha256,x.createdAt,x,byteLength,(x.metadata as any)?.evidenceSignature?.mac||null,(x.metadata as any)?.evidenceSignature?.keyId||null]);return []},
 saveFindings:async(xs:Finding[])=>{xs=xs.map(x=>({...x,fingerprint:x.fingerprint||findingFingerprint(x)}));if(pool)xs=await assignFingerprintLineage(pool,xs);if(!pool)return rw<Finding>('findings.json',a=>[...a,...xs.filter(x=>!a.some(v=>v.id===x.id))]);for(const x of xs)await insert('findings',x,['id','assessment_id','severity','source','created_at','payload'],[x.id,x.assessmentId,x.severity,x.source,x.createdAt,x]);return []},
 saveAudit:async(x:AuditEvent)=>{if(!pool)return rw<AuditEvent>('audit.json',a=>[...a,x]);await insert('audit_events',x,['id','assessment_id','action','created_at','payload'],[x.id,x.assessmentId||null,x.action,x.createdAt,x]);return []},
 saveDocument:async(x:{id:string,assessmentId:string,filename:string,mimeType:string,size:number,sha256:string,createdAt:string,content:Buffer,documentType?:string,description?:string})=>{if(!pool)throw new Error('Document vault requires PostgreSQL');await pool.query('INSERT INTO documents(id,assessment_id,filename,mime_type,size_bytes,sha256,created_at,content) VALUES($1,$2,$3,$4,$5,$6,$7,$8)',[x.id,x.assessmentId,x.filename,x.mimeType,x.size,x.sha256,x.createdAt,x.content])},
 documents:async(assessmentId:string)=>{if(!pool)return [];const r=await pool.query('SELECT id,assessment_id as "assessmentId",filename,mime_type as "mimeType",size_bytes as size,sha256,created_at as "createdAt" FROM documents WHERE assessment_id=$1 AND withdrawn_at IS NULL ORDER BY created_at DESC',[assessmentId]);return r.rows},
 document:async(id:string)=>{if(!pool)return null;const r=await pool.query('SELECT id,assessment_id as "assessmentId",filename,mime_type as "mimeType",size_bytes as size,sha256,created_at as "createdAt",content FROM documents WHERE id=$1 AND withdrawn_at IS NULL',[id]);return r.rows[0]||null},
 deleteDocument:async(id:string,actorUserId?:string)=>{if(!pool)return false;const r=await pool.query('UPDATE documents SET withdrawn_at=now(),withdrawn_by=$2 WHERE id=$1 AND withdrawn_at IS NULL',[id,actorUserId||null]);return (r.rowCount||0)>0}
};