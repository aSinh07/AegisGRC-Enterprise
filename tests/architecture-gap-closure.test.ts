import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {readFile} from 'node:fs/promises';
import pg from 'pg';
import {retestEvidenceIsComplete} from '../src/finding-review.js';
import {guardedDisposition,interimNotice,isTerminalAssessment} from '../src/report-status.js';
import {renderPdf} from '../src/pdf.js';
import {renderDefensiveSecurityPdf} from '../src/defensive-report.js';

const ciDb=process.env.NODE_ENV==='test'&&/^postgres(?:ql)?:\/\/[^/]*@(?:localhost|127\.0\.0\.1):5432\//.test(process.env.DATABASE_URL||'');

// Gap 1 — a killed/timed-out scanner must never be accepted as clean retest evidence.
test('retest closure rejects killed, timed-out and truncated scanner evidence',()=>{
 assert.equal(retestEvidenceIsComplete({exitCode:0,metadata:{}}),true);
 assert.equal(retestEvidenceIsComplete({exitCode:null,metadata:{timedOut:true}}),false,'SIGKILL yields exitCode null; Number(null)===0 must not pass');
 assert.equal(retestEvidenceIsComplete({exitCode:null,metadata:{}}),false);
 assert.equal(retestEvidenceIsComplete({exitCode:'0',metadata:{}}),false);
 assert.equal(retestEvidenceIsComplete({metadata:{}}),false);
 assert.equal(retestEvidenceIsComplete({exitCode:1,metadata:{}}),false);
 assert.equal(retestEvidenceIsComplete({exitCode:0,metadata:{timedOut:true}}),false);
 assert.equal(retestEvidenceIsComplete({exitCode:0,metadata:{stdoutTruncated:true}}),false);
 assert.equal(retestEvidenceIsComplete({exitCode:0,metadata:{stderrTruncated:true}}),false);
 assert.equal(retestEvidenceIsComplete(null),false);
});
test('finding review closure uses the strict retest completeness gate',async()=>{
 const src=await readFile(new URL('../src/finding-review.ts',import.meta.url),'utf8');
 assert.match(src,/retestEvidenceIsComplete\(ev\.payload\)/);
 assert.doesNotMatch(src,/Number\(ev\.payload\?\.exitCode\)/);
});

// Gap 2 — non-terminal assessments can never produce a clean/green report conclusion.
test('report disposition is interim and never green while an assessment is RUNNING',()=>{
 const running=guardedDisposition('RUNNING','NO MATERIAL FINDINGS OBSERVED','GREEN',0);
 assert.equal(running.interim,true);assert.equal(running.tone,'AMBER');
 assert.doesNotMatch(running.text,/NO MATERIAL FINDINGS/);assert.match(running.text,/INTERIM/);
 assert.equal(guardedDisposition('RUNNING','REMEDIATION REQUIRED','RED',2).tone,'RED');
 assert.match(guardedDisposition('AUTHORIZED','x','GREEN',1).text,/INTERIM SNAPSHOT · ASSESSMENT AUTHORIZED/);
 const failed=guardedDisposition('FAILED','NO MATERIAL FINDINGS OBSERVED','GREEN',0);
 assert.equal(failed.tone,'AMBER');assert.match(failed.text,/NO ASSURANCE CONCLUSION/);
 assert.equal(guardedDisposition('INTERRUPTED','x','GREEN',0).tone,'AMBER');
 assert.deepEqual(guardedDisposition('COMPLETED','NO MATERIAL FINDINGS OBSERVED','GREEN',0),{text:'NO MATERIAL FINDINGS OBSERVED',tone:'GREEN',interim:false});
 assert.equal(isTerminalAssessment('completed'),true);assert.equal(isTerminalAssessment('RUNNING'),false);
 assert.match(String(interimNotice('RUNNING')),/INTERIM REPORT/);assert.equal(interimNotice('PARTIAL'),null);
});
test('technical, remediation and defensive PDFs render for interim and interrupted assessments',async()=>{
 for(const status of ['RUNNING','INTERRUPTED','COMPLETED'] as const){
  const a:any={id:crypto.randomUUID(),target:'https://example.test',authorizedAt:new Date().toISOString(),status,findings:[],evidenceIds:[]};
  for(const kind of ['technical','remediation'] as const){const b=await renderPdf(a,[],[],kind);assert.ok(b.length>1000);assert.equal(b.subarray(0,5).toString(),'%PDF-')}
  const d=await renderDefensiveSecurityPdf(a,[],[]);assert.ok(d.length>1000);
 }
});

// Gap 3 — orphaned RUNNING full assessments are recovered after restart.
test('server recovers orphaned RUNNING assessments at boot and periodically',async()=>{
 const s=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');
 assert.match(s,/await recoverInterruptedAssessments\(\[\],0\)/);
 assert.match(s,/recoverInterruptedAssessments\(activeFullScans\.keys\(\),maxFullAssessmentMs\(\)\)/);
 const store=await readFile(new URL('../src/store.ts',import.meta.url),'utf8');
 assert.match(store,/payload=EXCLUDED\.payload,updated_at=now\(\)/);
});

// Gap 4 — ZAP (a required full-assessment engine) and the Caddy edge are deployed.
test('production compose deploys ZAP for the aegis service and an opt-in Caddy edge',async()=>{
 const c=await readFile(new URL('../docker-compose.production.yml',import.meta.url),'utf8');
 assert.match(c,/\n  zap:\n/);assert.match(c,/ZAP_URL: http:\/\/zap:8080/);assert.match(c,/api\.disablekey=false/);
 assert.doesNotMatch(c,/zap:[\s\S]*?ports:\s*\n\s*- "8080/);
 assert.match(c,/\n  caddy:\n[\s\S]*profiles: \["edge"\]/);assert.match(c,/Caddyfile\.production:\/etc\/caddy\/Caddyfile:ro/);
 const d=await readFile(new URL('../scripts/deploy-gce.sh',import.meta.url),'utf8');
 assert.match(d,/required=\([^)]*ZAP_API_KEY\)/);assert.match(d,/up -d --no-deps zap/);
 const e=await readFile(new URL('../.env.production.example',import.meta.url),'utf8');
 assert.match(e,/ZAP_API_KEY=REPLACE_WITH/);
});

// Gap 5 — audit attribution and evidence immutability.
test('audit events record the real acting user instead of a generic operator',async()=>{
 const s=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');
 assert.doesNotMatch(s,/actor:'operator'/);
 assert.match(s,/action:'DOCUMENT_WITHDRAWN',actor:u\.userId/);
 assert.match(s,/executeRealTool\(name,assessmentId,t,userId\)/);
});
test('schema makes evidence and audit events append-only and documents retained',async()=>{
 const sql=await readFile(new URL('../db/schema.sql',import.meta.url),'utf8');
 assert.match(sql,/CREATE TRIGGER evidence_append_only BEFORE UPDATE OR DELETE ON evidence/);
 assert.match(sql,/CREATE TRIGGER audit_events_append_only BEFORE UPDATE OR DELETE ON audit_events/);
 assert.match(sql,/CREATE TRIGGER documents_content_immutable/);
 assert.match(sql,/evidence_assessment_id_fkey FOREIGN KEY \(assessment_id\) REFERENCES assessments\(id\) ON DELETE RESTRICT/);
 const store=await readFile(new URL('../src/store.ts',import.meta.url),'utf8');
 assert.doesNotMatch(store,/DELETE FROM documents/);
});

test('PostgreSQL enforces append-only evidence, retained documents and assessment recovery',{skip:!ciDb},async()=>{
 const pool=new pg.Pool({connectionString:process.env.DATABASE_URL,ssl:false});
 const sql=await readFile(new URL('../db/schema.sql',import.meta.url),'utf8');
 await pool.query(sql);await pool.query(sql); // idempotent re-run
 const a=crypto.randomUUID(),ev=crypto.randomUUID(),au=crypto.randomUUID(),doc=crypto.randomUUID(),sha='a'.repeat(64);
 await pool.query(`INSERT INTO assessments(id,target,authorized_at,status,payload,updated_at) VALUES($1,'https://example.test',now(),'RUNNING',$2,now()-interval '3 hours')`,[a,{id:a,status:'RUNNING'}]);
 await pool.query(`INSERT INTO evidence(id,assessment_id,source,sha256,created_at,payload) VALUES($1,$2,'nmap',$3,now(),'{}')`,[ev,a,sha]);
 await pool.query(`INSERT INTO audit_events(id,assessment_id,action,created_at,payload) VALUES($1,$2,'T',now(),'{}')`,[au,a]);
 await pool.query(`INSERT INTO documents(id,assessment_id,filename,mime_type,size_bytes,sha256,created_at,content) VALUES($1,$2,'p.pdf','application/pdf',3,$3,now(),'\\x010203')`,[doc,a,sha]);
 await assert.rejects(pool.query(`UPDATE evidence SET sha256=$2 WHERE id=$1`,[ev,'b'.repeat(64)]),/append-only/);
 await assert.rejects(pool.query(`DELETE FROM evidence WHERE id=$1`,[ev]),/append-only/);
 await assert.rejects(pool.query(`UPDATE audit_events SET action='X' WHERE id=$1`,[au]),/append-only/);
 await assert.rejects(pool.query(`DELETE FROM audit_events WHERE id=$1`,[au]),/append-only/);
 await assert.rejects(pool.query(`TRUNCATE evidence CASCADE`),/append-only/);
 await assert.rejects(pool.query(`DELETE FROM documents WHERE id=$1`,[doc]),/withdrawal/);
 await assert.rejects(pool.query(`UPDATE documents SET content='\\x00' WHERE id=$1`,[doc]),/immutable/);
 await pool.query(`UPDATE documents SET withdrawn_at=now() WHERE id=$1`,[doc]);
 await assert.rejects(pool.query(`UPDATE documents SET withdrawn_at=NULL WHERE id=$1`,[doc]),/immutable/);
 await assert.rejects(pool.query(`DELETE FROM assessments WHERE id=$1`,[a]),/foreign key|violates/);

 // Recovery: an active in-process id is skipped; an orphaned RUNNING row becomes INTERRUPTED with an audit event.
 const {recoverInterruptedAssessments}=await import('../src/assessment-recovery.js');
 const active=crypto.randomUUID();
 await pool.query(`INSERT INTO assessments(id,target,authorized_at,status,payload,updated_at) VALUES($1,'https://example.test',now(),'RUNNING',$2,now()-interval '3 hours')`,[active,{id:active,status:'RUNNING'}]);
 const recovered=await recoverInterruptedAssessments([active],60*60*1000);
 assert.ok(recovered.includes(a));assert.ok(!recovered.includes(active));
 const row=(await pool.query(`SELECT status,payload->>'status' AS ps,payload->>'interruptionReason' AS reason FROM assessments WHERE id=$1`,[a])).rows[0];
 assert.equal(row.status,'INTERRUPTED');assert.equal(row.ps,'INTERRUPTED');assert.match(row.reason,/interrupted/i);
 assert.equal((await pool.query(`SELECT count(*)::int n FROM audit_events WHERE assessment_id=$1 AND action='ASSESSMENT_INTERRUPTED'`,[a])).rows[0].n,1);
 assert.equal((await pool.query(`SELECT status FROM assessments WHERE id=$1`,[active])).rows[0].status,'RUNNING');

 // Explicit, transaction-scoped purge remains possible for governed retention.
 const c=await pool.connect();
 try{await c.query('BEGIN');await c.query(`SET LOCAL aegis.allow_evidence_purge='on'`);
  await c.query('DELETE FROM documents WHERE assessment_id=ANY($1::uuid[])',[[a,active]]);await c.query('DELETE FROM evidence WHERE assessment_id=ANY($1::uuid[])',[[a,active]]);
  await c.query('DELETE FROM audit_events WHERE assessment_id=ANY($1::uuid[])',[[a,active]]);await c.query('DELETE FROM assessments WHERE id=ANY($1::uuid[])',[[a,active]]);await c.query('COMMIT')}
 finally{c.release()}
 assert.equal((await pool.query('SELECT count(*)::int n FROM evidence WHERE id=$1',[ev])).rows[0].n,0);
 const {pool:shared}=await import('../src/db-pool.js');await shared.end();await pool.end();
});
