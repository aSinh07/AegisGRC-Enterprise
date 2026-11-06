import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {readFile} from 'node:fs/promises';
import pg from 'pg';
import {signEvidence,verifyEvidenceSignature,canonicalJson,evidenceSigningKey} from '../src/evidence-signing.js';
import {auditEntryHash,GENESIS_HASH} from '../src/audit-chain.js';

const ciDb=process.env.NODE_ENV==='test'&&/^postgres(?:ql)?:\/\/[^/]*@(?:localhost|127\.0\.0\.1):5432\//.test(process.env.DATABASE_URL||'');
const KEY='k'.repeat(40);
const env={EVIDENCE_HMAC_KEY:KEY,NODE_ENV:'test'} as NodeJS.ProcessEnv;
const sample=()=>({id:crypto.randomUUID(),assessmentId:crypto.randomUUID(),source:'nmap',sha256:'a'.repeat(64),createdAt:'2026-11-06T00:00:00.000Z',exitCode:0,stdout:'<nmaprun/>',stderr:'',metadata:{target:'https://example.com',durationMs:12,nested:{b:1,a:[1,2]}}});

// ── Gap: evidence is plain SHA-256 ──────────────────────────────────────────
test('evidence HMAC signs the canonical record and verifies after a jsonb-style round trip',()=>{
 const signed=signEvidence(sample(),env);
 const sig=(signed.metadata as any).evidenceSignature;
 assert.equal(sig.alg,'HMAC-SHA256');assert.match(sig.mac,/^[0-9a-f]{64}$/);
 const roundTrip=JSON.parse(canonicalJson(signed)); // key order changes like jsonb
 assert.equal(verifyEvidenceSignature(roundTrip,env).status,'VALID');
});
test('evidence HMAC detects tampering with output, hash, exit code or metadata',()=>{
 const signed=signEvidence(sample(),env);
 for(const mutate of [(x:any)=>{x.stdout+='x'},(x:any)=>{x.sha256='b'.repeat(64)},(x:any)=>{x.exitCode=1},(x:any)=>{x.metadata.target='https://evil.example'},(x:any)=>{x.assessmentId=crypto.randomUUID()}]){
  const copy=structuredClone(signed);mutate(copy);assert.equal(verifyEvidenceSignature(copy,env).status,'INVALID');
 }
 assert.equal(verifyEvidenceSignature(signed,{...env,EVIDENCE_HMAC_KEY:'z'.repeat(40)}).status,'KEY_MISMATCH');
 assert.equal(verifyEvidenceSignature(sample(),env).status,'UNSIGNED');
});
test('evidence signing fails closed in production without a real key',()=>{
 assert.throws(()=>evidenceSigningKey({NODE_ENV:'production'} as any),/EVIDENCE_HMAC_KEY/);
 assert.throws(()=>evidenceSigningKey({NODE_ENV:'production',EVIDENCE_HMAC_KEY:'REPLACE_WITH_AT_LEAST_32_RANDOM_BYTES'} as any),/EVIDENCE_HMAC_KEY/);
 assert.throws(()=>evidenceSigningKey({NODE_ENV:'production',EVIDENCE_HMAC_KEY:'short'} as any),/EVIDENCE_HMAC_KEY/);
 assert.equal(evidenceSigningKey({NODE_ENV:'production',EVIDENCE_HMAC_KEY:KEY} as any),KEY);
 assert.equal(evidenceSigningKey({NODE_ENV:'development'} as any),null);
});
test('every evidence write path in the store signs and persists the MAC',async()=>{
 const src=await readFile(new URL('../src/store.ts',import.meta.url),'utf8');
 assert.equal((src.match(/signEvidence\(withEvidenceProvenance\(/g)||[]).length,2);
 assert.equal((src.match(/hmac_sha256,hmac_key_id/g)||[]).length,2);
});

test('audit chain database trigger links rows, detects edits and survives concurrent writers',{skip:!ciDb},async()=>{
 const {execFileSync}=await import('node:child_process');
 execFileSync('npx',['tsx','scripts/init-db.ts'],{env:process.env,stdio:'ignore'});
 const pool=new pg.Pool({connectionString:process.env.DATABASE_URL,ssl:false});
 try{
  const ids=Array.from({length:12},()=>crypto.randomUUID());
  await Promise.all(ids.map((id,i)=>pool.query('INSERT INTO audit_events(id,assessment_id,action,created_at,payload) VALUES($1,NULL,$2,now(),$3)',[id,'TEST_CHAIN_'+i,{id,action:'TEST_CHAIN_'+i,actor:'test',metadata:{i}}])));
  const {verifyAuditChain,checkpointAuditChain}=await import('../src/audit-chain.js');
  process.env.EVIDENCE_HMAC_KEY=KEY;
  const ok=await verifyAuditChain();
  assert.equal(ok.status,'INTACT',JSON.stringify(ok.breaks));assert.ok(ok.checked>=12);
  const cp=await checkpointAuditChain();assert.ok(cp.created||cp.reason==='HEAD_ALREADY_CHECKPOINTED');
  const after=await verifyAuditChain();assert.equal(after.checkpoints.invalid.length,0);assert.ok(after.checkpoints.valid>=1);
  // Ordinary UPDATE is blocked by the append-only trigger.
  await assert.rejects(pool.query("UPDATE audit_events SET action='X' WHERE id=$1",[ids[3]]),/append-only/);
  // A privileged tamper (purge override) is detected by the chain verifier.
  const c=await pool.connect();
  try{await c.query('BEGIN');await c.query("SET LOCAL aegis.allow_evidence_purge='on'");await c.query(`UPDATE audit_events SET payload=payload||'{"tampered":true}'::jsonb WHERE id=$1`,[ids[3]]);
   const broken=await verifyAuditChainWith(c);assert.equal(broken,'ENTRY_HASH_MISMATCH');await c.query('ROLLBACK')}finally{c.release()}
 }finally{await pool.end()}
});
// Recompute inside the tampering transaction (its writes are not visible to other connections).
async function verifyAuditChainWith(c:pg.PoolClient){
 const rows=(await c.query(`SELECT chain_seq::text AS seq,id::text AS id,coalesce(assessment_id::text,'') AS aid,action,to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS ts,payload::text AS body,prev_hash,entry_hash FROM audit_events WHERE chain_seq IS NOT NULL ORDER BY chain_seq`)).rows;
 let prev=GENESIS_HASH;
 for(const r of rows){if(r.prev_hash!==prev)return 'PREV_HASH_MISMATCH';if(auditEntryHash(r.prev_hash,r.id,r.aid,r.action,r.ts,r.body)!==r.entry_hash)return 'ENTRY_HASH_MISMATCH';prev=r.entry_hash}
 return 'INTACT';
}
test('evidence saved through the store verifies after a real PostgreSQL jsonb round trip',{skip:!ciDb},async()=>{
 process.env.EVIDENCE_HMAC_KEY=KEY;
 const {db}=await import('../src/store.js');
 const pool=new pg.Pool({connectionString:process.env.DATABASE_URL,ssl:false});
 try{
  const aid=crypto.randomUUID();
  await pool.query("INSERT INTO assessments(id,target,authorized_at,status,payload) VALUES($1,'https://example.com',now(),'COMPLETED','{}')",[aid]);
  const ev={...sample(),assessmentId:aid,stdout:'unicode ✓ "quotes" \\ backslash',metadata:{target:'https://example.com',ratio:1.5,big:12345678901,flags:[true,false,null]}};
  await db.saveEvidence(ev as any);
  const row=(await pool.query('SELECT payload,hmac_sha256,hmac_key_id FROM evidence WHERE id=$1',[ev.id])).rows[0];
  assert.match(row.hmac_sha256,/^[0-9a-f]{64}$/);assert.equal(row.hmac_key_id,row.payload.metadata.evidenceSignature.keyId);
  assert.equal(verifyEvidenceSignature(row.payload,env).status,'VALID');
  const tampered=structuredClone(row.payload);tampered.stdout='clean';assert.equal(verifyEvidenceSignature(tampered,env).status,'INVALID');
 }finally{await pool.end()}
});
