import crypto from 'node:crypto';
import {pool} from './db-pool.js';
import {evidenceSigningKey,signingKeyId,checkpointMac} from './evidence-signing.js';

// Verifies the audit_events hash chain written by the aegis_chain_audit_event trigger.
// Hashes are recomputed here in Node from the raw stored rows rather than by calling the
// database hash function, so a replaced SQL function cannot vouch for itself.

export const GENESIS_HASH='0'.repeat(64);
export function auditEntryHash(prev:string,id:string,assessmentId:string,action:string,createdUtc:string,body:string){
 return crypto.createHash('sha256').update('aegis-audit-v1|'+prev+'|'+id+'|'+assessmentId+'|'+action+'|'+createdUtc+'|'+body,'utf8').digest('hex');
}

export type AuditChainBreak={chainSeq:string;id:string;reason:'ENTRY_HASH_MISMATCH'|'PREV_HASH_MISMATCH'|'UNCHAINED_ROW'};
export type AuditChainReport={status:'INTACT'|'BROKEN'|'EMPTY';checked:number;head:{chainSeq:string;entryHash:string}|null;breaks:AuditChainBreak[];
 checkpoints:{checked:number;valid:number;invalid:{chainSeq:string;reason:string}[];keyStatus:'AVAILABLE'|'UNAVAILABLE'};verifiedAt:string};

const ROW_SQL=`SELECT chain_seq::text AS seq,id::text AS id,coalesce(assessment_id::text,'') AS aid,action,
 to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS ts,payload::text AS body,prev_hash,entry_hash
 FROM audit_events WHERE chain_seq IS NOT NULL AND chain_seq > $1 ORDER BY chain_seq ASC LIMIT $2`;

export async function verifyAuditChain(opts:{batch?:number;maxBreaks?:number}={}):Promise<AuditChainReport>{
 const batch=Math.max(100,Math.min(20000,opts.batch||5000)),maxBreaks=opts.maxBreaks||25;
 const breaks:AuditChainBreak[]=[];let checked=0,prev=GENESIS_HASH,cursor='0',head:AuditChainReport['head']=null;
 const unchained=(await pool.query('SELECT id::text AS id FROM audit_events WHERE chain_seq IS NULL OR entry_hash IS NULL LIMIT $1',[maxBreaks])).rows;
 for(const r of unchained)breaks.push({chainSeq:'',id:r.id,reason:'UNCHAINED_ROW'});
 for(;;){
  const rows=(await pool.query(ROW_SQL,[cursor,batch])).rows;if(!rows.length)break;
  for(const r of rows){
   checked++;
   if(r.prev_hash!==prev&&breaks.length<maxBreaks)breaks.push({chainSeq:r.seq,id:r.id,reason:'PREV_HASH_MISMATCH'});
   const recomputed=auditEntryHash(String(r.prev_hash),r.id,r.aid,r.action,r.ts,r.body);
   if(recomputed!==r.entry_hash&&breaks.length<maxBreaks)breaks.push({chainSeq:r.seq,id:r.id,reason:'ENTRY_HASH_MISMATCH'});
   prev=String(r.entry_hash);cursor=r.seq;head={chainSeq:r.seq,entryHash:prev};
  }
 }
 let key:string|null=null;try{key=evidenceSigningKey()}catch{key=null}
 const cps=(await pool.query('SELECT c.chain_seq::text AS seq,c.entry_hash,c.hmac_sha256,c.key_id,a.entry_hash AS actual FROM audit_chain_checkpoints c LEFT JOIN audit_events a ON a.chain_seq=c.chain_seq ORDER BY c.chain_seq DESC LIMIT 500')).rows;
 const invalid:{chainSeq:string;reason:string}[]=[];let valid=0;
 for(const c of cps){
  if(c.actual!==c.entry_hash){invalid.push({chainSeq:c.seq,reason:c.actual?'CHAIN_DIVERGES_FROM_CHECKPOINT':'CHECKPOINTED_ROW_MISSING'});continue}
  if(!key)continue;
  if(c.key_id!==signingKeyId(key)){invalid.push({chainSeq:c.seq,reason:'CHECKPOINT_KEY_MISMATCH'});continue}
  const exp=Buffer.from(checkpointMac(key,c.seq,c.entry_hash),'hex'),act=Buffer.from(String(c.hmac_sha256),'hex');
  if(exp.length===act.length&&crypto.timingSafeEqual(exp,act))valid++;else invalid.push({chainSeq:c.seq,reason:'CHECKPOINT_MAC_INVALID'});
 }
 return {status:checked===0&&!breaks.length?'EMPTY':breaks.length||invalid.length?'BROKEN':'INTACT',checked,head,breaks,
  checkpoints:{checked:cps.length,valid,invalid,keyStatus:key?'AVAILABLE':'UNAVAILABLE'},verifiedAt:new Date().toISOString()};
}

/** Signs the current chain head with the application key. No-op when the head is already checkpointed. */
export async function checkpointAuditChain(){
 const key=evidenceSigningKey();if(!key)return {created:false,reason:'NO_SIGNING_KEY'};
 const head=(await pool.query('SELECT chain_seq::text AS seq,entry_hash FROM audit_events WHERE chain_seq IS NOT NULL ORDER BY chain_seq DESC LIMIT 1')).rows[0];
 if(!head)return {created:false,reason:'EMPTY_CHAIN'};
 const last=(await pool.query('SELECT chain_seq::text AS seq FROM audit_chain_checkpoints ORDER BY chain_seq DESC LIMIT 1')).rows[0];
 if(last?.seq===head.seq)return {created:false,reason:'HEAD_ALREADY_CHECKPOINTED',chainSeq:head.seq};
 const id=crypto.randomUUID();
 await pool.query('INSERT INTO audit_chain_checkpoints(id,chain_seq,entry_hash,hmac_sha256,key_id) VALUES($1,$2,$3,$4,$5)',[id,head.seq,head.entry_hash,checkpointMac(key,head.seq,head.entry_hash),signingKeyId(key)]);
 return {created:true,id,chainSeq:head.seq,entryHash:head.entry_hash};
}

export function startAuditCheckpointer(intervalMs=Number(process.env.AUDIT_CHECKPOINT_INTERVAL_MS||600000)){
 const ms=Math.max(60000,Number.isFinite(intervalMs)?intervalMs:600000);
 const tick=()=>checkpointAuditChain().catch(e=>console.error('[AEGIS AUDIT] checkpoint failed',String(e?.message||e)));
 const t=setInterval(tick,ms);t.unref?.();setTimeout(tick,5000).unref?.();return t;
}
