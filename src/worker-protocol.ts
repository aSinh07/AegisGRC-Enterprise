import crypto from 'node:crypto';
import {canonicalJson} from './evidence-signing.js';

// Authenticated scanner-worker protocol.
//
// The worker only makes OUTBOUND requests (pull model). Each request is signed with the
// worker's own secret: HMAC-SHA256 over method, path, timestamp, nonce and body digest.
// The server rejects unknown workers, a clock skew over 5 minutes, a body that does not
// match its digest, a bad signature, or a reused nonce (replay). Each scan result also
// carries a separate output signature that is kept with the evidence as a worker attestation.

export const WORKER_SIG_VERSION='AEGIS-WORKER-V1';
export const MAX_SKEW_MS=5*60*1000;

export function parseWorkerKeys(raw:string=process.env.AEGIS_WORKER_KEYS||''){
 const keys=new Map<string,string>();
 for(const part of raw.split(',').map(x=>x.trim()).filter(Boolean)){
  const i=part.indexOf(':');if(i<1)continue;const id=part.slice(0,i).trim(),secret=part.slice(i+1).trim();
  if(!/^[A-Za-z0-9_.-]{1,64}$/.test(id))throw new Error('Invalid scanner worker id in AEGIS_WORKER_KEYS: '+id);
  if(secret.length<32)throw new Error('Scanner worker secret for '+id+' must be at least 32 characters');
  keys.set(id,secret);
 }
 return keys;
}

const sha256=(b:Buffer|string)=>crypto.createHash('sha256').update(b).digest('hex');
export function requestSigningInput(method:string,path:string,timestamp:string,nonce:string,bodySha:string){
 return [WORKER_SIG_VERSION,method.toUpperCase(),path,timestamp,nonce,bodySha].join('\n');
}
export function signWorkerRequest(workerId:string,secret:string,method:string,path:string,body:Buffer|string,now=Date.now()){
 const timestamp=String(now),nonce=crypto.randomBytes(16).toString('hex'),bodySha=sha256(body);
 const signature=crypto.createHmac('sha256',secret).update(requestSigningInput(method,path,timestamp,nonce,bodySha)).digest('hex');
 return {'X-Aegis-Worker-Id':workerId,'X-Aegis-Timestamp':timestamp,'X-Aegis-Nonce':nonce,'X-Aegis-Body-Sha256':bodySha,'X-Aegis-Signature':signature};
}

export type WorkerAuthResult={ok:true;workerId:string}|{ok:false;reason:string};
/** Verifies a signed request. `rememberNonce` must atomically record the nonce and return false if it was already seen. */
export async function verifyWorkerRequest(h:Record<string,unknown>,method:string,path:string,body:Buffer,keys:Map<string,string>,rememberNonce:(workerId:string,nonce:string)=>Promise<boolean>,now=Date.now()):Promise<WorkerAuthResult>{
 const g=(k:string)=>String(h[k.toLowerCase()]??'');
 const workerId=g('X-Aegis-Worker-Id'),ts=g('X-Aegis-Timestamp'),nonce=g('X-Aegis-Nonce'),bodySha=g('X-Aegis-Body-Sha256'),sig=g('X-Aegis-Signature');
 const secret=keys.get(workerId);if(!secret)return {ok:false,reason:'UNKNOWN_WORKER'};
 if(!/^\d{10,16}$/.test(ts)||Math.abs(now-Number(ts))>MAX_SKEW_MS)return {ok:false,reason:'STALE_OR_FUTURE_TIMESTAMP'};
 if(!/^[0-9a-f]{32}$/.test(nonce))return {ok:false,reason:'BAD_NONCE'};
 if(sha256(body)!==bodySha)return {ok:false,reason:'BODY_DIGEST_MISMATCH'};
 const expected=Buffer.from(crypto.createHmac('sha256',secret).update(requestSigningInput(method,path,ts,nonce,bodySha)).digest('hex'),'hex'),actual=Buffer.from(sig,'hex');
 if(expected.length!==actual.length||!crypto.timingSafeEqual(expected,actual))return {ok:false,reason:'BAD_SIGNATURE'};
 if(!await rememberNonce(workerId,nonce))return {ok:false,reason:'REPLAYED_NONCE'};
 return {ok:true,workerId};
}

/** Worker-side signature over the raw scan output, stored with the evidence as an attestation. */
export function outputSigningInput(taskId:string,raw:unknown){return 'AEGIS-WORKER-RESULT-V1|'+taskId+'|'+sha256(canonicalJson(raw))}
export function signScanOutput(secret:string,taskId:string,raw:unknown){return crypto.createHmac('sha256',secret).update(outputSigningInput(taskId,raw)).digest('hex')}
export function verifyScanOutput(secret:string,taskId:string,raw:unknown,signature:string){
 const e=Buffer.from(signScanOutput(secret,taskId,raw),'hex'),a=Buffer.from(String(signature||''),'hex');
 return e.length===a.length&&crypto.timingSafeEqual(e,a);
}
export const rawOutputDigest=(raw:unknown)=>sha256(canonicalJson(raw));
