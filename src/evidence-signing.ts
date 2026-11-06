import crypto from 'node:crypto';

// Keyed integrity for scanner/import evidence.
//
// SHA-256 alone proves that bytes match a digest, but anyone who can write the
// database can rewrite both. An HMAC over the canonical evidence record, keyed with
// EVIDENCE_HMAC_KEY (held by the application, never stored in the database), means a
// database-only attacker cannot forge or alter evidence without detection.

export const EVIDENCE_SIGNATURE_VERSION='aegis-evidence-v1';
const PLACEHOLDER=/change-me|REPLACE_WITH/i;

export type EvidenceSignature={version:string;alg:'HMAC-SHA256';keyId:string;mac:string;signedAt:string};
export type EvidenceSignatureStatus='VALID'|'INVALID'|'UNSIGNED'|'KEY_UNAVAILABLE'|'KEY_MISMATCH';

/** Returns the signing key, or null in non-production when none is set. Fails closed in production. */
export function evidenceSigningKey(env:NodeJS.ProcessEnv=process.env):string|null{
 const k=String(env.EVIDENCE_HMAC_KEY||'');
 if(env.NODE_ENV==='production'){
  if(k.length<32||PLACEHOLDER.test(k))throw new Error('EVIDENCE_HMAC_KEY must be at least 32 non-placeholder characters in production; evidence cannot be signed');
  return k;
 }
 return k?k:null;
}

export function signingKeyId(key:string){return crypto.createHash('sha256').update('aegis-key-id|'+key).digest('hex').slice(0,16)}

/** Deterministic JSON: sorted object keys, undefined dropped (matches JSON/jsonb round-trip). */
export function canonicalJson(v:unknown):string{
 if(v===null||typeof v!=='object')return JSON.stringify(v)??'null';
 if(Array.isArray(v))return '['+v.map(x=>x===undefined?'null':canonicalJson(x)).join(',')+']';
 const o=v as Record<string,unknown>;
 return '{'+Object.keys(o).filter(k=>o[k]!==undefined).sort().map(k=>JSON.stringify(k)+':'+canonicalJson(o[k])).join(',')+'}';
}

type SignableEvidence={id:string;assessmentId:string;source:string;sha256:string;createdAt:string;exitCode?:number|null;stdout?:string;stderr?:string;metadata?:Record<string,unknown>};

/** The exact bytes covered by the MAC. The signature itself is excluded from metadata. */
export function evidenceSigningInput(x:SignableEvidence){
 const {evidenceSignature:_omit,...metadata}=(x.metadata||{}) as Record<string,unknown>;
 return EVIDENCE_SIGNATURE_VERSION+'\n'+canonicalJson({id:x.id,assessmentId:x.assessmentId,source:x.source,sha256:x.sha256,createdAt:x.createdAt,exitCode:x.exitCode===undefined?null:x.exitCode,stdout:x.stdout||'',stderr:x.stderr||'',metadata});
}

export function computeEvidenceMac(key:string,x:SignableEvidence){return crypto.createHmac('sha256',key).update(evidenceSigningInput(x)).digest('hex')}

/** Signs evidence; returns the record with metadata.evidenceSignature set (or unchanged when no dev key). */
export function signEvidence<T extends SignableEvidence>(x:T,env:NodeJS.ProcessEnv=process.env):T&{metadata:Record<string,unknown>}{
 const key=evidenceSigningKey(env);
 const metadata={...(x.metadata||{})};delete (metadata as any).evidenceSignature;
 if(!key)return {...x,metadata:{...metadata,evidenceSignatureStatus:'UNSIGNED_NO_KEY'}};
 const base={...x,metadata};
 const sig:EvidenceSignature={version:EVIDENCE_SIGNATURE_VERSION,alg:'HMAC-SHA256',keyId:signingKeyId(key),mac:computeEvidenceMac(key,base),signedAt:new Date().toISOString()};
 return {...base,metadata:{...metadata,evidenceSignature:sig}};
}

export function verifyEvidenceSignature(x:SignableEvidence,env:NodeJS.ProcessEnv=process.env):{status:EvidenceSignatureStatus;keyId?:string}{
 const sig=(x.metadata as any)?.evidenceSignature as EvidenceSignature|undefined;
 if(!sig||sig.alg!=='HMAC-SHA256'||typeof sig.mac!=='string')return {status:'UNSIGNED'};
 let key:string|null=null;try{key=evidenceSigningKey(env)}catch{key=null}
 if(!key)return {status:'KEY_UNAVAILABLE',keyId:sig.keyId};
 if(signingKeyId(key)!==sig.keyId)return {status:'KEY_MISMATCH',keyId:sig.keyId};
 const expected=Buffer.from(computeEvidenceMac(key,x),'hex'),actual=Buffer.from(String(sig.mac),'hex');
 return {status:expected.length===actual.length&&crypto.timingSafeEqual(expected,actual)?'VALID':'INVALID',keyId:sig.keyId};
}

/** HMAC for an audit-chain checkpoint (chain head) using the same application-held key. */
export function checkpointMac(key:string,chainSeq:number|string,entryHash:string){
 return crypto.createHmac('sha256',key).update('aegis-audit-checkpoint-v1|'+String(chainSeq)+'|'+entryHash).digest('hex');
}
