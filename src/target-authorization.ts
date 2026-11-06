import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import {pool} from './db-pool.js';
import {requireOrgPermission} from './grc-organizations.js';
import {validatePublicHttpTarget} from './network-target.js';
import {pinnedHttpGet} from './pinned-egress.js';

// Target authorization: proof of control plus a second-person approval.
//
// Before this module, the only gate was a self-attested "I am authorized" checkbox.
// Now an organization must (1) prove it controls the hostname, either with a DNS TXT
// record or a file under /.well-known, and (2) have a different user with approval
// rights approve the verified target. The database also enforces that the approver is
// not the requester. Approvals expire and can be revoked.

export type VerificationMethod='DNS_TXT'|'HTTP_FILE';
export type TargetAuthorizationMode='enforce'|'attest';
export const CHALLENGE_LABEL='_aegis-challenge';
export const WELL_KNOWN_PATH='/.well-known/aegis-verification.txt';
const TOKEN_PREFIX='aegis-verification=';

export function targetAuthorizationMode(env:NodeJS.ProcessEnv=process.env):TargetAuthorizationMode{
 const v=String(env.TARGET_AUTHORIZATION_MODE||'').trim().toLowerCase();
 if(v==='enforce'||v==='attest')return v;
 return env.NODE_ENV==='production'?'enforce':'attest';
}
export function approvalTtlDays(env:NodeJS.ProcessEnv=process.env){const n=Number(env.TARGET_AUTHORIZATION_TTL_DAYS||90);return Number.isFinite(n)?Math.min(365,Math.max(1,Math.trunc(n))):90}
export const normalizeHostname=(h:string)=>String(h||'').trim().toLowerCase().replace(/\.$/,'');

export function challengeInstructions(method:VerificationMethod,hostname:string,origin:string,token:string){
 const value=TOKEN_PREFIX+token;
 return method==='DNS_TXT'
  ?{method,recordType:'TXT',recordName:CHALLENGE_LABEL+'.'+hostname,recordValue:value,note:'Publish this TXT record, wait for DNS propagation, then run verification.'}
  :{method,url:origin+WELL_KNOWN_PATH,fileContent:value,note:'Serve this exact text at the URL (HTTP 200, no redirect), then run verification.'};
}

/** Pure matcher shared by both methods: one line/record must equal the expected value exactly. */
export function challengeMatches(observed:string[],token:string){const want=TOKEN_PREFIX+token;return observed.some(x=>String(x).trim()===want)}

const COLUMNS=`id,organization_id,hostname,origin,method,status,requested_by,justification,verified_at,verification_evidence,decided_by,decided_at,decision_note,expires_at,created_at,updated_at`;

export async function requestTargetAuthorization(userId:string,orgId:string,input:{targetUrl:string;method?:string;justification?:string},validate=validatePublicHttpTarget){
 await requireOrgPermission(userId,orgId,'manageAssessment');
 const method=(String(input.method||'DNS_TXT').toUpperCase()) as VerificationMethod;
 if(method!=='DNS_TXT'&&method!=='HTTP_FILE')throw Object.assign(new Error('Verification method must be DNS_TXT or HTTP_FILE'),{statusCode:400});
 const justification=String(input.justification||'').trim();
 if(justification.length<10||justification.length>2000)throw Object.assign(new Error('Justification must be 10-2000 characters (engagement, ticket or contract reference)'),{statusCode:400});
 const t=await validate(String(input.targetUrl||''));
 const hostname=normalizeHostname(t.url.hostname),token=crypto.randomBytes(24).toString('hex'),id=crypto.randomUUID();
 const row=(await pool.query(`INSERT INTO target_authorizations(id,organization_id,hostname,origin,method,token,status,requested_by,justification)
  VALUES($1,$2,$3,$4,$5,$6,'PENDING_VERIFICATION',$7,$8) RETURNING ${COLUMNS}`,[id,orgId,hostname,t.url.origin,method,token,userId,justification])).rows[0];
 await audit('TARGET_AUTHORIZATION_REQUESTED',userId,{organizationId:orgId,targetAuthorizationId:id,hostname,method});
 return {...row,challenge:challengeInstructions(method,hostname,t.url.origin,token)};
}

export type ChallengeObservation={observed:string[];evidence:Record<string,unknown>};
export type ChallengeObserver=(method:VerificationMethod,hostname:string,origin:string)=>Promise<ChallengeObservation>;
async function observeChallenge(method:VerificationMethod,hostname:string,origin:string):Promise<ChallengeObservation>{
 if(method==='DNS_TXT'){
  const name=CHALLENGE_LABEL+'.'+hostname;
  try{const recs=await dns.resolveTxt(name);return {observed:recs.map(r=>r.join('')),evidence:{recordName:name,records:recs.map(r=>r.join('')).slice(0,20)}}}
  catch(e:any){return {observed:[],evidence:{recordName:name,error:String(e?.code||e?.message||e)}}}
 }
 // HTTP file: scope-validated, DNS-pinned, no redirects, small body cap.
 const t=await validatePublicHttpTarget(origin);
 try{const r=await pinnedHttpGet(t,5000,{'User-Agent':'AegisGRC-OwnershipVerification/1.0'},{path:WELL_KNOWN_PATH,maxBodyBytes:4096});
  const lines=r.status===200?r.body.split(/\r?\n/):[];
  return {observed:lines,evidence:{url:origin+WELL_KNOWN_PATH,status:r.status,bodySha256:crypto.createHash('sha256').update(r.body).digest('hex'),resolvedAddresses:t.addresses}};
 }catch(e:any){return {observed:[],evidence:{url:origin+WELL_KNOWN_PATH,error:String(e?.message||e)}}}
}

export async function verifyTargetAuthorization(userId:string,orgId:string,id:string,observe:ChallengeObserver=observeChallenge){
 await requireOrgPermission(userId,orgId,'manageAssessment');
 const row=(await pool.query('SELECT * FROM target_authorizations WHERE id=$1 AND organization_id=$2',[id,orgId])).rows[0];
 if(!row)throw Object.assign(new Error('Target authorization not found'),{statusCode:404});
 if(row.status!=='PENDING_VERIFICATION')throw Object.assign(new Error('Only PENDING_VERIFICATION requests can be verified (current: '+row.status+')'),{statusCode:409});
 const o=await observe(row.method,row.hostname,row.origin),ok=challengeMatches(o.observed,row.token);
 const evidence={...o.evidence,matched:ok,observedAt:new Date().toISOString()};
 if(!ok){await audit('TARGET_OWNERSHIP_VERIFICATION_FAILED',userId,{organizationId:orgId,targetAuthorizationId:id,hostname:row.hostname,evidence});return {verified:false,status:row.status,evidence,challenge:challengeInstructions(row.method,row.hostname,row.origin,row.token)}}
 const updated=(await pool.query(`UPDATE target_authorizations SET status='VERIFIED',verified_at=now(),verification_evidence=$3,updated_at=now() WHERE id=$1 AND organization_id=$2 AND status='PENDING_VERIFICATION' RETURNING ${COLUMNS}`,[id,orgId,evidence])).rows[0];
 if(!updated)throw Object.assign(new Error('Target authorization changed concurrently'),{statusCode:409});
 await audit('TARGET_OWNERSHIP_VERIFIED',userId,{organizationId:orgId,targetAuthorizationId:id,hostname:row.hostname,method:row.method,evidence});
 return {verified:true,...updated};
}

export async function decideTargetAuthorization(userId:string,orgId:string,id:string,input:{decision:string;note?:string}){
 await requireOrgPermission(userId,orgId,'approveTarget');
 const decision=String(input.decision||'').toUpperCase(),note=String(input.note||'').trim().slice(0,2000);
 if(decision!=='APPROVE'&&decision!=='REJECT')throw Object.assign(new Error('Decision must be APPROVE or REJECT'),{statusCode:400});
 const row=(await pool.query('SELECT status,requested_by,hostname FROM target_authorizations WHERE id=$1 AND organization_id=$2',[id,orgId])).rows[0];
 if(!row)throw Object.assign(new Error('Target authorization not found'),{statusCode:404});
 if(row.requested_by===userId)throw Object.assign(new Error('Separation of duties: the requester cannot approve or reject their own target'),{statusCode:403});
 if(row.status!=='VERIFIED')throw Object.assign(new Error('Only ownership-VERIFIED targets can be decided (current: '+row.status+')'),{statusCode:409});
 const status=decision==='APPROVE'?'APPROVED':'REJECTED';
 const updated=(await pool.query(`UPDATE target_authorizations SET status=$3,decided_by=$4,decided_at=now(),decision_note=$5,expires_at=CASE WHEN $3='APPROVED' THEN now()+($6::text||' days')::interval ELSE NULL END,updated_at=now()
  WHERE id=$1 AND organization_id=$2 AND status='VERIFIED' RETURNING ${COLUMNS}`,[id,orgId,status,userId,note||null,String(approvalTtlDays())])).rows[0];
 if(!updated)throw Object.assign(new Error('Target authorization changed concurrently'),{statusCode:409});
 await audit(status==='APPROVED'?'TARGET_AUTHORIZATION_APPROVED':'TARGET_AUTHORIZATION_REJECTED',userId,{organizationId:orgId,targetAuthorizationId:id,hostname:row.hostname,note,expiresAt:updated.expires_at});
 return updated;
}

export async function revokeTargetAuthorization(userId:string,orgId:string,id:string,reason:string){
 await requireOrgPermission(userId,orgId,'approveTarget');
 const r=String(reason||'').trim();if(r.length<5)throw Object.assign(new Error('Revocation reason is required'),{statusCode:400});
 const updated=(await pool.query(`UPDATE target_authorizations SET status='REVOKED',decision_note=$3,updated_at=now() WHERE id=$1 AND organization_id=$2 AND status IN ('PENDING_VERIFICATION','VERIFIED','APPROVED') RETURNING ${COLUMNS}`,[id,orgId,r.slice(0,2000)])).rows[0];
 if(!updated)throw Object.assign(new Error('Target authorization not found or already closed'),{statusCode:404});
 await audit('TARGET_AUTHORIZATION_REVOKED',userId,{organizationId:orgId,targetAuthorizationId:id,hostname:updated.hostname,reason:r});
 return updated;
}

export async function listTargetAuthorizations(userId:string,orgId:string){
 const m=await requireOrgPermission(userId,orgId,'read');
 const rows=(await pool.query(`SELECT ${COLUMNS},(status='APPROVED' AND expires_at>now()) AS active FROM target_authorizations WHERE organization_id=$1 ORDER BY created_at DESC LIMIT 200`,[orgId])).rows;
 const role=String((m as any)?.role||'');
 return {mode:targetAuthorizationMode(),canApprove:['ORG_ADMIN','GRC_MANAGER'].includes(role),userId,items:rows};
}

/** The approved, unexpired authorization covering this hostname for the organization, if any. */
export async function activeTargetAuthorization(orgId:string,hostname:string){
 return (await pool.query(`SELECT id,hostname,origin,method,requested_by,decided_by,decided_at,expires_at FROM target_authorizations
  WHERE organization_id=$1 AND hostname=$2 AND status='APPROVED' AND expires_at>now() ORDER BY decided_at DESC LIMIT 1`,[orgId,normalizeHostname(hostname)])).rows[0]||null;
}

/** Gate used when an assessment is authorized and before every active URL scan. */
export async function targetAuthorizationBasis(orgId:string|null|undefined,hostname:string){
 const mode=targetAuthorizationMode();
 if(mode==='attest')return {mode,basis:'SELF_ATTESTED' as const,authorization:null};
 if(!orgId)return {mode,basis:'NONE' as const,authorization:null};
 const a=await activeTargetAuthorization(orgId,hostname);
 return {mode,basis:a?'VERIFIED_AND_APPROVED' as const:'NONE' as const,authorization:a};
}
export async function assertTargetAuthorized(orgId:string|null|undefined,hostname:string){
 const b=await targetAuthorizationBasis(orgId,hostname);
 if(b.mode==='enforce'&&!b.authorization)throw Object.assign(new Error('No approved, unexpired target authorization covers '+normalizeHostname(hostname)+'. Verify ownership and obtain a second-person approval first.'),{statusCode:403,code:'TARGET_AUTHORIZATION_REQUIRED'});
 return b;
}

async function audit(action:string,actor:string,metadata:Record<string,unknown>){
 const id=crypto.randomUUID(),createdAt=new Date().toISOString();
 await pool.query('INSERT INTO audit_events(id,assessment_id,action,created_at,payload) VALUES($1,NULL,$2,$3,$4)',[id,action,createdAt,{id,action,actor,createdAt,metadata}]);
}
