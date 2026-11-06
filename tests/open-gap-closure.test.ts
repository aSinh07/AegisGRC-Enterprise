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

// ── Gap: scanners re-resolve DNS after scope validation (DNS rebinding) ─────
import http from 'node:http';
import net from 'node:net';
import {startProxyPinnedTo,pinnedAddress,pinnedLookup} from '../src/pinned-egress.js';
import {scannerArgs} from '../src/scanner-args.js';

test('pinned egress proxy connects only to the validated address, never re-resolving the hostname',async()=>{
 const seen:string[]=[];
 const origin=http.createServer((req,res)=>{seen.push(String(req.headers.host));res.end('pinned-ok')});
 await new Promise<void>(r=>origin.listen(0,'127.0.0.1',()=>r()));
 const port=(origin.address() as net.AddressInfo).port;
 // "rebind.example" does not resolve at all: success proves the proxy used the pinned IP, not DNS.
 const proxy=await startProxyPinnedTo('127.0.0.1','rebind.example',[port]);
 const viaProxy=(target:string)=>new Promise<{status:number;body:string}>((resolve,reject)=>{
  const req=http.request({host:'127.0.0.1',port:proxy.port,path:target,method:'GET'},res=>{let b='';res.on('data',d=>b+=d);res.on('end',()=>resolve({status:res.statusCode||0,body:b}))});req.on('error',reject);req.end()});
 try{
  const ok=await viaProxy(`http://rebind.example:${port}/`);
  assert.equal(ok.status,200);assert.equal(ok.body,'pinned-ok');assert.equal(seen[0],`rebind.example:${port}`);
  assert.equal((await viaProxy(`http://169.254.169.254:${port}/latest/meta-data/`)).status,403,'other hosts are refused');
  assert.equal((await viaProxy('http://rebind.example:6379/')).status,403,'other ports are refused');
  const connect=await new Promise<string>(resolve=>{const s=net.connect(proxy.port,'127.0.0.1',()=>s.write('CONNECT internal.example:443 HTTP/1.1\r\nHost: internal.example:443\r\n\r\n'));s.once('data',d=>{resolve(String(d));s.destroy()})});
  assert.match(connect,/403/);
  assert.equal(proxy.record.allowed,1);assert.equal(proxy.record.denied.length,3);
 }finally{await proxy.close();origin.close()}
});
test('pinned address selection refuses private and reserved addresses',()=>{
 assert.throws(()=>pinnedAddress(['127.0.0.1','10.0.0.5','169.254.169.254']),/No validated public address/);
 assert.equal(pinnedAddress(['2606:4700::1','93.184.216.34']),'93.184.216.34');
 const lookup=pinnedLookup({url:new URL('https://example.com'),addresses:['93.184.216.34']});
 lookup('example.com',{all:true},(err:any,addrs:any)=>{assert.equal(err,null);assert.deepEqual(addrs,[{address:'93.184.216.34',family:4}])});
 lookup('evil.example',{},(err:any)=>assert.match(String(err?.message),/outside the authorized target/));
});
test('every URL scanner profile is pinned: nmap by IP, HTTP scanners through the loopback proxy',()=>{
 const u=new URL('https://example.com/');
 const nmap=scannerArgs('nmap',u,{pinnedAddress:'93.184.216.34'});assert.equal(nmap.at(-1),'93.184.216.34');assert.ok(!nmap.includes('example.com'));
 assert.ok(scannerArgs('nmap',u,{pinnedAddress:'2606:4700::1'}).includes('-6'));
 assert.ok(scannerArgs('wapiti',u,{proxyUrl:'http://127.0.0.1:4000'}).includes('--proxy'));
 assert.ok(scannerArgs('sqlmap',u,{proxyUrl:'http://127.0.0.1:4000'}).includes('--proxy=http://127.0.0.1:4000'));
 const nuclei=scannerArgs('nuclei',u,{proxyUrl:'http://127.0.0.1:4000'});assert.ok(nuclei.includes('-proxy'));assert.deepEqual(nuclei.slice(nuclei.indexOf('-pt'),nuclei.indexOf('-pt')+2),['-pt','http']);
 for(const tool of ['wapiti','nuclei','sqlmap'] as const)assert.throws(()=>scannerArgs(tool,u,{}),/pinned loopback egress proxy/);
 assert.throws(()=>scannerArgs('nmap',u,{}),/pinned IP/);
});
test('server scanner paths use pinned egress and ZAP fails closed without a pinned upstream',async()=>{
 const server=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');
 assert.doesNotMatch(server,/'--open','-oX','-',(t|safeTarget)\.url\.hostname/);
 assert.doesNotMatch(server,/zapScan\(/);assert.equal((server.match(/zapScanPinned\(/g)||[]).length,2);
 assert.doesNotMatch(server,/await fetch\(t\.url\.origin/);
 const {zapScanPinned}=await import('../src/zap.js');const prior=process.env.ZAP_EGRESS_PROXY_HOST;delete process.env.ZAP_EGRESS_PROXY_HOST;
 try{await assert.rejects(zapScanPinned({url:new URL('https://example.com'),addresses:['93.184.216.34']}),/fail closed/)}finally{if(prior!==undefined)process.env.ZAP_EGRESS_PROXY_HOST=prior}
 const jobs=await readFile(new URL('../src/scanner-jobs.ts',import.meta.url),'utf8');assert.match(jobs,/scanTls\(fresh\.url\.origin,pinnedAddress\(fresh\.addresses\)\)/);
});

// ── Gap: Nuclei templates are not pinned in the image ───────────────────────
import {nucleiTemplatesPin} from '../src/scanner-args.js';
import {mkdtemp,writeFile} from 'node:fs/promises';
import os from 'node:os';
test('nuclei templates are pinned by release and commit, read-only, and never auto-updated',async()=>{
 const docker=await readFile(new URL('../Dockerfile',import.meta.url),'utf8');
 assert.match(docker,/NUCLEI_TEMPLATES_VERSION=v\d+\.\d+\.\d+/);
 assert.match(docker,/NUCLEI_TEMPLATES_COMMIT=[0-9a-f]{40}/);
 assert.match(docker,/test "\$\(git -C \/opt\/nuclei-templates rev-parse HEAD\)" = "\$\{NUCLEI_TEMPLATES_COMMIT\}"/);
 assert.match(docker,/chmod -R a-w \/opt\/nuclei-templates/);
 const args=scannerArgs('nuclei',new URL('https://example.com'),{proxyUrl:'http://127.0.0.1:1'});
 assert.ok(args.includes('-duc'));assert.equal(args[args.indexOf('-t')+1],'/opt/nuclei-templates');assert.ok(args.includes('-ni'));
 const dir=await mkdtemp(os.tmpdir()+'/nt-');assert.equal(nucleiTemplatesPin(dir).version,'UNPINNED');
 await writeFile(dir+'/.aegis-pin','v10.5.1 79fb682760ab3d5b0e22afbb44709353cbebf023\n');
 assert.deepEqual(nucleiTemplatesPin(dir),{version:'v10.5.1',commit:'79fb682760ab3d5b0e22afbb44709353cbebf023'});
});

// ── Gap: no Security Analyst or Developer roles ─────────────────────────────
import {roleAllows} from '../src/grc-organizations.js';
test('SECURITY_ANALYST scans and triages; DEVELOPER can only read and retest',()=>{
 assert.equal(roleAllows('SECURITY_ANALYST','manageAssessment'),true);
 assert.equal(roleAllows('SECURITY_ANALYST','findingReview'),true);
 assert.equal(roleAllows('SECURITY_ANALYST','retest'),true);
 assert.equal(roleAllows('SECURITY_ANALYST','manageOrg'),false);
 assert.equal(roleAllows('SECURITY_ANALYST','manageControl'),false);
 assert.equal(roleAllows('SECURITY_ANALYST','approveTarget'),false);
 assert.equal(roleAllows('DEVELOPER','retest'),true);
 assert.equal(roleAllows('DEVELOPER','read'),true);
 for(const p of ['manageAssessment','findingReview','manageRisk','manageControl','manageScope','manageOrg','approveTarget','review'] as const)assert.equal(roleAllows('DEVELOPER',p),false,p);
 assert.equal(roleAllows('GRC_ANALYST','retest'),true);assert.equal(roleAllows('VIEWER','retest'),false);
});
test('every finding retest endpoint requires the retest permission, not assessment management',async()=>{
 const server=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');
 const handlers=server.split(/\napp\./).filter(h=>/^post\('[^']*retest'/.test(h)&&!h.startsWith("post('/api/grc/organizations/:orgId/capa"));
 assert.equal(handlers.length,7);
 for(const h of handlers){assert.match(h,/requireOrgPermission\(u\.userId,access\.organization_id,'retest'\)/,h.slice(0,90));assert.doesNotMatch(h.split('\napp.')[0].slice(0,1500),/'manageAssessment'/,h.slice(0,90))}
 const orgs=await readFile(new URL('../src/grc-organizations.ts',import.meta.url),'utf8');
 assert.equal((orgs.match(/'SECURITY_ANALYST','DEVELOPER','CONTROL_OWNER'/g)||[]).length,3,'role type, list and DB CHECK constraints include the new roles');
});
test('DEVELOPER membership is accepted by the database and limited by permission checks',{skip:!ciDb},async()=>{
 const {initOrganizations,createOrganization,addMember,requireOrgPermission}=await import('../src/grc-organizations.js');
 const pool=new pg.Pool({connectionString:process.env.DATABASE_URL,ssl:false});
 try{
  await initOrganizations();
  const mk=async()=>{const id=crypto.randomUUID();await pool.query("INSERT INTO app_users(id,email,password_hash,password_salt,totp_secret) VALUES($1,$2,'x','x','x')",[id,id+'@t.example']);return id};
  const admin=await mk(),dev=await mk(),sec=await mk();
  const org:any=await createOrganization(admin,{name:'Role test '+admin.slice(0,8)});const orgId=org.id||org.organization?.id;
  await addMember(admin,orgId,dev,'DEVELOPER');await addMember(admin,orgId,sec,'SECURITY_ANALYST');
  await requireOrgPermission(dev,orgId,'retest');
  await assert.rejects(requireOrgPermission(dev,orgId,'manageAssessment'),/Insufficient organization role/);
  await assert.rejects(requireOrgPermission(dev,orgId,'findingReview'),/Insufficient organization role/);
  await requireOrgPermission(sec,orgId,'manageAssessment');await requireOrgPermission(sec,orgId,'findingReview');
  await assert.rejects(requireOrgPermission(sec,orgId,'manageOrg'),/Insufficient organization role/);
 }finally{await pool.end()}
});

// ── Gap: target authorization is a self-attested checkbox ───────────────────
import {challengeMatches,challengeInstructions,targetAuthorizationMode} from '../src/target-authorization.js';
test('ownership challenge matching is exact and instructions name the record or file',()=>{
 assert.equal(challengeMatches(['aegis-verification=abc'],'abc'),true);
 assert.equal(challengeMatches(['  aegis-verification=abc  '],'abc'),true);
 assert.equal(challengeMatches(['aegis-verification=abcd','x aegis-verification=abc'],'abc'),false);
 assert.equal(challengeMatches([],'abc'),false);
 assert.deepEqual(challengeInstructions('DNS_TXT','app.example.com','https://app.example.com','t1'),{method:'DNS_TXT',recordType:'TXT',recordName:'_aegis-challenge.app.example.com',recordValue:'aegis-verification=t1',note:'Publish this TXT record, wait for DNS propagation, then run verification.'});
 assert.equal((challengeInstructions('HTTP_FILE','app.example.com','https://app.example.com','t1') as any).url,'https://app.example.com/.well-known/aegis-verification.txt');
 assert.equal(targetAuthorizationMode({NODE_ENV:'production'} as any),'enforce');
 assert.equal(targetAuthorizationMode({NODE_ENV:'production',TARGET_AUTHORIZATION_MODE:'attest'} as any),'attest');
 assert.equal(targetAuthorizationMode({NODE_ENV:'test'} as any),'attest');
});
test('target authorization needs verified ownership and a different approver, and gates scans',{skip:!ciDb},async()=>{
 const ta=await import('../src/target-authorization.js');
 const {createOrganization,addMember}=await import('../src/grc-organizations.js');
 const pool=new pg.Pool({connectionString:process.env.DATABASE_URL,ssl:false});
 const prevMode=process.env.TARGET_AUTHORIZATION_MODE;process.env.TARGET_AUTHORIZATION_MODE='enforce';
 try{
  const mk=async()=>{const id=crypto.randomUUID();await pool.query("INSERT INTO app_users(id,email,password_hash,password_salt,totp_secret) VALUES($1,$2,'x','x','x')",[id,id+'@t.example']);return id};
  const admin=await mk(),manager=await mk(),analyst=await mk();
  const org:any=await createOrganization(admin,{name:'TA test '+admin.slice(0,8)});const orgId=org.id||org.organization?.id;
  await addMember(admin,orgId,manager,'GRC_MANAGER');await addMember(admin,orgId,analyst,'SECURITY_ANALYST');
  const host='scan-'+admin.slice(0,8)+'.example.com';
  const fakeValidate=async(raw:string)=>({url:new URL(raw),addresses:['93.184.216.34']});
  await assert.rejects(ta.assertTargetAuthorized(orgId,host),/No approved, unexpired target authorization/);
  await assert.rejects(ta.requestTargetAuthorization(analyst,orgId,{targetUrl:'https://'+host,justification:'short'},fakeValidate),/Justification/);
  const req=await ta.requestTargetAuthorization(analyst,orgId,{targetUrl:'https://'+host+'/login',method:'DNS_TXT',justification:'Pen test SOW-2026-114 signed by CISO'},fakeValidate);
  assert.equal(req.status,'PENDING_VERIFICATION');assert.equal(req.challenge.recordName,'_aegis-challenge.'+host);assert.ok(!('token' in req),'token is only exposed through the challenge');
  await assert.rejects(ta.decideTargetAuthorization(manager,orgId,req.id,{decision:'APPROVE'}),/Only ownership-VERIFIED/);
  const miss=await ta.verifyTargetAuthorization(analyst,orgId,req.id,async()=>({observed:['aegis-verification=wrong'],evidence:{}}));
  assert.equal(miss.verified,false);
  const value=req.challenge.recordValue as string;
  const hit=await ta.verifyTargetAuthorization(analyst,orgId,req.id,async()=>({observed:[value],evidence:{records:[value]}}));
  assert.equal(hit.verified,true);
  await assert.rejects(ta.decideTargetAuthorization(analyst,orgId,req.id,{decision:'APPROVE'}),/Insufficient organization role/,'analyst cannot approve');
  // Requester with approval rights still cannot self-approve (app check + DB CHECK).
  const self=await ta.requestTargetAuthorization(manager,orgId,{targetUrl:'https://self-'+host,justification:'Self-approval attempt for test'},fakeValidate);
  await ta.verifyTargetAuthorization(manager,orgId,self.id,async()=>({observed:[self.challenge.recordValue as string],evidence:{}}));
  await assert.rejects(ta.decideTargetAuthorization(manager,orgId,self.id,{decision:'APPROVE'}),/Separation of duties/);
  await assert.rejects(pool.query("UPDATE target_authorizations SET status='APPROVED',decided_by=requested_by,decided_at=now(),expires_at=now()+interval '1 day' WHERE id=$1",[self.id]),/separation_of_duties/);
  const ok=await ta.decideTargetAuthorization(manager,orgId,req.id,{decision:'APPROVE',note:'SOW verified'});
  assert.equal(ok.status,'APPROVED');assert.ok(new Date(ok.expires_at).getTime()>Date.now()+80*86400e3);
  const basis=await ta.assertTargetAuthorized(orgId,host.toUpperCase());assert.equal(basis.basis,'VERIFIED_AND_APPROVED');
  await assert.rejects(ta.assertTargetAuthorized(orgId,'other.example.com'),/No approved/);
  await ta.revokeTargetAuthorization(admin,orgId,req.id,'Engagement ended');
  await assert.rejects(ta.assertTargetAuthorized(orgId,host),/No approved/,'revocation stops scans');
  const actions=(await pool.query("SELECT action FROM audit_events WHERE payload->'metadata'->>'targetAuthorizationId'=$1 ORDER BY chain_seq",[req.id])).rows.map((r:any)=>r.action);
  assert.deepEqual(actions,['TARGET_AUTHORIZATION_REQUESTED','TARGET_OWNERSHIP_VERIFICATION_FAILED','TARGET_OWNERSHIP_VERIFIED','TARGET_AUTHORIZATION_APPROVED','TARGET_AUTHORIZATION_REVOKED']);
 }finally{if(prevMode===undefined)delete process.env.TARGET_AUTHORIZATION_MODE;else process.env.TARGET_AUTHORIZATION_MODE=prevMode;await pool.end()}
});
test('assessment authorization and every active URL scan consult the target authorization gate',async()=>{
 const server=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');
 assert.match(server,/code:'TARGET_AUTHORIZATION_REQUIRED'/);
 assert.match(server,/async function executeRealTool[^\n]*\n[^\n]*\n await assertTargetAuthorized\(await assessmentOrganizationId\(assessmentId\),t\.url\.hostname\);/);
 const ui=await readFile(new URL('../public/target-authorization.js',import.meta.url),'utf8');
 assert.doesNotMatch(ui,/innerHTML/);assert.match(ui,/globalThis\.openTargetAuthorizations=/);
});

// ── Gap: HTTP-posture and sqlmap findings have no deterministic retest ──────
import {findingFingerprint} from '../src/finding-correlation.js';
import {sqlmapTextFindings} from '../src/infrastructure-parsers.js';
test('sqlmap and HTTP-posture findings have stable fingerprints across independent runs',()=>{
 const raw='Parameter: id (GET)\n    Type: boolean-based blind\n    Title: AND boolean-based blind\n    Payload: id=1 AND 1=1\n';
 const a=sqlmapTextFindings('a1','https://example.com','e1',raw)[0],b=sqlmapTextFindings('a1','https://example.com','e2',raw)[0];
 assert.ok(a&&b);assert.notEqual(a.id,b.id);assert.equal(findingFingerprint(a),findingFingerprint(b));
 const other=sqlmapTextFindings('a1','https://example.com','e3',raw.replace('id (GET)','q (GET)'))[0];assert.notEqual(findingFingerprint(a),findingFingerprint(other));
 const posture=(desc:string)=>({id:crypto.randomUUID(),assessmentId:'a',source:'http' as const,title:'Server technology disclosed',description:desc,severity:'LOW' as const,asset:'https://example.com',evidenceHash:'x',createdAt:'',mappings:{}});
 assert.equal(findingFingerprint(posture('Server: nginx/1.1')),findingFingerprint(posture('Server: nginx/1.2')),'description changes do not break the fingerprint');
});
test('targeted retest supports http and sqlmap, and a failed posture probe can never close a finding',async()=>{
 const server=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');
 assert.match(server,/const NATIVE_RETEST_SOURCES=\['nmap','wapiti','zap','nuclei','sqlmap','http'\]/);
 assert.match(server,/original\.source==='http'\?await retestHttpPosture\(/);
 assert.match(server,/const exitCode=q\.error\|\|!q\.status\?1:0;/);
 assert.match(server,/const findings=exitCode===0\?q\.findings:\[\]/);
 const {retestEvidenceIsComplete}=await import('../src/finding-review.js');
 assert.equal(retestEvidenceIsComplete({exitCode:1,metadata:{mode:'live-http-posture'}}),false);
 const ui=await readFile(new URL('../public/dashboard.js',import.meta.url),'utf8');
 assert.match(ui,/\['nmap','wapiti','zap','nuclei','sqlmap','http'\]\.includes/);
});

// ── Gap: Finding → Risk → CAPA promotion is manual ──────────────────────────
import {atOrAbove,derivedRiskRating} from '../src/finding-promotion.js';
test('promotion threshold and severity-derived risk ratings',()=>{
 assert.equal(atOrAbove('CRITICAL','HIGH'),true);assert.equal(atOrAbove('MEDIUM','HIGH'),false);assert.equal(atOrAbove('HIGH','HIGH'),true);
 assert.deepEqual(derivedRiskRating('CRITICAL'),{likelihood:4,impact:5});
 assert.deepEqual(derivedRiskRating('HIGH'),{likelihood:4,impact:4});
});
test('confirming a finding auto-creates one issue, risk and CAPA under the policy owner, idempotently',{skip:!ciDb},async()=>{
 const {initGrcCore}=await import('../src/grc-core.js');
 const {initOrganizations,createOrganization,addMember}=await import('../src/grc-organizations.js');
 const {initIssueRiskCapa}=await import('../src/grc-remediation.js');
 const {initFindingReview,reviewFinding}=await import('../src/finding-review.js');
 const {initFindingRisk}=await import('../src/finding-risk.js');
 const fp=await import('../src/finding-promotion.js');
 const pool=new pg.Pool({connectionString:process.env.DATABASE_URL,ssl:false});
 try{
  await initGrcCore();await initOrganizations();await initIssueRiskCapa();await initFindingReview();await initFindingRisk();await fp.initFindingPromotion();
  const mk=async()=>{const id=crypto.randomUUID();await pool.query("INSERT INTO app_users(id,email,password_hash,password_salt,totp_secret) VALUES($1,$2,'x','x','x')",[id,id+'@t.example']);return id};
  const manager=await mk(),analyst=await mk();
  const org:any=await createOrganization(manager,{name:'Promo '+manager.slice(0,8)});const orgId=org.id||org.organization?.id;
  await addMember(manager,orgId,analyst,'SECURITY_ANALYST');
  const aid=crypto.randomUUID();
  await pool.query("INSERT INTO assessments(id,target,authorized_at,status,payload,organization_id,created_by) VALUES($1,'https://example.com',now(),'COMPLETED','{}',$2,$3)",[aid,orgId,manager]);
  const mkFinding=async(severity:string)=>{const id=crypto.randomUUID();const f={id,assessmentId:aid,source:'nuclei',title:'Finding '+severity+' '+id.slice(0,6),description:'d',severity,asset:'https://example.com',evidenceHash:'e'.repeat(64),createdAt:new Date().toISOString(),mappings:{},remediation:'Patch the component and retest.'};await pool.query('INSERT INTO findings(id,assessment_id,severity,source,created_at,payload) VALUES($1,$2,$3,$4,now(),$5)',[id,aid,severity,'nuclei',f]);return id};
  const high=await mkFinding('HIGH'),medium=await mkFinding('MEDIUM');
  // Disabled by default: nothing is created.
  await reviewFinding(analyst,aid,high,{decision:'CONFIRMED',rationale:'Reproduced manually in staging'});
  assert.equal((await fp.autoPromoteConfirmedFinding(orgId,aid,high,analyst)).reason,'POLICY_DISABLED');
  await assert.rejects(fp.setPromotionPolicy(analyst,orgId,{enabled:true}),/Insufficient organization role/,'only risk managers set the policy');
  await fp.setPromotionPolicy(manager,orgId,{enabled:true,minSeverity:'HIGH'});
  const out=await fp.autoPromoteConfirmedFinding(orgId,aid,high,analyst);
  assert.equal(out.status,'PROMOTED',out.reason);assert.ok(out.issueId&&out.riskId&&out.capaId);
  const risk=(await pool.query('SELECT inherent_score,treatment,created_by FROM grc_enterprise_risks WHERE id=$1',[out.riskId])).rows[0];
  assert.equal(risk.inherent_score,16);assert.equal(risk.treatment,'MITIGATE');assert.equal(risk.created_by,manager);
  const again=await fp.autoPromoteConfirmedFinding(orgId,aid,high,analyst);assert.equal(again.reason,'ALREADY_PROMOTED');
  assert.equal(Number((await pool.query('SELECT count(*) c FROM grc_capa WHERE issue_id=$1',[out.issueId])).rows[0].c),1);
  await reviewFinding(analyst,aid,medium,{decision:'CONFIRMED',rationale:'Reproduced manually in staging'});
  assert.equal((await fp.autoPromoteConfirmedFinding(orgId,aid,medium,analyst)).reason,'BELOW_THRESHOLD');
  // Unconfirmed findings are never promoted, even by the sweep.
  const unreviewed=await mkFinding('CRITICAL');
  const sweep=await fp.runPromotionSweep(manager,orgId);assert.ok(!sweep.outcomes.some(x=>x.findingId===unreviewed));
  // Policy owner losing authority makes automation fail closed.
  await pool.query("UPDATE grc_promotion_policies SET owner_user_id=$2 WHERE organization_id=$1",[orgId,analyst]);
  const critical=await mkFinding('CRITICAL');await reviewFinding(analyst,aid,critical,{decision:'CONFIRMED',rationale:'Reproduced manually in staging'});
  const failed=await fp.autoPromoteConfirmedFinding(orgId,aid,critical,analyst);assert.equal(failed.status,'FAILED');assert.match(String(failed.reason),/Insufficient organization role/);
 }finally{await pool.end()}
});
