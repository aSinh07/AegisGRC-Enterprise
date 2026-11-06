import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import pg from 'pg';
import {spawn,type ChildProcess} from 'node:child_process';
import {signWorkerRequest,verifyWorkerRequest,signScanOutput,verifyScanOutput,parseWorkerKeys} from '../src/worker-protocol.js';
import {SCAN_PROFILES,taskStateFor} from '../src/url-scan-jobs.js';

const ciDb=process.env.NODE_ENV==='test'&&/^postgres(?:ql)?:\/\/[^/]*@(?:localhost|127\.0\.0\.1):5432\//.test(process.env.DATABASE_URL||'');
const fakeValidate=async(raw:string)=>({url:new URL(raw),addresses:['93.184.216.34']});
const SECRET='w'.repeat(48);

// ── Worker protocol ─────────────────────────────────────────────────────────
test('worker requests are authenticated, bound to path and body, fresh and single-use',async()=>{
 const keys=parseWorkerKeys('gce-1:'+SECRET);const seen=new Set<string>();const remember=async(w:string,n:string)=>{const k=w+n;if(seen.has(k))return false;seen.add(k);return true};
 const body=Buffer.from('{"tools":["nmap"]}');const h=signWorkerRequest('gce-1',SECRET,'POST','/api/worker/v1/claim',body);
 const lower=Object.fromEntries(Object.entries(h).map(([k,v])=>[k.toLowerCase(),v]));
 assert.deepEqual(await verifyWorkerRequest(lower,'POST','/api/worker/v1/claim',body,keys,remember),{ok:true,workerId:'gce-1'});
 assert.equal((await verifyWorkerRequest(lower,'POST','/api/worker/v1/claim',body,keys,remember) as any).reason,'REPLAYED_NONCE');
 const fresh=()=>Object.fromEntries(Object.entries(signWorkerRequest('gce-1',SECRET,'POST','/api/worker/v1/claim',body)).map(([k,v])=>[k.toLowerCase(),v]));
 assert.equal((await verifyWorkerRequest(fresh(),'POST','/api/worker/v1/tasks/x/result',body,keys,remember) as any).reason,'BAD_SIGNATURE','signature is bound to the path');
 assert.equal((await verifyWorkerRequest(fresh(),'POST','/api/worker/v1/claim',Buffer.from('{}'),keys,remember) as any).reason,'BODY_DIGEST_MISMATCH');
 assert.equal((await verifyWorkerRequest({...fresh(),'x-aegis-worker-id':'rogue'},'POST','/api/worker/v1/claim',body,keys,remember) as any).reason,'UNKNOWN_WORKER');
 const old=Object.fromEntries(Object.entries(signWorkerRequest('gce-1',SECRET,'POST','/api/worker/v1/claim',body,Date.now()-10*60e3)).map(([k,v])=>[k.toLowerCase(),v]));
 assert.equal((await verifyWorkerRequest(old,'POST','/api/worker/v1/claim',body,keys,remember) as any).reason,'STALE_OR_FUTURE_TIMESTAMP');
 assert.throws(()=>parseWorkerKeys('gce-1:short'),/at least 32/);
});
test('scan output signature covers the canonical raw result',()=>{
 const raw={tool:'nmap',stdout:'<nmaprun/>',stderr:'',exitCode:0,meta:{b:1,a:2}};
 const sig=signScanOutput(SECRET,'task-1',raw);
 assert.equal(verifyScanOutput(SECRET,'task-1',{meta:{a:2,b:1},exitCode:0,stderr:'',stdout:'<nmaprun/>',tool:'nmap'},sig),true,'key order does not matter');
 assert.equal(verifyScanOutput(SECRET,'task-1',{...raw,stdout:'<nmaprun><host/></nmaprun>'},sig),false);
 assert.equal(verifyScanOutput(SECRET,'task-2',raw,sig),false,'bound to the task id');
});
test('scan profiles: only DEEP carries active attack tools and needs approval',()=>{
 assert.equal(SCAN_PROFILES.QUICK.requiresApproval,false);assert.equal(SCAN_PROFILES.STANDARD.requiresApproval,false);assert.equal(SCAN_PROFILES.DEEP.requiresApproval,true);
 const tools=(p:keyof typeof SCAN_PROFILES)=>SCAN_PROFILES[p].tasks.map(t=>t.tool+(t.options?.zapMode?':'+t.options.zapMode:''));
 assert.ok(!tools('STANDARD').includes('sqlmap'));assert.ok(tools('STANDARD').includes('zap:passive'));
 assert.ok(tools('DEEP').includes('sqlmap'));assert.ok(tools('DEEP').includes('zap:active'));
 assert.equal(taskStateFor({exitCode:0,timedOut:false,stdoutTruncated:false,stderrTruncated:false}),'SUCCEEDED');
 assert.equal(taskStateFor({exitCode:null,timedOut:true,stdoutTruncated:false,stderrTruncated:false}),'TIMEOUT');
 assert.equal(taskStateFor({exitCode:0,timedOut:false,stdoutTruncated:true,stderrTruncated:false}),'FAILED','truncated output is never a success');
});

// ── Shared fixtures for the PostgreSQL tests ────────────────────────────────
async function fixture(pool:pg.Pool){
 const {createOrganization,addMember,initOrganizations}=await import('../src/grc-organizations.js');
 const ta=await import('../src/target-authorization.js');
 await initOrganizations();
 const mk=async()=>{const id=crypto.randomUUID();await pool.query("INSERT INTO app_users(id,email,password_hash,password_salt,totp_secret) VALUES($1,$2,'x','x','x')",[id,id+'@t.example']);return id};
 const manager=await mk(),analyst=await mk(),developer=await mk();
 const org:any=await createOrganization(manager,{name:'Lifecycle '+manager.slice(0,8)});const orgId=org.id||org.organization?.id;
 await addMember(manager,orgId,analyst,'SECURITY_ANALYST');await addMember(manager,orgId,developer,'DEVELOPER');
 const host='app-'+manager.slice(0,8)+'.example.com',origin='https://'+host;
 const req=await ta.requestTargetAuthorization(analyst,orgId,{targetUrl:origin,justification:'Engagement SOW-77 approved by CISO'},fakeValidate);
 await ta.verifyTargetAuthorization(analyst,orgId,req.id,async()=>({observed:[req.challenge.recordValue as string],evidence:{}}));
 await ta.decideTargetAuthorization(manager,orgId,req.id,{decision:'APPROVE'});
 const mkAssessment=async()=>{const id=crypto.randomUUID();await pool.query("INSERT INTO assessments(id,target,authorized_at,status,payload,organization_id,created_by) VALUES($1,$2,now(),'AUTHORIZED',$3,$4,$5)",[id,origin,{id,target:origin,authorizedAt:new Date().toISOString(),status:'AUTHORIZED',findings:[],evidenceIds:[],organizationId:orgId},orgId,analyst]);return id};
 return {orgId,manager,analyst,developer,host,origin,targetAuthorizationId:req.id,mkAssessment,ta};
}
const rawHttp=(headers:Record<string,string>)=>({tool:'http' as const,startedAt:new Date().toISOString(),completedAt:new Date().toISOString(),stdout:JSON.stringify({status:200,headers}),stderr:'',exitCode:0,timedOut:false,stdoutTruncated:false,stderrTruncated:false,durationMs:12,egress:{mode:'PINNED_LOOKUP',pinnedAddress:'93.184.216.34'}});

test('scan jobs: queued with pinned scope, leased, persisted as signed evidence, finalized; deep scans need a second approver',{skip:!ciDb},async()=>{
 const prior=process.env.TARGET_AUTHORIZATION_MODE;process.env.TARGET_AUTHORIZATION_MODE='enforce';process.env.EVIDENCE_HMAC_KEY='e'.repeat(40);
 const pool=new pg.Pool({connectionString:process.env.DATABASE_URL,ssl:false});
 const jobs=await import('../src/url-scan-jobs.js');
 const {installScanJobPersistence}=await import('../src/scan-job-persistence.js');installScanJobPersistence();
 const {verifyEvidenceSignature}=await import('../src/evidence-signing.js');
 try{
  const f=await fixture(pool);const aid=await f.mkAssessment();
  await assert.rejects(jobs.enqueueUrlScanJob(f.developer,aid,{profile:'QUICK'},fakeValidate),/Insufficient organization role/,'developers cannot start scans');
  const job=await jobs.enqueueUrlScanJob(f.analyst,aid,{profile:'QUICK'},fakeValidate);
  assert.equal(job.status,'QUEUED');assert.deepEqual(job.pinned_addresses,['93.184.216.34']);assert.equal(job.target_authorization_id,f.targetAuthorizationId);
  assert.equal((await jobs.enqueueUrlScanJob(f.analyst,aid,{profile:'QUICK'},fakeValidate)).reused,true,'one active job per assessment');
  assert.equal((await pool.query('SELECT status FROM assessments WHERE id=$1',[aid])).rows[0].status,'RUNNING');
  // Lease every QUICK task for this job (other tests' jobs may be queued too: only touch ours).
  // Isolate from queued work left by other test runs in the shared CI database.
  await pool.query("UPDATE url_scan_tasks SET state='CANCELLED' WHERE state IN ('QUEUED','LEASED') AND job_id<>$1",[job.id]);
  const leases:any[]=[];for(let i=0;i<2;i++){const l=await jobs.claimUrlScanTask('test-worker');if(l)leases.push(l)}
  assert.equal(leases.length,2);
  const http=leases.find(l=>l.spec.tool==='http'),nmap=leases.find(l=>l.spec.tool==='nmap');
  assert.equal(http.spec.origin,f.origin);assert.deepEqual(http.spec.pinnedAddresses,['93.184.216.34']);
  await assert.rejects(jobs.completeUrlScanTask(http.taskId,'test-worker','wrong-token',rawHttp({}),{}),/Lease not held/);
  await assert.rejects(jobs.completeUrlScanTask(http.taskId,'other-worker',http.leaseToken,rawHttp({}),{}),/Lease not held/);
  await assert.rejects(jobs.completeUrlScanTask(http.taskId,'test-worker',http.leaseToken,{...rawHttp({}),tool:'nmap'} as any,{}),/does not match/);
  const done=await jobs.completeUrlScanTask(http.taskId,'test-worker',http.leaseToken,rawHttp({server:'nginx','x-content-type-options':'nosniff'}),{mode:'TEST',workerId:'test-worker'});
  assert.equal(done.state,'SUCCEEDED');assert.ok(done.evidence!.findingCount>=3,'missing HSTS/CSP/framing + server banner are findings');
  const ev=(await pool.query('SELECT payload FROM evidence WHERE id=$1',[done.evidence!.evidenceId])).rows[0].payload;
  assert.equal(verifyEvidenceSignature(ev).status,'VALID');assert.equal(ev.metadata.scanJobId,job.id);assert.equal(ev.metadata.workerAttestation.workerId,'test-worker');
  await jobs.completeUrlScanTask(nmap.taskId,'test-worker',nmap.leaseToken,null,{},'nmap: executable not found');
  const final=(await pool.query('SELECT status,coverage FROM url_scan_jobs WHERE id=$1',[job.id])).rows[0];
  assert.equal(final.status,'PARTIAL');assert.deepEqual(final.coverage.failed,['nmap']);
  const a=(await pool.query('SELECT status,payload FROM assessments WHERE id=$1',[aid])).rows[0];
  assert.equal(a.status,'PARTIAL');assert.equal(a.payload.scanCoverage.scanJobId,job.id);
  // DEEP: awaits approval, nothing is leasable until a different approver signs off.
  const aid2=await f.mkAssessment();
  const deep=await jobs.enqueueUrlScanJob(f.analyst,aid2,{profile:'DEEP'},fakeValidate);
  assert.equal(deep.status,'AWAITING_APPROVAL');
  assert.equal(Number((await pool.query("SELECT count(*) c FROM url_scan_tasks WHERE job_id=$1 AND state='BLOCKED'",[deep.id])).rows[0].c),6);
  await assert.rejects(jobs.decideUrlScanJob(f.analyst,deep.id,{decision:'APPROVE'}),/Insufficient organization role/);
  await pool.query("UPDATE url_scan_jobs SET requested_by=$2 WHERE id=$1",[deep.id,f.manager]);
  await assert.rejects(jobs.decideUrlScanJob(f.manager,deep.id,{decision:'APPROVE'}),/Separation of duties/);
  await pool.query("UPDATE url_scan_jobs SET requested_by=$2 WHERE id=$1",[deep.id,f.analyst]);
  await jobs.decideUrlScanJob(f.manager,deep.id,{decision:'APPROVE'});
  assert.equal(Number((await pool.query("SELECT count(*) c FROM url_scan_tasks WHERE job_id=$1 AND state='QUEUED'",[deep.id])).rows[0].c),6);
  // Lease expiry: requeued, then FAILED after max attempts.
  const t=(await pool.query("SELECT id FROM url_scan_tasks WHERE job_id=$1 AND tool='sqlmap'",[deep.id])).rows[0].id;
  for(let attempt=1;attempt<=2;attempt++){
   await pool.query("UPDATE url_scan_tasks SET state='LEASED',lease_owner='dead',lease_token='x',attempts=$2,lease_expires_at=now()-interval '1 minute' WHERE id=$1",[t,attempt]);
   await jobs.recoverExpiredScanLeases();
   assert.equal((await pool.query('SELECT state FROM url_scan_tasks WHERE id=$1',[t])).rows[0].state,attempt<2?'QUEUED':'FAILED');
  }
  // Revoking the target authorization cancels the queued work at hand-out.
  await f.ta.revokeTargetAuthorization(f.manager,f.orgId,f.targetAuthorizationId,'Engagement ended');
  for(let i=0;i<20;i++){const l=await jobs.claimUrlScanTask('test-worker');if(!l)break;assert.notEqual(l.jobId,deep.id,'no task of a revoked target is handed out');await pool.query("UPDATE url_scan_tasks SET state='QUEUED',lease_owner=NULL,lease_token=NULL WHERE id=$1",[l.taskId]);break}
  const cancelled=(await pool.query("SELECT status FROM url_scan_jobs WHERE id=$1",[deep.id])).rows[0].status;
  assert.equal(cancelled,'FAILED','all tasks cancelled → job fails closed');
 }finally{if(prior===undefined)delete process.env.TARGET_AUTHORIZATION_MODE;else process.env.TARGET_AUTHORIZATION_MODE=prior;await pool.end()}
});

test('remote worker API: signed claim and signed result over HTTP; tampered output and replays are refused',{skip:!ciDb},async()=>{
 const pool=new pg.Pool({connectionString:process.env.DATABASE_URL,ssl:false});
 const port=18000+Math.floor(Math.random()*1000);
 const srv:ChildProcess=spawn(process.execPath,['--import','tsx','src/server.ts'],{env:{...process.env,PORT:String(port),SCAN_WORKER_MODE:'remote',AEGIS_WORKER_KEYS:'gce-test:'+SECRET,TARGET_AUTHORIZATION_MODE:'attest',EVIDENCE_HMAC_KEY:'e'.repeat(40)},stdio:'ignore'});
 try{
  let up=false;for(let i=0;i<60&&!up;i++){try{up=(await fetch(`http://127.0.0.1:${port}/api/ready`)).ok}catch{}if(!up)await new Promise(r=>setTimeout(r,500))}
  assert.ok(up,'server started');
  const jobs=await import('../src/url-scan-jobs.js');
  const f=await fixture(pool);const aid=await f.mkAssessment();
  const job=await jobs.enqueueUrlScanJob(f.analyst,aid,{profile:'QUICK'},fakeValidate);
  const post=async(path:string,body:any,mutate?:(h:any)=>void)=>{const raw=Buffer.from(JSON.stringify(body));const h:any={'Content-Type':'application/json',...signWorkerRequest('gce-test',SECRET,'POST',path,raw)};mutate?.(h);const r=await fetch(`http://127.0.0.1:${port}${path}`,{method:'POST',headers:h,body:raw});return {status:r.status,data:r.status===204?null:await r.json().catch(()=>null),headers:h,raw}};
  assert.equal((await post('/api/worker/v1/claim',{},h=>{h['X-Aegis-Signature']='0'.repeat(64)})).status,401);
  await pool.query("UPDATE url_scan_tasks SET state='CANCELLED' WHERE state IN ('QUEUED','LEASED') AND job_id<>$1",[job.id]);
  let lease:any=null;
  for(let i=0;i<20;i++){const r=await post('/api/worker/v1/claim',{tools:['http']});if(r.status!==200)break;if(r.data.jobId===job.id){lease=r.data;break}}
  assert.ok(lease,'worker leased the http task of our job');
  const raw=rawHttp({});
  const path='/api/worker/v1/tasks/'+lease.taskId+'/result';
  const bad=await post(path,{leaseToken:lease.leaseToken,raw:{...raw,stdout:raw.stdout.replace('200','201')},outputSignature:signScanOutput(SECRET,lease.taskId,raw)});
  assert.equal(bad.status,400,'output that does not match its signature is rejected');
  const ok=await post(path,{leaseToken:lease.leaseToken,raw,outputSignature:signScanOutput(SECRET,lease.taskId,raw)});
  assert.equal(ok.status,200,JSON.stringify(ok.data));assert.equal(ok.data.state,'SUCCEEDED');
  const replay=await fetch(`http://127.0.0.1:${port}${path}`,{method:'POST',headers:ok.headers,body:ok.raw});
  assert.equal(replay.status,401,'exact replay of a signed request is refused');
  const ev=(await pool.query('SELECT payload FROM evidence WHERE id=$1',[ok.data.evidence.evidenceId])).rows[0].payload;
  assert.equal(ev.metadata.workerAttestation.signatureVerified,true);assert.equal(ev.metadata.workerAttestation.workerId,'gce-test');
  assert.equal((await pool.query('SELECT 1 FROM scanner_workers WHERE id=$1',['gce-test'])).rowCount,1);
 }finally{srv.kill('SIGTERM');await pool.end()}
});
