import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import pg from 'pg';
import {ISO27001_ANNEX_A,ISO42001_ANNEX_A,ISO27701_CATEGORIES,EXTRA_CANONICAL_CONTROLS} from '../src/iso-library.js';
import {builtInFrameworkLibrary} from '../src/framework-library.js';
import {evaluateControlGates,type GateInputs} from '../src/soa-gates.js';
import {nextPolicyVersion} from '../src/governance-depth.js';

const ciDb=process.env.NODE_ENV==='test'&&/^postgres(?:ql)?:\/\/[^/]*@(?:localhost|127\.0\.0\.1):5432\//.test(process.env.DATABASE_URL||'');

test('ISO/IEC 27001:2022 Annex A library has all 93 controls in four themes, each mapped to known controls',()=>{
 const theme=(t:string)=>ISO27001_ANNEX_A.filter(([k])=>k.startsWith('A.'+t+'.')).length;
 assert.equal(ISO27001_ANNEX_A.length,93);
 assert.deepEqual([theme('5'),theme('6'),theme('7'),theme('8')],[37,8,14,34]);
 assert.equal(new Set(ISO27001_ANNEX_A.map(x=>x[0])).size,93,'unique control ids');
 for(const t of ['5','6','7','8']){const n=ISO27001_ANNEX_A.filter(([k])=>k.startsWith('A.'+t+'.')).map(([k])=>Number(k.split('.')[2]));assert.deepEqual(n,Array.from({length:n.length},(_,i)=>i+1),'A.'+t+' is contiguous')}
 const known=new Set([...builtInFrameworkLibrary.controls.map(c=>c.key),...EXTRA_CANONICAL_CONTROLS.map(c=>c.key)]);
 for(const [k,,controls,guidance] of [...ISO27001_ANNEX_A,...ISO42001_ANNEX_A,...ISO27701_CATEGORIES]){
  assert.ok(controls.length>0,k);for(const c of controls)assert.ok(known.has(c),k+' → '+c);
  assert.ok(guidance.length>=30&&guidance.length<=200,k+' has short own-words guidance');
 }
 assert.equal(ISO27001_ANNEX_A.find(x=>x[0]==='A.8.8')![1],'Management of technical vulnerabilities');
 assert.deepEqual(ISO42001_ANNEX_A.map(x=>x[0]),['A.2','A.3','A.4','A.5','A.6','A.7','A.8','A.9','A.10']);
});

const base:GateInputs={applicability:'APPLICABLE',justification:'Internet-facing service',approvedBy:'approver',ownerUserId:'owner',implementation:'IMPLEMENTED',
 evidence:[{validatedBy:'auditor',submittedBy:'owner',validUntil:new Date(Date.now()+30*86400e3).toISOString(),status:'VALID'}],closureEvidence:0,latestTest:{result:'PASS',executedAt:new Date().toISOString()},openIssues:0,openCapa:0,overdueCapa:0,openRisks:0};
test('the five SoA gates: PASS only when all hold; ACTION_REQUIRED vs CONDITIONAL otherwise',()=>{
 assert.equal(evaluateControlGates(base).status,'PASS');
 assert.equal(evaluateControlGates({...base,approvedBy:'owner'}).status,'ACTION_REQUIRED','owner self-approval fails gate 1');
 assert.equal(evaluateControlGates({...base,applicability:'PENDING'}).status,'ACTION_REQUIRED');
 assert.equal(evaluateControlGates({...base,implementation:'PARTIAL'}).status,'ACTION_REQUIRED');
 const g3=(x:Partial<GateInputs>)=>evaluateControlGates({...base,...x}).gates[2];
 assert.equal(g3({evidence:[{...base.evidence[0],validatedBy:'owner',submittedBy:'owner'}]}).passed,false,'self-validated evidence is not independent');
 assert.equal(g3({evidence:[{...base.evidence[0],validUntil:new Date(Date.now()-1000).toISOString()}]}).reason,'Evidence expired');
 assert.equal(g3({evidence:[],closureEvidence:1}).passed,true,'an independently reviewed closure retest counts');
 assert.equal(evaluateControlGates({...base,latestTest:{result:'FAIL',executedAt:''}}).status,'CONDITIONAL');
 assert.equal(evaluateControlGates({...base,openCapa:1}).status,'CONDITIONAL');
 assert.equal(evaluateControlGates({...base,openCapa:1,overdueCapa:1}).status,'ACTION_REQUIRED');
 assert.equal(evaluateControlGates({...base,applicability:'NOT_APPLICABLE',implementation:'NOT_IMPLEMENTED',evidence:[],latestTest:null}).status,'NOT_APPLICABLE');
 assert.equal(evaluateControlGates({...base,applicability:'NOT_APPLICABLE',approvedBy:null}).status,'ACTION_REQUIRED','unapproved exclusion is not N/A');
 assert.equal(nextPolicyVersion('1.4'),'1.5');assert.equal(nextPolicyVersion('draft'),'1.1');
});

test('Phase 2 on PostgreSQL: ISO library seeded, SoA gates exported and signed, dashboard, policy versions, assets, scheduler',{skip:!ciDb},async()=>{
 process.env.REPORT_SIGNING_KEY='r'.repeat(48);process.env.TARGET_AUTHORIZATION_MODE='attest';
 const pool=new pg.Pool({connectionString:process.env.DATABASE_URL,ssl:false});
 const {initRuntimeSchema}=await import('../src/schema-init.js');await initRuntimeSchema();
 const {createOrganization,addMember}=await import('../src/grc-organizations.js');
 const soaMod=await import('../src/soa-gates.js');const gd=await import('../src/governance-depth.js');const sch=await import('../src/scheduler.js');
 const {recordSignedReport,verifyReportRecord}=await import('../src/report-records.js');
 try{
  assert.equal(Number((await pool.query("SELECT count(*) c FROM grc_framework_requirements WHERE framework='ISO27001' AND framework_version='2022' AND requirement_key LIKE 'A.%.%'")).rows[0].c),93);
  const mk=async()=>{const id=crypto.randomUUID();await pool.query("INSERT INTO app_users(id,email,password_hash,password_salt,totp_secret) VALUES($1,$2,'x','x','x')",[id,id+'@t.example']);return id};
  const admin=await mk(),owner=await mk(),auditor=await mk();
  const org:any=await createOrganization(admin,{name:'P2 '+admin.slice(0,8)});const orgId=org.id||org.organization?.id;
  await addMember(admin,orgId,owner,'CONTROL_OWNER');await addMember(admin,orgId,auditor,'AUDITOR');
  const scopeId=crypto.randomUUID();await pool.query("INSERT INTO grc_scopes(id,organization_id,name,status,created_by) VALUES($1,$2,$3,'ACTIVE',$4)",[scopeId,orgId,'ISMS '+scopeId.slice(0,6),admin]);
  const sc=async(key:string,fields:string)=>{const id=crypto.randomUUID();await pool.query(`INSERT INTO grc_scope_controls(id,organization_id,scope_id,control_id,${fields.split('=')[0]}) SELECT $1,$2,$3,id,${fields.split('=')[1]} FROM grc_canonical_controls WHERE control_key=$4`,[id,orgId,scopeId,key]);return id};
  const pass=await sc('VUL-01',"applicability,applicability_justification,implementation,owner_user_id,approved_by,approved_at='APPLICABLE','Internet-facing','IMPLEMENTED','"+owner+"','"+admin+"',now()");
  await sc('PHY-01',"applicability,applicability_justification,approved_by,approved_at='NOT_APPLICABLE','Fully cloud-hosted; no premises','"+admin+"',now()");
  await sc('CFG-01',"applicability='PENDING'");
  const req=crypto.randomUUID();await pool.query("INSERT INTO grc_evidence_requests(id,organization_id,scope_control_id,title,owner_user_id,status,created_by) VALUES($1,$2,$3,'Monthly scan report',$4,'VALID',$5)",[req,orgId,pass,owner,admin]);
  await pool.query("INSERT INTO grc_evidence_versions(id,evidence_request_id,version,source_type,sha256,submitted_by,validated_by,validated_at,valid_until) VALUES($1,$2,1,'SCANNER',$3,$4,$5,now(),now()+interval '10 days')",[crypto.randomUUID(),req,'a'.repeat(64),owner,auditor]);
  const td=crypto.randomUUID();await pool.query("INSERT INTO grc_control_test_definitions(id,organization_id,scope_control_id,name,test_type) VALUES($1,$2,$3,'Scan evidence present','EVIDENCE_PRESENT')",[td,orgId,pass]);
  await pool.query("INSERT INTO grc_control_test_runs(id,organization_id,test_definition_id,result,rationale,executed_by) VALUES($1,$2,$3,'PASS','Report present and current',$4)",[crypto.randomUUID(),orgId,td,auditor]);
  const soa=await soaMod.soaWithGates(admin,orgId,scopeId);
  const by=(k:string)=>soa.controls.find(c=>c.controlKey===k)!;
  assert.equal(by('VUL-01').status,'PASS');assert.equal(by('PHY-01').status,'NOT_APPLICABLE');assert.equal(by('CFG-01').status,'ACTION_REQUIRED');
  assert.ok((by('VUL-01').mappings as any[]).some(m=>m.framework==='ISO27001'&&m.key==='A.8.8'),'VUL-01 shows the ISO 27001 Annex A mapping');
  // Phase 2 gate artefact: SoA export with all five gates, stored and signed.
  const pdf=await gd.soaPdf(soa),xlsx=gd.soaXlsx(soa);assert.equal(pdf.subarray(0,4).toString(),'%PDF');assert.ok(xlsx.length>1000);
  const rec=await recordSignedReport({organizationId:orgId,scopeRef:scopeId,reportType:'SOA',format:'pdf',filename:'soa.pdf',contentType:'application/pdf',body:pdf,actor:admin});
  assert.equal((await verifyReportRecord(admin,rec.id)).status,'VERIFIED');
  // Evidence freshness reminder (expires in 10 days), deduplicated per day.
  const n1=await sch.generateReminders(),n2=await sch.generateReminders();assert.ok(n1>=1);assert.equal(n2,0,'reminders are deduplicated');
  const notes=await sch.listNotifications(admin,orgId);assert.ok(notes.some((n:any)=>n.kind==='EVIDENCE_EXPIRING'&&n.recipient_user_id===owner));
  assert.equal((await pool.query("SELECT count(*) c FROM grc_notifications WHERE organization_id=$1 AND user_id=$2 AND dedupe_key LIKE 'reminder:EVIDENCE_EXPIRING:%'",[orgId,owner])).rows[0].c,'1','mirrored into the in-app notification centre');
  const sent:string[]=[];const d=await sch.deliverNotifications(500,async(to)=>{sent.push(to)});assert.ok(d.sent>=1&&sent.includes(owner+'@t.example'));
  // Dashboard.
  const dash=await gd.complianceDashboard(admin,orgId);
  assert.equal(dash.controls.pass,1);assert.equal(dash.controls.actionRequired,1);
  assert.ok(dash.frameworks.find(f=>f.framework==='ISO27001')!.inScope>0);assert.equal(dash.evidenceFreshness.expiringIn30Days,1);
  // Policy versioning.
  const pid=crypto.randomUUID();await pool.query("INSERT INTO grc_policies(id,organization_id,policy_key,title,version,status,content_ref,approved_by,approved_at,owner_user_id) VALUES($1,$2,'POL-IS','Information security policy','1.0','APPROVED','doc://v1',$3,now(),$4)",[pid,orgId,admin,owner]);
  await assert.rejects(gd.revisePolicy(auditor,orgId,pid,{changeSummary:'Annual update'}),/Insufficient/);
  const rev=await gd.revisePolicy(owner,orgId,pid,{changeSummary:'Annual update for 2027',contentRef:'doc://v2'});
  assert.equal(rev.version,'1.1');assert.equal(rev.status,'DRAFT');
  const hist=await gd.policyVersionHistory(admin,orgId,pid);assert.equal(hist.history[0].version,'1.0');assert.equal(hist.history[0].content_ref,'doc://v1');assert.equal(hist.acknowledgement.version,'1.1');
  // Asset links.
  const asset=crypto.randomUUID();await pool.query("INSERT INTO assessment_assets(id,organization_id,asset_type,asset_key,name) VALUES($1,$2,'APPLICATION',$3,'Customer portal')",[asset,orgId,'app-'+asset.slice(0,6)]);
  const prof=await gd.linkAsset(owner,orgId,asset,{linkType:'SCOPE_CONTROL',recordId:pass});assert.equal(prof.controls[0].control_key,'VUL-01');
  await assert.rejects(gd.linkAsset(owner,orgId,asset,{linkType:'RISK',recordId:crypto.randomUUID()}),/not found/);
  // Recurring scans: a due schedule queues a durable scan job under its creator.
  const aid=crypto.randomUUID();await pool.query("INSERT INTO assessments(id,target,authorized_at,status,payload,organization_id) VALUES($1,'https://sched.example.com',now(),'COMPLETED','{}',$2)",[aid,orgId]);
  const s=await sch.createScanSchedule(admin,aid,{profile:'QUICK',intervalDays:7,firstRunAt:new Date(Date.now()-1000).toISOString()});
  const out=await sch.runDueScanSchedules(async(raw:string)=>({url:new URL(raw),addresses:['93.184.216.34']}));
  const mine=out.find((x:any)=>x.scheduleId===s.id) as any;assert.ok(mine?.jobId,JSON.stringify(out));
  assert.equal((await pool.query('SELECT purpose FROM url_scan_jobs WHERE id=$1',[mine.jobId])).rows[0].purpose,'SCHEDULED');
  assert.ok(new Date((await pool.query('SELECT next_run_at FROM grc_scan_schedules WHERE id=$1',[s.id])).rows[0].next_run_at).getTime()>Date.now()+6*86400e3);
 }finally{await pool.end()}
});
