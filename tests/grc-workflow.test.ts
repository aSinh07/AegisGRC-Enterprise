import test from 'node:test';
import {readFile} from 'node:fs/promises';
import assert from 'node:assert/strict';
import {authorizeGrcTransition,allowedTransitions} from '../src/grc-workflow.js';
const base={type:'EVIDENCE' as const,from:'SUBMITTED',to:'APPROVED',role:'REVIEWER' as const,actorId:'reviewer',ownerId:'owner',submitterId:'owner',evidenceValidated:true};
test('independent reviewer may approve validated evidence',()=>assert.equal(authorizeGrcTransition(base).ok,true));
test('self approval denied',()=>assert.equal(authorizeGrcTransition({...base,actorId:'owner'}).ok,false));
test('unvalidated evidence denied',()=>assert.equal(authorizeGrcTransition({...base,evidenceValidated:false}).ok,false));
test('invalid transition denied',()=>assert.equal(authorizeGrcTransition({...base,to:'CLOSED'}).ok,false));
test('risk acceptance requires expiry',()=>assert.equal(authorizeGrcTransition({type:'RISK_ACCEPTANCE',from:'IN_REVIEW',to:'APPROVED',role:'GRC_MANAGER',actorId:'manager',submitterId:'owner'}).ok,false));
test('remediation closure requires passing retest',()=>assert.equal(authorizeGrcTransition({type:'REMEDIATION',from:'VALIDATION',to:'CLOSED',role:'REVIEWER',actorId:'reviewer',submitterId:'owner'}).ok,false));
test('policy exposes valid next states',()=>assert.deepEqual(allowedTransitions('EVIDENCE','DRAFT'),['SUBMITTED']));

test('core remediation state changes commit audit events atomically',async()=>{
 const src=await readFile(new URL('../src/grc-remediation.ts',import.meta.url),'utf8');
 assert.match(src,/db:Queryable=pool/);
 assert.match(src,/CREATED',user,undefined,\{issueId,score,treatment:t\},client/);
 assert.match(src,/RISK_ACCEPTED'.*client/);
 assert.match(src,/CREATED',user,undefined,\{issueId\},client/);
 assert.match(src,/CLOSED'.*client/);
});

test('CAPA evidence retest and finding review audit writes are atomic',async()=>{
 const rem=await readFile(new URL('../src/grc-remediation.ts',import.meta.url),'utf8');
 assert.match(rem,/EVIDENCE_SUBMITTED'.*client/);
 assert.match(rem,/RETEST_'.*client/);
 const review=await readFile(new URL('../src/finding-review.ts',import.meta.url),'utf8');
 assert.match(review,/action:'FINDING_REVIEWED'/);
 assert.match(review,/INSERT INTO audit_events/);
 const reviewInsert=review.indexOf("INSERT INTO audit_events");
 const commit=review.indexOf("await client.query('COMMIT')",reviewInsert);
 assert.ok(reviewInsert>=0&&commit>reviewInsert);
});


test('CAPA evidence and retest preconditions are locked inside their transactions',async()=>{
 const remediation=await readFile(new URL('../src/grc-remediation.ts',import.meta.url),'utf8');
 const evidenceStart=remediation.indexOf('export async function submitCapaEvidence');
 const retestStart=remediation.indexOf('export async function attachRetest',evidenceStart);
 const closeStart=remediation.indexOf('export async function closeCapa',retestStart);
 const evidence=remediation.slice(evidenceStart,retestStart),retest=remediation.slice(retestStart,closeStart);
 assert.ok(evidence.indexOf("client.query('BEGIN')")<evidence.indexOf('FOR UPDATE'));
 assert.match(evidence,/FOR UPDATE OF v,r/);
 assert.match(evidence,/client\.query\('ROLLBACK'\)/);
 assert.ok(retest.indexOf("client.query('BEGIN')")<retest.indexOf('FOR UPDATE'));
 assert.match(retest,/CAPA is not ready for retest/);
 assert.match(retest,/grc_control_test_runs[\s\S]*WHERE r\.id=\$1 AND r\.organization_id=\$2 FOR UPDATE OF r,d/);
 assert.match(retest,/client\.query\('ROLLBACK'\)/);
});


test('finding promotion is concurrency safe and idempotent',async()=>{
 const risk=await readFile(new URL('../src/finding-risk.ts',import.meta.url),'utf8');
 const start=risk.indexOf('export async function promoteFindingToIssue');
 const fn=risk.slice(start);
 assert.ok(fn.indexOf("client.query('BEGIN')")<fn.indexOf('SELECT organization_id FROM assessments'));
 assert.match(fn,/findings WHERE id=\$1 AND assessment_id=\$2 FOR UPDATE/);
 assert.match(fn,/finding_reviews[\s\S]*LIMIT 1 FOR UPDATE/);
 assert.match(fn,/ON CONFLICT \(organization_id,finding_id\) WHERE finding_id IS NOT NULL DO NOTHING RETURNING \*/);
 assert.match(fn,/const winner=.*SELECT \* FROM grc_issues/s);
 assert.match(fn,/client\.query\('ROLLBACK'\)/);
});


test('finding review route relies on the transactional audit event only',async()=>{
 const server=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');
 const start=server.indexOf("app.post('/api/grc/assessments/:assessmentId/findings/:findingId/review'");
 const end=server.indexOf("app.get('/api/grc/assessments/:assessmentId/findings/:findingId/reviews'",start);
 const route=server.slice(start,end);
 assert.match(route,/reviewFinding\(u\.userId,req\.params\.assessmentId,req\.params\.findingId/);
 assert.doesNotMatch(route,/db\.saveAudit/);
 const review=await readFile(new URL('../src/finding-review.ts',import.meta.url),'utf8');
 const fn=review.slice(review.indexOf('export async function reviewFinding'),review.indexOf('export async function findingReviewHistory'));
 assert.match(fn,/INSERT INTO audit_events/);
 assert.match(fn,/client\.query\('COMMIT'\)/);
 assert.match(fn,/client\.query\('ROLLBACK'\)/);
});


test('CAPA closure validates retest and reviewer independence under transaction locks',async()=>{
 const remediation=await readFile(new URL('../src/grc-remediation.ts',import.meta.url),'utf8');
 const start=remediation.indexOf('export async function closeCapa');
 const end=remediation.indexOf('export async function listCapa',start);
 const fn=remediation.slice(start,end);
 assert.ok(fn.indexOf("client.query('BEGIN')")<fn.indexOf('SELECT c.*,r.result retest_result'));
 assert.match(fn,/FOR UPDATE OF c/);
 assert.match(fn,/Validated control-test or targeted finding-retest proof required/);
 assert.match(fn,/Independent reviewer required for CAPA closure/);
 assert.match(fn,/WHERE id=\$1 AND status='VALIDATION' RETURNING \*/);
 assert.match(fn,/CAPA state changed before closure/);
 assert.match(fn,/client\.query\('ROLLBACK'\)/);
});


test('assessment mutations require an explicit mutation role',async()=>{
 const orgs=await readFile(new URL('../src/grc-organizations.ts',import.meta.url),'utf8');
 assert.match(orgs,/manageAssessment:new Set<OrgRole>\(\['ORG_ADMIN','GRC_MANAGER','GRC_ANALYST','SECURITY_ANALYST'\]\)/);
 const server=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');
 for(const route of ["app.post('/api/scans/quick'","app.post('/api/scans/run'","app.post('/api/assessments/:id/documents'","app.post('/api/assessments/:id/documents/:docId/security-assess'","app.post('/api/assessments/:id/documents/:docId/analyze'"]){
  const start=server.indexOf(route);assert.ok(start>=0,route+' missing');const next=server.indexOf('app.',start+10);const body=server.slice(start,next<0?start+5000:next);assert.match(body,/requireOrgPermission\(u\.userId,access\.organization_id,'manageAssessment'\)/,route);
 }
});


test('finding promotion audit is committed with the issue transaction',async()=>{
 const risk=await readFile(new URL('../src/finding-risk.ts',import.meta.url),'utf8');
 const start=risk.indexOf('export async function promoteFindingToIssue');const fn=risk.slice(start);
 assert.match(fn,/CONFIRMED_FINDING_PROMOTED_TO_GRC_ISSUE/);
 assert.match(fn,/CONFIRMED_FINDING_PROMOTED_TO_GRC_ISSUE[\s\S]*client/);
 const server=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');
 const rs=server.indexOf("app.post('/api/grc/organizations/:orgId/assessments/:assessmentId/findings/:findingId/issue'");const re=server.indexOf("app.get('/api/grc/assessments/:assessmentId/audit-package.:format'",rs);const route=server.slice(rs,re);
 assert.doesNotMatch(route,/db\.saveAudit/);
});


test('failed control test and generated issue commit atomically',async()=>{
 const evidence=await readFile(new URL('../src/grc-evidence.ts',import.meta.url),'utf8');
 const start=evidence.indexOf('export async function runControlTest');
 const end=evidence.indexOf('export async function listEvidence',start);
 const fn=evidence.slice(start,end);
 assert.ok(fn.indexOf("client.query('BEGIN')")<fn.indexOf('grc_control_test_definitions'));
 assert.match(fn,/active=true FOR UPDATE/);
 assert.match(fn,/INSERT INTO grc_control_test_runs/);
 assert.match(fn,/INSERT INTO grc_issues/);
 assert.ok(fn.indexOf('INSERT INTO grc_control_test_runs')<fn.indexOf('INSERT INTO grc_issues'));
 assert.ok(fn.indexOf('INSERT INTO grc_issues')<fn.indexOf("client.query('COMMIT')"));
 assert.match(fn,/client\.query\('ROLLBACK'\)/);
});


test('evidence submission serializes version allocation under request lock',async()=>{
 const evidence=await readFile(new URL('../src/grc-evidence.ts',import.meta.url),'utf8');
 const start=evidence.indexOf('export async function submitEvidence');
 const end=evidence.indexOf('export async function validateEvidence',start);
 const fn=evidence.slice(start,end);
 assert.ok(fn.indexOf("client.query('BEGIN')")<fn.indexOf('grc_evidence_requests'));
 assert.match(fn,/grc_evidence_requests WHERE id=\$1 AND organization_id=\$2 FOR UPDATE/);
 assert.ok(fn.indexOf('FOR UPDATE')<fn.indexOf('COALESCE(max(version),0)+1'));
 assert.match(fn,/INSERT INTO grc_evidence_versions/);
 assert.ok(fn.indexOf('INSERT INTO grc_evidence_versions')<fn.indexOf("client.query('COMMIT')"));
 assert.match(fn,/client\.query\('ROLLBACK'\)/);
});

test('evidence reviewer independence is checked under transaction locks',async()=>{
 const evidence=await readFile(new URL('../src/grc-evidence.ts',import.meta.url),'utf8');
 const start=evidence.indexOf('export async function validateEvidence');
 const end=evidence.indexOf('export async function createTestDefinition',start);
 const fn=evidence.slice(start,end);
 assert.ok(fn.indexOf("client.query('BEGIN')")<fn.indexOf('SELECT r.*,v.submitted_by'));
 assert.match(fn,/FOR UPDATE OF r,v/);
 assert.ok(fn.indexOf('FOR UPDATE OF r,v')<fn.indexOf('Evidence submitter cannot validate own evidence'));
 assert.ok(fn.indexOf('Evidence submitter cannot validate own evidence')<fn.indexOf("client.query('COMMIT')"));
 assert.match(fn,/client\.query\('ROLLBACK'\)/);
});


test('risk acceptance eligibility is locked and compare-and-set protected',async()=>{
 const remediation=await readFile(new URL('../src/grc-remediation.ts',import.meta.url),'utf8');
 const start=remediation.indexOf('export async function approveRiskAcceptance');
 const end=remediation.indexOf('export async function createCapa',start);
 const fn=remediation.slice(start,end);
 assert.ok(fn.indexOf("client.query('BEGIN')")<fn.indexOf('grc_enterprise_risks WHERE id=$1'));
 assert.match(fn,/grc_enterprise_risks WHERE id=\$1 AND organization_id=\$2 FOR UPDATE/);
 assert.ok(fn.indexOf('FOR UPDATE')<fn.indexOf("r.treatment!=='ACCEPT'"));
 assert.match(fn,/status='ACCEPTANCE_PENDING' RETURNING \*/);
 assert.match(fn,/Risk state changed before acceptance/);
 assert.ok(fn.indexOf('RISK_ACCEPTED')<fn.indexOf("client.query('COMMIT')"));
 assert.match(fn,/client\.query\('ROLLBACK'\)/);
});

test('issue derived risk and CAPA lock source issue and reject closed state',async()=>{
 const remediation=await readFile(new URL('../src/grc-remediation.ts',import.meta.url),'utf8');
 const riskStart=remediation.indexOf('export async function createRiskFromIssue');
 const acceptStart=remediation.indexOf('export async function approveRiskAcceptance',riskStart);
 const risk=remediation.slice(riskStart,acceptStart);
 assert.ok(risk.indexOf("client.query('BEGIN')")<risk.indexOf('grc_issues WHERE id=$1'));
 assert.match(risk,/grc_issues WHERE id=\$1 AND organization_id=\$2 FOR UPDATE/);
 assert.match(risk,/Closed issue cannot create a new risk/);
 const capaStart=remediation.indexOf('export async function createCapa',acceptStart);
 const evidenceStart=remediation.indexOf('export async function submitCapaEvidence',capaStart);
 const capa=remediation.slice(capaStart,evidenceStart);
 assert.ok(capa.indexOf("client.query('BEGIN')")<capa.indexOf('grc_issues WHERE id=$1'));
 assert.match(capa,/grc_issues WHERE id=\$1 AND organization_id=\$2 FOR UPDATE/);
 assert.match(capa,/Closed issue cannot create CAPA/);
 assert.match(capa,/client\.query\('ROLLBACK'\)/);
});


test('CAPA evidence submission enforces lifecycle state and compare-and-set update',async()=>{
 const remediation=await readFile(new URL('../src/grc-remediation.ts',import.meta.url),'utf8');
 const start=remediation.indexOf('export async function submitCapaEvidence');
 const end=remediation.indexOf('export async function attachRetest',start);
 const fn=remediation.slice(start,end);
 assert.match(fn,/grc_capa WHERE id=\$1 AND organization_id=\$2 FOR UPDATE/);
 assert.match(fn,/CAPA is not accepting evidence in its current state/);
 assert.match(fn,/v\.validated_at IS NOT NULL AND v\.valid_until>now\(\)/);
 assert.match(fn,/status = ANY\(\$3::text\[\]\) RETURNING \*/);
 assert.match(fn,/CAPA state changed before evidence submission/);
 assert.ok(fn.indexOf('EVIDENCE_SUBMITTED')<fn.indexOf("client.query('COMMIT')"));
});

test('CAPA retest only accepts deterministic result and compare-and-set transition',async()=>{
 const remediation=await readFile(new URL('../src/grc-remediation.ts',import.meta.url),'utf8');
 const start=remediation.indexOf('export async function attachRetest');
 const end=remediation.indexOf('export async function closeCapa',start);
 const fn=remediation.slice(start,end);
 assert.match(fn,/grc_control_test_runs[\s\S]*WHERE r\.id=\$1 AND r\.organization_id=\$2 FOR UPDATE OF r,d/);
 assert.match(fn,/run\.result!=='PASS'&&run\.result!=='FAIL'/);
 assert.match(fn,/Retest must have a deterministic PASS or FAIL result/);
 assert.match(fn,/status = ANY\(\$4::text\[\]\) RETURNING \*/);
 assert.match(fn,/CAPA state changed before retest attachment/);
 assert.match(fn,/client\.query\('ROLLBACK'\)/);
});


test('scope control approval locks reviewed state and compare-and-set protects decision',async()=>{
 const controls=await readFile(new URL('../src/grc-controls.ts',import.meta.url),'utf8');
 const start=controls.indexOf('export async function approveScopeControl');
 const end=controls.indexOf('export async function statementOfApplicability',start);
 const fn=controls.slice(start,end);
 assert.ok(fn.indexOf("client.query('BEGIN')")<fn.indexOf('grc_scope_controls WHERE id=$1'));
 assert.match(fn,/grc_scope_controls WHERE id=\$1 AND organization_id=\$2 AND scope_id=\$3 FOR UPDATE/);
 assert.ok(fn.indexOf('FOR UPDATE')<fn.indexOf('Control owner cannot approve own applicability decision'));
 assert.ok(fn.indexOf('FOR UPDATE')<fn.indexOf('Pending applicability cannot be approved'));
 assert.match(fn,/applicability=\$5 AND owner_user_id IS NOT DISTINCT FROM \$6 RETURNING \*/);
 assert.match(fn,/Scope control state changed before approval/);
 assert.match(fn,/client\.query\('ROLLBACK'\)/);
});


test('GRC automation is persisted and tenant-scoped',async()=>{
 const automation=await readFile(new URL('../src/grc-automation.ts',import.meta.url),'utf8');
 assert.match(automation,/CREATE TABLE IF NOT EXISTS grc_automation_rules/);
 assert.match(automation,/CREATE TABLE IF NOT EXISTS grc_automation_runs/);
 assert.match(automation,/requireOrgPermission\(user,org,'manageOrg'\)/);
 assert.match(automation,/organization_id=\$2 AND enabled=true FOR UPDATE/);
 assert.match(automation,/EVIDENCE_EXPIRY/);
 assert.match(automation,/CONTROL_TEST_DUE/);
 assert.match(automation,/CAPA_SLA/);
 assert.match(automation,/RISK_ACCEPTANCE_EXPIRY/);
 assert.match(automation,/status='EXPIRED'/);
 assert.match(automation,/status='OVERDUE'/);
 assert.match(automation,/status='ACCEPTANCE_PENDING'/);
});


test('scheduled automation runner locks due rules against duplicate execution',async()=>{
 const automation=await readFile(new URL('../src/grc-automation.ts',import.meta.url),'utf8');
 const start=automation.indexOf('export async function runDueAutomations');
 const fn=automation.slice(start);
 assert.match(fn,/next_run_at<=now\(\)/);
 assert.match(fn,/FOR UPDATE SKIP LOCKED/);
 assert.ok(fn.indexOf('FOR UPDATE SKIP LOCKED')<fn.indexOf("status) VALUES($1,$2,$3,'RUNNING')"));
 assert.match(fn,/trigger:'SCHEDULED'/);
 assert.match(fn,/next_run_at=now\(\)\+\(interval_hours::text\|\|' hours'\)::interval/);
});

test('scheduler ingress requires dedicated timing-safe secret',async()=>{
 const server=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');
 const start=server.indexOf("app.post('/api/internal/grc/automation/run-due'");
 const end=server.indexOf("app.get('/api/grc/organizations/:orgId/automation'",start);
 const fn=server.slice(start,end);
 assert.match(fn,/GRC_AUTOMATION_SECRET/);
 assert.match(fn,/x-aegis-automation-secret/);
 assert.match(fn,/expected\.length<32/);
 assert.match(fn,/crypto\.timingSafeEqual/);
 assert.match(fn,/runDueAutomations/);
});


test('evidence validation accepts only latest submitted version with compare-and-set state',async()=>{
 const evidence=await readFile(new URL('../src/grc-evidence.ts',import.meta.url),'utf8');
 const start=evidence.indexOf('export async function validateEvidence');
 const end=evidence.indexOf('export async function createTestDefinition',start);
 const fn=evidence.slice(start,end);
 assert.match(fn,/q\.status!=='SUBMITTED'/);
 assert.match(fn,/ORDER BY version DESC LIMIT 1 FOR UPDATE/);
 assert.match(fn,/Only the latest evidence version can be validated/);
 assert.match(fn,/WHERE id=\$1 AND status='SUBMITTED' RETURNING id/);
 assert.match(fn,/UPDATE grc_evidence_versions SET validated_by=.*validation_note/);
});

test('CAPA evidence and retest are semantically bound to affected control',async()=>{
 const remediation=await readFile(new URL('../src/grc-remediation.ts',import.meta.url),'utf8');
 const evidenceStart=remediation.indexOf('export async function submitCapaEvidence');
 const retestStart=remediation.indexOf('export async function attachRetest');
 const closeStart=remediation.indexOf('export async function closeCapa');
 const evidenceFn=remediation.slice(evidenceStart,retestStart);
 const retestFn=remediation.slice(retestStart,closeStart);
 assert.match(evidenceFn,/SELECT scope_control_id FROM grc_issues/);
 assert.match(evidenceFn,/ev\.scope_control_id!==issue\.scope_control_id/);
 assert.match(evidenceFn,/CAPA evidence must belong to the affected control/);
 assert.match(retestFn,/JOIN grc_control_test_definitions d ON d\.id=r\.test_definition_id/);
 assert.match(retestFn,/run\.scope_control_id!==issue\.scope_control_id/);
 assert.match(retestFn,/CAPA retest must test the affected control/);
});


test('organization membership changes protect last administrator',async()=>{
 const org=await readFile(new URL('../src/grc-organizations.ts',import.meta.url),'utf8');
 const addStart=org.indexOf('export async function addMember');
 const statusStart=org.indexOf('export async function setMemberStatus');
 const listStart=org.indexOf('export async function listMembers');
 const addFn=org.slice(addStart,statusStart),statusFn=org.slice(statusStart,listStart);
 assert.match(addFn,/SELECT id FROM grc_organizations WHERE id=\$1 FOR UPDATE/);
 assert.match(addFn,/SELECT role,status FROM grc_organization_members.*FOR UPDATE/);
 assert.match(addFn,/Organization must retain at least one active administrator/);
 assert.match(addFn,/Organization admin cannot demote self/);
 assert.match(statusFn,/Organization administrator cannot suspend self/);
 assert.match(statusFn,/role='ORG_ADMIN' AND status='ACTIVE'/);
 assert.match(statusFn,/admins<=1/);
 assert.match(statusFn,/BEGIN/);assert.match(statusFn,/COMMIT/);assert.match(statusFn,/ROLLBACK/);
});


test('GRC notifications are persistent tenant-safe and deduplicated',async()=>{
 const ops=await readFile(new URL('../src/grc-operations.ts',import.meta.url),'utf8');
 const automation=await readFile(new URL('../src/grc-automation.ts',import.meta.url),'utf8');
 assert.match(ops,/CREATE TABLE IF NOT EXISTS grc_notifications/);
 assert.match(ops,/UNIQUE\(organization_id,user_id,dedupe_key\)/);
 assert.match(ops,/WHERE organization_id=\$1 AND user_id=\$2/);
 assert.match(ops,/WHERE id=\$1 AND organization_id=\$2 AND user_id=\$3/);
 assert.match(automation,/CAPA_OVERDUE:/);
 assert.match(automation,/RISK_ACCEPTANCE_EXPIRED:/);
 assert.match(automation,/ON CONFLICT\(organization_id,user_id,dedupe_key\) DO NOTHING/);
});


test('automation only auto-runs deterministic evidence-present tests',async()=>{
 const automation=await readFile(new URL('../src/grc-automation.ts',import.meta.url),'utf8');
 const start=automation.indexOf("}else if(kind==='CONTROL_TEST_DUE')");
 const end=automation.indexOf("}else if(kind==='CAPA_SLA')",start);
 const fn=automation.slice(start,end);
 assert.match(fn,/t\.test_type!=='EVIDENCE_PRESENT'/);
 assert.match(fn,/requires human execution or review/);
 assert.match(fn,/grc_control_test_runs/);
 assert.match(fn,/executed_by\) VALUES\(\$1,\$2,\$3,\$4,\$5,\$6,NULL\)/);
 assert.match(fn,/No current independently validated evidence is present/);
 assert.match(fn,/source_type='CONTROL_TEST'/);
 assert.match(fn,/scope_control_id,priority,status/);
 assert.match(fn,/CONTROL_TEST_FAIL:/);
 assert.match(fn,/manualDue:due\.length-autoRun/);
});

test('Semgrep findings retain stable scanner identity for targeted remediation',async()=>{const s=await readFile(new URL('../src/parsers.ts',import.meta.url),'utf8');assert.match(s,/scannerId:\[String\(r\.check_id\|\|'semgrep'\),String\(r\.path\|\|''\),String\(r\.start\?\.line\|\|r\.start\?\.offset\|\|''\)\]\.join\('\|'\)/);assert.match(s,/confidence:'SCANNER_REPORTED'/)});

test('GRC recommendation endpoint is access-controlled and non-mutating',async()=>{const server=await readFile('src/server.ts','utf8');const start=server.indexOf("app.get('/api/grc/assessments/:assessmentId/findings/:findingId/grc-recommendation'");assert.ok(start>=0);const end=server.indexOf("app.get('/api/grc/assessments/:assessmentId/findings/:findingId/reviews'",start);const route=server.slice(start,end);assert.match(route,/currentUser/);assert.match(route,/requireAssessmentAccess/);assert.match(route,/recommendFindingGrcLinkage/);assert.doesNotMatch(route,/promoteFindingToIssue|INSERT INTO|UPDATE grc_/);});
