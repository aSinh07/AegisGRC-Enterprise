import crypto from 'node:crypto';
import nodemailer from 'nodemailer';
import {pool} from './db-pool.js';
import {requireAssessmentAccess,requireOrgPermission} from './grc-organizations.js';
import {enqueueUrlScanJob} from './url-scan-jobs.js';

// Scheduler and alerts (target architecture, Phase 2):
//  • recurring scans: due schedules enqueue a durable scan job under the creator's authority,
//    re-checking their permission and the target authorization every run (fail closed);
//  • reminders: evidence expiring/expired, issue SLA breaches, CAPA due soon/overdue, policy reviews,
//    deep scans awaiting approval. Each reminder is deduplicated per record per day;
//  • delivery: every reminder appears in the in-app notification centre; email goes out through SMTP
//    when configured (SMTP_HOST etc.), otherwise the outbox row is marked SKIPPED.

const err=(m:string,statusCode:number)=>Object.assign(new Error(m),{statusCode});

export async function createScanSchedule(user:string,assessmentId:string,input:{profile?:string;intervalDays?:number;firstRunAt?:string}){
 const access=await requireAssessmentAccess(user,assessmentId);await requireOrgPermission(user,access.organization_id,'manageAssessment');
 const profile=String(input.profile||'STANDARD').toUpperCase();if(!['QUICK','STANDARD','DEEP'].includes(profile))throw err('Profile must be QUICK, STANDARD or DEEP',400);
 const days=Number(input.intervalDays||7);if(!Number.isInteger(days)||days<1||days>365)throw err('intervalDays must be 1-365',400);
 const first=input.firstRunAt?new Date(input.firstRunAt):new Date(Date.now()+days*86400e3);if(!Number.isFinite(first.getTime()))throw err('Invalid firstRunAt',400);
 return (await pool.query(`INSERT INTO grc_scan_schedules(id,organization_id,assessment_id,profile,interval_days,next_run_at,created_by) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *`,[crypto.randomUUID(),access.organization_id,assessmentId,profile,days,first,user])).rows[0];
}
export async function listScanSchedules(user:string,org:string){await requireOrgPermission(user,org,'read');return (await pool.query('SELECT s.*,a.target FROM grc_scan_schedules s JOIN assessments a ON a.id=s.assessment_id WHERE s.organization_id=$1 ORDER BY s.next_run_at',[org])).rows}
export async function setScanScheduleEnabled(user:string,org:string,id:string,enabled:boolean){
 await requireOrgPermission(user,org,'manageAssessment');
 const r=(await pool.query('UPDATE grc_scan_schedules SET enabled=$3 WHERE id=$1 AND organization_id=$2 RETURNING *',[id,org,enabled])).rows[0];if(!r)throw err('Schedule not found',404);return r;
}

/** Runs due schedules. Validation is injectable for tests; production resolves and checks scope. */
export async function runDueScanSchedules(validate?:Parameters<typeof enqueueUrlScanJob>[3]){
 const due=(await pool.query(`UPDATE grc_scan_schedules SET next_run_at=next_run_at+(interval_days||' days')::interval,last_run_at=now() WHERE id IN (SELECT id FROM grc_scan_schedules WHERE enabled AND next_run_at<=now() ORDER BY next_run_at LIMIT 20 FOR UPDATE SKIP LOCKED) RETURNING *`)).rows;
 const results=[];
 for(const s of due){
  try{const job=await enqueueUrlScanJob(s.created_by,s.assessment_id,{profile:s.profile,purpose:'SCHEDULED'},validate);
   await pool.query('UPDATE grc_scan_schedules SET last_result=$2 WHERE id=$1',[s.id,(job.reused?'ALREADY_ACTIVE ':'QUEUED ')+job.id]);results.push({scheduleId:s.id,jobId:job.id,status:job.status});}
  catch(e:any){const reason=String(e?.message||e).slice(0,500);
   await pool.query('UPDATE grc_scan_schedules SET last_result=$2 WHERE id=$1',[s.id,'FAILED: '+reason]);
   await notify(s.organization_id,'SCAN_SCHEDULE_FAILED',s.created_by,'SCAN_SCHEDULE',s.id,'Scheduled scan could not start','The scheduled '+s.profile+' scan for assessment '+s.assessment_id+' did not start: '+reason);
   results.push({scheduleId:s.id,error:reason})}
 }
 return results;
}

async function notify(org:string,kind:string,recipient:string|null,recordType:string,recordId:string,subject:string,body:string){
 const day=new Date().toISOString().slice(0,10);
 const r=await pool.query(`INSERT INTO grc_reminder_outbox(id,organization_id,kind,recipient_user_id,record_type,record_id,subject,body,dedupe_key) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(dedupe_key) DO NOTHING`,
  [crypto.randomUUID(),org,kind,recipient,recordType,recordId,subject,body,[kind,recordId,recipient||'-',day].join(':')]);
 // Also surface it in the existing in-app notification centre (grc_notifications).
 if(r.rowCount&&recipient){const sev=/OVERDUE|BREACHED|EXPIRED|FAILED/.test(kind)?'HIGH':'WARNING';
  await pool.query(`INSERT INTO grc_notifications(id,organization_id,user_id,severity,title,message,record_type,record_id,dedupe_key) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(organization_id,user_id,dedupe_key) DO NOTHING`,
   [crypto.randomUUID(),org,recipient,sev,subject,body,recordType,recordId,'reminder:'+[kind,recordId,day].join(':')]).catch(()=>{})}
 return r.rowCount||0;
}

/** Generates reminders across all organizations (idempotent per record per day). */
export async function generateReminders(){
 let created=0;
 const run=async(sql:string,f:(r:any)=>[string,string,string|null,string,string,string,string])=>{for(const r of (await pool.query(sql)).rows)created+=await notify(...f(r))};
 await run(`SELECT r.organization_id,r.owner_user_id,r.id,r.title,v.valid_until FROM grc_evidence_requests r JOIN grc_evidence_versions v ON v.evidence_request_id=r.id WHERE v.valid_until BETWEEN now() AND now()+interval '14 days' AND r.status='VALID'`,
  r=>[r.organization_id,'EVIDENCE_EXPIRING',r.owner_user_id,'EVIDENCE_REQUEST',r.id,'Evidence expires soon: '+r.title,'Evidence for "'+r.title+'" stops being current on '+new Date(r.valid_until).toISOString().slice(0,10)+'. Submit a fresh version so the control keeps passing gate 3.']);
 await run(`SELECT r.organization_id,r.owner_user_id,r.id,r.title FROM grc_evidence_requests r WHERE r.status='VALID' AND NOT EXISTS (SELECT 1 FROM grc_evidence_versions v WHERE v.evidence_request_id=r.id AND (v.valid_until IS NULL OR v.valid_until>now()))`,
  r=>[r.organization_id,'EVIDENCE_EXPIRED',r.owner_user_id,'EVIDENCE_REQUEST',r.id,'Evidence expired: '+r.title,'Evidence for "'+r.title+'" has expired. The related control cannot PASS until fresh evidence is validated.']);
 await run(`SELECT organization_id,owner_user_id,id,issue_key,title,due_at FROM grc_issues WHERE status NOT IN ('CLOSED','REMEDIATION_VERIFIED') AND due_at<now() AND organization_id IS NOT NULL`,
  r=>[r.organization_id,'ISSUE_SLA_BREACHED',r.owner_user_id,'ISSUE',r.id,'SLA breached: '+r.issue_key,r.issue_key+' "'+r.title+'" passed its remediation due date ('+new Date(r.due_at).toISOString().slice(0,10)+').']);
 await run(`SELECT organization_id,owner_user_id,id,capa_key,due_at FROM grc_capa WHERE status<>'CLOSED' AND due_at BETWEEN now() AND now()+interval '7 days'`,
  r=>[r.organization_id,'CAPA_DUE_SOON',r.owner_user_id,'CAPA',r.id,'CAPA due soon: '+r.capa_key,r.capa_key+' is due on '+new Date(r.due_at).toISOString().slice(0,10)+'.']);
 await run(`SELECT organization_id,owner_user_id,id,capa_key,due_at FROM grc_capa WHERE status<>'CLOSED' AND due_at<now()`,
  r=>[r.organization_id,'CAPA_OVERDUE',r.owner_user_id,'CAPA',r.id,'CAPA overdue: '+r.capa_key,r.capa_key+' was due on '+new Date(r.due_at).toISOString().slice(0,10)+' and is still open.']);
 await run(`SELECT organization_id,owner_user_id,id,policy_key,title,next_review_at FROM grc_policies WHERE status='APPROVED' AND next_review_at<now()+interval '14 days'`,
  r=>[r.organization_id,'POLICY_REVIEW_DUE',r.owner_user_id,'POLICY',r.id,'Policy review due: '+r.policy_key,'"'+r.title+'" is due for review on '+new Date(r.next_review_at).toISOString().slice(0,10)+'.']);
 await run(`SELECT j.organization_id,m.user_id,j.id,j.origin FROM url_scan_jobs j JOIN grc_organization_members m ON m.organization_id=j.organization_id AND m.status='ACTIVE' AND m.role IN ('ORG_ADMIN','GRC_MANAGER') AND m.user_id<>j.requested_by WHERE j.status='AWAITING_APPROVAL'`,
  r=>[r.organization_id,'DEEP_SCAN_APPROVAL_PENDING',r.user_id,'SCAN_JOB',r.id,'Deep scan awaiting your approval','A DEEP scan of '+r.origin+' is waiting for a second approver in Governed Lifecycle.']);
 return created;
}

let transport:ReturnType<typeof nodemailer.createTransport>|null|undefined;
function mailer(){
 if(transport!==undefined)return transport;
 const host=process.env.SMTP_HOST;
 transport=host?nodemailer.createTransport({host,port:Number(process.env.SMTP_PORT||587),secure:String(process.env.SMTP_SECURE||'')==='true',requireTLS:String(process.env.SMTP_SECURE||'')!=='true',auth:process.env.SMTP_USER?{user:process.env.SMTP_USER,pass:process.env.SMTP_PASSWORD||''}:undefined}):null;
 return transport;
}
/** Sends PENDING notifications by email. Without SMTP they are marked SKIPPED and stay visible in-app. */
export async function deliverNotifications(limit=50,send?:(to:string,subject:string,text:string)=>Promise<void>){
 const rows=(await pool.query(`SELECT n.id,n.subject,n.body,u.email FROM grc_reminder_outbox n LEFT JOIN app_users u ON u.id=n.recipient_user_id WHERE n.status='PENDING' ORDER BY n.created_at LIMIT $1`,[limit])).rows;
 const t=mailer();const from=process.env.SMTP_FROM||'AegisGRC <no-reply@localhost>';
 const out={sent:0,skipped:0,failed:0};
 for(const n of rows){
  if(!n.email||(!t&&!send)){await pool.query(`UPDATE grc_reminder_outbox SET status='SKIPPED',error=$2 WHERE id=$1`,[n.id,n.email?'SMTP not configured':'No recipient email']);out.skipped++;continue}
  try{if(send)await send(n.email,n.subject,n.body);else await t!.sendMail({from,to:n.email,subject:'[AegisGRC] '+n.subject,text:n.body+'\n\nThis is an automated AegisGRC reminder.'});
   await pool.query(`UPDATE grc_reminder_outbox SET status='SENT',sent_at=now(),attempts=attempts+1 WHERE id=$1`,[n.id]);out.sent++}
  catch(e:any){await pool.query(`UPDATE grc_reminder_outbox SET status=CASE WHEN attempts+1>=5 THEN 'FAILED' ELSE 'PENDING' END,attempts=attempts+1,error=$2 WHERE id=$1`,[n.id,String(e?.message||e).slice(0,500)]);out.failed++}
 }
 return out;
}
export async function listNotifications(user:string,org:string,mineOnly=false){
 await requireOrgPermission(user,org,'read');
 return (await pool.query(`SELECT id,kind,recipient_user_id,record_type,record_id,subject,body,status,created_at,sent_at FROM grc_reminder_outbox WHERE organization_id=$1 ${mineOnly?'AND recipient_user_id=$2':''} ORDER BY created_at DESC LIMIT 200`,mineOnly?[org,user]:[org])).rows;
}

export function startScheduler(intervalMs=Number(process.env.SCHEDULER_INTERVAL_MS||300000)){
 const tick=async()=>{try{await runDueScanSchedules();await generateReminders();await deliverNotifications()}catch(e:any){console.error('[AEGIS SCHEDULER]',String(e?.message||e))}};
 const t=setInterval(()=>void tick(),Math.max(60000,intervalMs));t.unref?.();setTimeout(()=>void tick(),15000).unref?.();return t;
}
