import 'dotenv/config';
import {runScanTask,type RawScanResult,type ScanTool} from '../scan-runner.js';
import {signWorkerRequest,signScanOutput} from '../worker-protocol.js';
import type {LeasedTask} from '../url-scan-jobs.js';

// AegisGRC remote scanner worker.
//
// Pull-only: it makes outbound HTTPS requests to the system of record (through Cloudflare
// Tunnel + Access) and never listens on a port. It holds no database credentials and
// writes nothing to disk; raw output lives in memory only until it is returned. Every
// request is HMAC-signed and every result carries a signature over the raw output.

const base=String(process.env.AEGIS_URL||'').replace(/\/$/,'');
const workerId=String(process.env.AEGIS_WORKER_ID||'');
const secret=String(process.env.AEGIS_WORKER_SECRET||'');
const tools=String(process.env.AEGIS_WORKER_TOOLS||'').split(',').map(x=>x.trim()).filter(Boolean) as ScanTool[];
const pollMs=Math.max(1000,Number(process.env.AEGIS_WORKER_POLL_MS||5000));
const VERSION='aegis-scanner-worker/1.0';
if(!/^https:\/\//.test(base)&&!process.env.AEGIS_WORKER_ALLOW_HTTP)throw new Error('AEGIS_URL must be an https:// URL (set AEGIS_WORKER_ALLOW_HTTP=1 only for local testing)');
if(!workerId||secret.length<32)throw new Error('AEGIS_WORKER_ID and AEGIS_WORKER_SECRET (32+ chars) are required');

export async function call(path:string,body:unknown){
 const raw=Buffer.from(JSON.stringify(body??{}));
 const headers:Record<string,string>={'Content-Type':'application/json','X-Aegis-Worker-Version':VERSION,...signWorkerRequest(workerId,secret,'POST',path,raw)};
 // Cloudflare Access service token, when the API hostname is protected by Access.
 if(process.env.CF_ACCESS_CLIENT_ID)headers['CF-Access-Client-Id']=process.env.CF_ACCESS_CLIENT_ID;
 if(process.env.CF_ACCESS_CLIENT_SECRET)headers['CF-Access-Client-Secret']=process.env.CF_ACCESS_CLIENT_SECRET;
 const r=await fetch(base+path,{method:'POST',headers,body:raw,redirect:'error',signal:AbortSignal.timeout(60000)});
 if(r.status===204)return null;
 const d:any=await r.json().catch(()=>({}));
 if(!r.ok)throw Object.assign(new Error(path+' → HTTP '+r.status+': '+(d.error||'')+(d.reason?' ('+d.reason+')':'')),{status:r.status});
 return d;
}

async function runOne(lease:LeasedTask){
 const hb=setInterval(()=>{call('/api/worker/v1/tasks/'+lease.taskId+'/heartbeat',{leaseToken:lease.leaseToken}).catch(e=>console.error('[worker] heartbeat',e.message))},60000);
 let raw:RawScanResult|null=null,failure:string|undefined;
 try{raw=await runScanTask(lease.spec)}catch(e:any){failure=String(e?.message||e)}finally{clearInterval(hb)}
 const body={leaseToken:lease.leaseToken,raw,failure,outputSignature:raw?signScanOutput(secret,lease.taskId,raw):undefined};
 const out=await call('/api/worker/v1/tasks/'+lease.taskId+'/result',body);
 console.log('[worker] task',lease.taskId,lease.spec.tool,'→',out?.state);
 raw=null; // drop output from memory as soon as it is delivered
}

let stopping=false;
process.on('SIGTERM',()=>{stopping=true});process.on('SIGINT',()=>{stopping=true});
export async function main(){
 console.log('[worker] '+VERSION+' id='+workerId+' polling '+base+(tools.length?' tools='+tools.join(','):''));
 while(!stopping){
  try{const lease=await call('/api/worker/v1/claim',{tools:tools.length?tools:undefined}) as LeasedTask|null;
   if(lease){await runOne(lease);continue}}
  catch(e:any){console.error('[worker]',e.message)}
  await new Promise(r=>setTimeout(r,pollMs));
 }
}
if(process.argv[1]&&/scanner-worker\.(ts|js)$/.test(process.argv[1]))await main();
