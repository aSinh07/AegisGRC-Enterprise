import {spawn} from 'node:child_process';
import {pinnedAddress,withPinnedEgress,pinnedHttpGet,type PinnedTarget} from './pinned-egress.js';
import {scannerArgs,nucleiTemplatesPin} from './scanner-args.js';
import {zapScanPinned} from './zap.js';
import {revalidatePublicHttpTarget,blockedNetworkAddress} from './network-target.js';

// Executes one scan task and returns RAW output only. No database, no parsing, no storage:
// the same code runs inside the app (embedded worker) and on the remote scanner worker VM.
// Parsing, evidence signing and persistence happen on the system of record.

export type ScanTool='http'|'nmap'|'nuclei'|'wapiti'|'zap'|'sqlmap';
export type ScanTaskSpec={tool:ScanTool;options?:{zapMode?:'active'|'passive'};origin:string;pinnedAddresses:string[]};
export type RawScanResult={tool:ScanTool;startedAt:string;completedAt:string;stdout:string;stderr:string;exitCode:number|null;timedOut:boolean;stdoutTruncated:boolean;stderrTruncated:boolean;durationMs:number;egress:Record<string,unknown>;nucleiTemplates?:unknown;zapMode?:string};

const TIMEOUT=()=>Number(process.env.SCAN_TIMEOUT_MS||90000);
const MAX=()=>Number(process.env.MAX_OUTPUT_BYTES||1048576);

export function runProcess(cmd:string,args:string[]){
 return new Promise<{stdout:string;stderr:string;exitCode:number|null;durationMs:number;timedOut:boolean;stdoutTruncated:boolean;stderrTruncated:boolean}>((resolve,reject)=>{
  const started=Date.now(),max=MAX();let out='',err='',done=false,timedOut=false,stdoutTruncated=false,stderrTruncated=false;
  const child=spawn(cmd,args,{shell:false,stdio:['ignore','pipe','pipe'],env:{...process.env,HOME:'/tmp/aegis-tools',XDG_CONFIG_HOME:'/tmp/aegis-tools/config',XDG_CACHE_HOME:'/tmp/aegis-tools/cache',XDG_DATA_HOME:'/tmp/aegis-tools/data'}});
  const timer=setTimeout(()=>{timedOut=true;child.kill('SIGKILL')},TIMEOUT());
  const append=(base:string,chunk:Buffer,which:'stdout'|'stderr')=>{const next=base+chunk.toString();if(next.length>max){if(which==='stdout')stdoutTruncated=true;else stderrTruncated=true}return next.slice(0,max)};
  child.stdout.on('data',(d:Buffer)=>out=append(out,d,'stdout'));child.stderr.on('data',(d:Buffer)=>err=append(err,d,'stderr'));
  child.on('error',e=>{if(!done){done=true;clearTimeout(timer);reject(e)}});
  child.on('close',code=>{if(!done){done=true;clearTimeout(timer);resolve({stdout:out,stderr:err,exitCode:code,durationMs:Date.now()-started,timedOut,stdoutTruncated,stderrTruncated})}});
 });
}

/** Re-checks scope on the executing host: the hostname must still resolve only to the pinned public set. */
async function scopedTarget(spec:ScanTaskSpec):Promise<PinnedTarget>{
 const url=new URL(spec.origin);
 if(!spec.pinnedAddresses.length||spec.pinnedAddresses.some(a=>blockedNetworkAddress(a)))throw new Error('Task carries no valid pinned public address');
 return revalidatePublicHttpTarget({url,addresses:spec.pinnedAddresses});
}

export async function runScanTask(spec:ScanTaskSpec):Promise<RawScanResult>{
 const t=await scopedTarget(spec);const startedAt=new Date().toISOString(),t0=Date.now();
 const base=(r:Omit<RawScanResult,'tool'|'startedAt'|'completedAt'>)=>({tool:spec.tool,startedAt,completedAt:new Date().toISOString(),...r});
 if(spec.tool==='http'){
  let status=0,headers:Record<string,string>={},error='';
  try{const r=await pinnedHttpGet(t,5000,{'User-Agent':'AegisGRC-Posture/1.0'});status=r.status;headers=Object.fromEntries(Object.entries(r.headers).map(([k,v])=>[k,Array.isArray(v)?v.join(', '):String(v??'')]))}
  catch(e:any){error=String(e?.message||e)}
  const exitCode=error||!status?1:0;
  return base({stdout:JSON.stringify({status,headers}),stderr:error,exitCode,timedOut:false,stdoutTruncated:false,stderrTruncated:false,durationMs:Date.now()-t0,egress:{mode:'PINNED_LOOKUP',pinnedAddress:pinnedAddress(t.addresses),hostname:t.url.hostname}});
 }
 if(spec.tool==='zap'){
  const mode=spec.options?.zapMode==='passive'?'passive':'active';
  const out=await zapScanPinned(t,mode);
  return {...base({stdout:JSON.stringify(out.result),stderr:'',exitCode:0,timedOut:false,stdoutTruncated:false,stderrTruncated:false,durationMs:Date.now()-t0,egress:{mode:'PINNED_FORWARD_PROXY',...out.egress}}),zapMode:mode};
 }
 if(spec.tool==='nmap'){
  const ip=pinnedAddress(t.addresses);const r=await runProcess('nmap',scannerArgs('nmap',t.url,{pinnedAddress:ip}));
  return base({...r,egress:{mode:'DIRECT_PINNED_IP',pinnedAddress:ip,hostname:t.url.hostname}});
 }
 const tool=spec.tool;
 const out=await withPinnedEgress(t,p=>runProcess(tool,scannerArgs(tool,t.url,{proxyUrl:p.proxyUrl})));
 return {...base({...out.result,egress:{mode:'PINNED_FORWARD_PROXY',...out.egress}}),...(tool==='nuclei'?{nucleiTemplates:nucleiTemplatesPin()}:{})};
}
