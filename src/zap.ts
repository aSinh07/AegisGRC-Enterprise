import crypto from 'node:crypto';
import type { Finding,Severity } from './models.js';
import { mapFinding } from './grc.js';
import { withPinnedEgress,type PinnedTarget } from './pinned-egress.js';

const base=(process.env.ZAP_URL||'').replace(/\/$/,'');
const key=process.env.ZAP_API_KEY||'';
const pause=(ms:number)=>new Promise(r=>setTimeout(r,ms));

async function api(path:string,params:Record<string,string>={}){
 if(!base) throw new Error('OWASP ZAP is not configured');
 const q=new URLSearchParams({...params,apikey:key});
 const controller=new AbortController(); const timer=setTimeout(()=>controller.abort(),15000);
 try{const r=await fetch(base+path+'?'+q,{signal:controller.signal});if(!r.ok)throw new Error('ZAP HTTP '+r.status);return await r.json() as any}
 finally{clearTimeout(timer)}
}
export async function zapReady(){try{await api('/JSON/core/view/version/');return true}catch{return false}}
async function wait(path:string,id:string,limitMs=120000){const started=Date.now();while(Date.now()-started<limitMs){const d=await api(path,{scanId:id});const n=Number(d.status||0);if(n>=100)return;await pause(1500)}throw new Error('ZAP scan timed out')}
export async function zapScan(target:string){
 const spider=await api('/JSON/spider/action/scan/',{url:target,maxChildren:'20',recurse:'true',subtreeOnly:'true'});
 if(!spider.scan)throw new Error('ZAP spider did not start');await wait('/JSON/spider/view/status/',String(spider.scan),90000);
 const active=await api('/JSON/ascan/action/scan/',{url:target,recurse:'true',inScopeOnly:'false'});
 if(!active.scan)throw new Error('ZAP active scan did not start');await wait('/JSON/ascan/view/status/',String(active.scan),120000);
 const alerts=await api('/JSON/core/view/alerts/',{baseurl:target,start:'0',count:'500'});
 return Array.isArray(alerts.alerts)?alerts.alerts:[];
}
// ZAP runs in its own container and would otherwise resolve the target itself (DNS-rebinding
// window). Each scan points ZAP's upstream proxy at a per-scan pinned egress proxy in the
// app container. ZAP is a shared daemon, so pinned scans are serialized.
async function setZapUpstream(host:string,port:number,enabled:boolean){
 if(enabled)await api('/JSON/network/action/setHttpProxy/',{host,port:String(port),realm:'',username:'',password:''});
 await api('/JSON/network/action/setHttpProxyEnabled/',{enabled:String(enabled)});
}
let zapQueue:Promise<unknown>=Promise.resolve();
export function zapEgressProxyHost(env:NodeJS.ProcessEnv=process.env){return String(env.ZAP_EGRESS_PROXY_HOST||'').trim()}
export async function zapScanPinned(t:PinnedTarget){
 const host=zapEgressProxyHost();
 if(!host)throw new Error('ZAP_EGRESS_PROXY_HOST is not configured: ZAP scans fail closed without DNS-pinned egress');
 const job=()=>withPinnedEgress(t,async p=>{await setZapUpstream(host,p.port,true);try{return await zapScan(t.url.origin)}finally{await setZapUpstream('',0,false).catch(()=>{})}},{bindHost:'0.0.0.0'});
 const next=zapQueue.then(job,job);zapQueue=next.catch(()=>{});return next;
}
function sev(risk:string):Severity{const x=risk.toLowerCase();return x.includes('high')?'HIGH':x.includes('medium')?'MEDIUM':x.includes('low')?'LOW':'INFO'}
export function zapFindings(assessmentId:string,asset:string,evidenceHash:string,alerts:any[]):Finding[]{
 return alerts.map(a=>mapFinding({id:crypto.randomUUID(),assessmentId,source:'zap',title:String(a.alert||a.name||'ZAP alert'),description:String(a.description||a.evidence||'OWASP ZAP reported an alert.'),severity:sev(String(a.risk||a.riskdesc||'')),cwe:a.cweid&&String(a.cweid)!=='0'?'CWE-'+a.cweid:undefined,asset:String(a.url||asset),evidenceHash,createdAt:new Date().toISOString(),mappings:{owasp:[]},remediation:String(a.solution||a.reference||'Review the ZAP evidence and remediate the affected control.')}));
}
