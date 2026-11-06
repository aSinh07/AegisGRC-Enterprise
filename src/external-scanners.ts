import {spawn} from 'node:child_process';
import crypto from 'node:crypto';
import net from 'node:net';

export type ExternalTool='testssl'|'lynis'|'grype'|'syft'|'kubescape'|'checkov'|'gitleaks';
const MAX=Number(process.env.EXTERNAL_SCANNER_MAX_BYTES||8*1024*1024);
const TIMEOUT=Number(process.env.EXTERNAL_SCANNER_TIMEOUT_MS||180000);

function safe(v:string,label:string){const x=String(v||'').trim();if(!x||x.length>500||/[;&|<>$\x00-\x1f]/.test(x))throw new Error('Invalid '+label);return x}
function workspace(v:string){const x=safe(v,'workspace path');if(!x.startsWith('/workspace/'))throw new Error('Scanner paths are restricted to /workspace mounts');return x}
function image(v:string){const x=safe(v,'image reference');if(!/^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,299}$/.test(x))throw new Error('Invalid image reference');return x}
export async function toolVersion(command:string,args:string[]=['--version']){return run(command,args,{tool:command,target:'version'},30000)}
export async function run(command:string,args:string[],meta:Record<string,unknown>,timeoutMs=TIMEOUT){
 return new Promise<any>((resolve)=>{const started=Date.now();let out='',err='',truncated=false,timedOut=false,settled=false;const p=spawn(command,args,{shell:false,stdio:['ignore','pipe','pipe']});
 const add=(base:string,d:Buffer)=>{const prior=Buffer.from(base,'utf8'),room=Math.max(0,MAX-prior.length);if(d.length>room)truncated=true;if(room===0)return base;return Buffer.concat([prior,d.subarray(0,room)]).toString('utf8')};
 const timer=setTimeout(()=>{timedOut=true;p.kill('SIGKILL')},timeoutMs);
 p.stdout?.on('data',(d:Buffer)=>out=add(out,d));p.stderr?.on('data',(d:Buffer)=>err=add(err,d));
 p.on('error',(e:any)=>{if(settled)return;settled=true;clearTimeout(timer);const raw=JSON.stringify({command,args,meta,error:String(e?.message||e)});resolve({execution:'REAL_TOOL_EXECUTION',tool:String(meta.tool||command),command,args,exitCode:null,stdout:out,stderr:err||String(e?.message||e),timedOut,truncated,state:'UNAVAILABLE',durationMs:Date.now()-started,evidence:{sha256:crypto.createHash('sha256').update(raw).digest('hex')}})});
 p.on('close',(code)=>{if(settled)return;settled=true;clearTimeout(timer);const state=timedOut?'TIMEOUT':truncated?'TRUNCATED':code===0?'SUCCESS':'FAILED';const raw=JSON.stringify({command,args,meta,stdout:out,stderr:err,exitCode:code,timedOut,truncated});resolve({execution:'REAL_TOOL_EXECUTION',tool:String(meta.tool||command),command,args,exitCode:code,stdout:out,stderr:err,timedOut,truncated,state,durationMs:Date.now()-started,evidence:{sha256:crypto.createHash('sha256').update(raw).digest('hex')},metadata:meta})});
 });
}
// --ip pins testssl to the validated address so it never re-resolves the hostname (DNS rebinding).
export const scanTls=(target:string,pinnedIp:string)=>{if(!net.isIP(pinnedIp))throw new Error('testssl requires the validated pinned IP address');return run('testssl.sh',['--jsonfile-pretty','/dev/stdout','--warnings','off','--ip',pinnedIp,safe(target,'TLS target')],{tool:'testssl',target,pinnedAddress:pinnedIp})};
export const scanHostHardening=(targetPath:string)=>run('lynis',['audit','system','--quick','--no-colors'],{tool:'lynis',target:workspace(targetPath)});
export const scanImageWithGrype=(imageRef:string)=>run('grype',[image(imageRef),'-o','json'],{tool:'grype',imageRef});
export const generateSbom=(target:string)=>run('syft',[target.startsWith('/workspace/')?workspace(target):image(target),'-o','cyclonedx-json'],{tool:'syft',target});
export const scanKubernetes=(targetPath:string)=>run('kubescape',['scan','framework','nsa','--format','json','--output','/dev/stdout',workspace(targetPath)],{tool:'kubescape',targetPath});
export const scanIac=(sourcePath:string)=>run('checkov',['-d',workspace(sourcePath),'-o','json','--quiet'],{tool:'checkov',sourcePath});
function redactGitleaksReport(raw:string){try{const parsed=JSON.parse(raw);if(!Array.isArray(parsed))return '[]';return JSON.stringify(parsed.map((x:any)=>({RuleID:String(x?.RuleID||x?.ruleID||'gitleaks'),Description:String(x?.Description||x?.description||'Secret detected'),File:String(x?.File||x?.file||''),StartLine:Number(x?.StartLine||x?.startLine||0)||undefined,EndLine:Number(x?.EndLine||x?.endLine||0)||undefined,Commit:String(x?.Commit||x?.commit||'')||undefined,Fingerprint:String(x?.Fingerprint||x?.fingerprint||'')||undefined}))) }catch{return '[]'}}
export async function scanSecrets(sourcePath:string){const out=await run('gitleaks',['detect','--source',workspace(sourcePath),'--report-format','json','--report-path','/dev/stdout','--no-banner','--exit-code','0'],{tool:'gitleaks',sourcePath});const redacted=redactGitleaksReport(out.stdout);return {...out,stdout:redacted,evidence:{sha256:crypto.createHash('sha256').update(JSON.stringify({tool:'gitleaks',sourcePath:workspace(sourcePath),stdout:redacted,stderr:out.stderr,exitCode:out.exitCode,timedOut:out.timedOut,truncated:out.truncated})).digest('hex')},metadata:{...out.metadata,secretsRedacted:true}}}
