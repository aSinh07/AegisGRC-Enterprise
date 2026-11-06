import http from 'node:http';
import net from 'node:net';
import type {AddressInfo} from 'node:net';
import type {LookupFunction} from 'node:net';
import {blockedNetworkAddress} from './network-target.js';

// DNS-rebinding defence for active scanners.
//
// Scope validation resolves the target and blocks private/reserved addresses, but each
// scanner used to resolve the hostname again on its own. A hostile DNS server could
// answer the validation lookup with a public IP and the scanner's lookup with an
// internal one. Here every scanner HTTP(S) connection goes through a per-scan forward
// proxy that only accepts the authorized hostname and connects to the IP address that
// was validated. The scanner never resolves the target itself.

export type PinnedTarget={url:URL;addresses:string[]};
export type EgressRecord={pinnedAddress:string;hostname:string;allowedPorts:number[];allowed:number;denied:{target:string;reason:string}[]};

export function pinnedAddress(addresses:string[]){
 const ok=addresses.filter(a=>net.isIP(a)&&!blockedNetworkAddress(a));
 const v4=ok.find(a=>net.isIP(a)===4);const pick=v4||ok[0];
 if(!pick)throw new Error('No validated public address is available to pin the scan to');
 return pick;
}
export function allowedPorts(url:URL){return [...new Set([Number(url.port)||(url.protocol==='https:'?443:80),80,443])]}
const normalizeHost=(h:string)=>h.replace(/^\[|\]$/g,'').replace(/\.$/,'').toLowerCase();

/** Node lookup() that always answers with the pinned address (for in-process HTTP clients). */
export function pinnedLookup(t:PinnedTarget):LookupFunction{
 const ip=pinnedAddress(t.addresses),family=net.isIP(ip),host=normalizeHost(t.url.hostname);
 return ((hostname:string,options:any,cb:any)=>{
  if(typeof options==='function'){cb=options;options={}}
  if(normalizeHost(hostname)!==host)return cb(Object.assign(new Error('DNS lookup outside the authorized target is refused: '+hostname),{code:'EAEGISSCOPE'}));
  if(options?.all)return cb(null,[{address:ip,family}]);
  cb(null,ip,family);
 }) as LookupFunction;
}

export async function startPinnedEgressProxy(t:PinnedTarget,opts:{bindHost?:string}={}){
 return startProxyPinnedTo(pinnedAddress(t.addresses),t.url.hostname,allowedPorts(t.url),opts);
}
/** Proxy core. Callers must pass an address that already passed scope validation (see pinnedAddress). */
export async function startProxyPinnedTo(ip:string,hostname:string,ports:number[],opts:{bindHost?:string}={}){
 const host=normalizeHost(hostname);
 const record:EgressRecord={pinnedAddress:ip,hostname:host,allowedPorts:ports,allowed:0,denied:[]};
 const deny=(target:string,reason:string)=>{if(record.denied.length<100)record.denied.push({target,reason})};
 const check=(h:string,p:number)=>normalizeHost(h)!==host?'HOST_OUTSIDE_AUTHORIZED_SCOPE':!ports.includes(p)?'PORT_OUTSIDE_AUTHORIZED_SCOPE':null;
 const sockets=new Set<net.Socket>();
 const server=http.createServer((req,res)=>{
  // Plain-HTTP forward proxying: the request line carries an absolute URL.
  let u:URL;try{u=new URL(String(req.url))}catch{deny(String(req.url).slice(0,200),'NOT_ABSOLUTE_URL');res.writeHead(400).end();return}
  const port=Number(u.port)||80,why=u.protocol!=='http:'?'UNSUPPORTED_PROTOCOL':check(u.hostname,port);
  if(why){deny(u.host,why);res.writeHead(403,{'content-type':'text/plain'}).end('AegisGRC pinned egress: '+why);return}
  record.allowed++;
  const headers={...req.headers};delete headers['proxy-connection'];delete headers['proxy-authorization'];headers.host=u.host;
  const up=http.request({host:ip,port,method:req.method,path:u.pathname+u.search,headers,setHost:false},r=>{res.writeHead(r.statusCode||502,r.headers);r.pipe(res)});
  up.on('error',()=>{if(!res.headersSent)res.writeHead(502);res.end()});
  req.pipe(up);
 });
 server.on('connect',(req,client:net.Socket,head:Buffer)=>{
  // HTTPS tunnelling: CONNECT host:port. TLS (and SNI) stays end-to-end between the scanner and the target.
  sockets.add(client);client.on('close',()=>sockets.delete(client));client.on('error',()=>{});
  const m=/^(\[[^\]]+\]|[^:]+):(\d+)$/.exec(String(req.url||''));
  const why=!m?'MALFORMED_CONNECT':check(m[1],Number(m[2]));
  if(why||!m){deny(String(req.url).slice(0,200),why||'MALFORMED_CONNECT');client.end('HTTP/1.1 403 Forbidden\r\n\r\n');return}
  record.allowed++;
  const up=net.connect({host:ip,port:Number(m[2])},()=>{client.write('HTTP/1.1 200 Connection Established\r\n\r\n');if(head?.length)up.write(head);up.pipe(client);client.pipe(up)});
  sockets.add(up);up.on('close',()=>sockets.delete(up));
  up.on('error',()=>client.destroy());client.on('error',()=>up.destroy());
 });
 server.on('connection',s=>{sockets.add(s);s.on('close',()=>sockets.delete(s))});
 await new Promise<void>((resolve,reject)=>{server.once('error',reject);server.listen(0,opts.bindHost||'127.0.0.1',()=>resolve())});
 const port=(server.address() as AddressInfo).port;
 return {port,proxyUrl:'http://127.0.0.1:'+port,record,
  close:()=>new Promise<void>(r=>{for(const s of sockets)s.destroy();server.close(()=>r())})};
}

/** Runs fn with a pinned proxy and always tears it down; returns fn's result plus the egress record. */
export async function withPinnedEgress<T>(t:PinnedTarget,fn:(proxy:{proxyUrl:string;port:number;pinnedAddress:string})=>Promise<T>,opts:{bindHost?:string}={}){
 const p=await startPinnedEgressProxy(t,opts);
 try{const result=await fn({proxyUrl:p.proxyUrl,port:p.port,pinnedAddress:p.record.pinnedAddress});return {result,egress:p.record}}
 finally{await p.close()}
}

/** Single GET to the authorized origin over the pinned address (no redirects followed). */
export async function pinnedHttpGet(t:PinnedTarget,timeoutMs:number,headers:Record<string,string>={},opts:{path?:string;maxBodyBytes?:number}={}){
 const https=await import('node:https');
 const lib=t.url.protocol==='https:'?https:http;
 const path=opts.path||'/',max=Math.max(0,opts.maxBodyBytes||0);
 return new Promise<{status:number;headers:Record<string,string|string[]|undefined>;body:string}>((resolve,reject)=>{
  const req=lib.request({protocol:t.url.protocol,hostname:t.url.hostname,port:Number(t.url.port)||undefined,path,method:'GET',headers,lookup:pinnedLookup(t),servername:t.url.hostname,timeout:timeoutMs},res=>{
   if(!max){res.resume();resolve({status:res.statusCode||0,headers:res.headers,body:''});return}
   const chunks:Buffer[]=[];let n=0;
   res.on('data',(d:Buffer)=>{if(n<max){chunks.push(d.subarray(0,max-n));n+=d.length}if(n>=max)res.destroy()});
   const done=()=>resolve({status:res.statusCode||0,headers:res.headers,body:Buffer.concat(chunks).toString('utf8')});
   res.on('end',done);res.on('close',done);
  });
  req.on('timeout',()=>req.destroy(Object.assign(new Error('HTTP posture probe exceeded '+(timeoutMs/1000)+'s'),{name:'AbortError'})));
  req.on('error',reject);req.end();
 });
}
