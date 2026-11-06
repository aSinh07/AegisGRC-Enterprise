import {readFileSync} from 'node:fs';
import net from 'node:net';

// Fixed, server-owned argument profiles for the URL scanners. No user-supplied flags.
// Every profile is pinned: nmap scans the validated IP address directly, and the HTTP
// scanners must send all traffic through the per-scan pinned egress proxy.

export type UrlScanner='nmap'|'wapiti'|'nuclei'|'sqlmap';
export const NUCLEI_TEMPLATES_DIR=process.env.NUCLEI_TEMPLATES_DIR||'/opt/nuclei-templates';

export function scannerArgs(tool:UrlScanner,url:URL,pin:{pinnedAddress?:string;proxyUrl?:string}):string[]{
 if(tool==='nmap'){
  const ip=pin.pinnedAddress;if(!ip||!net.isIP(ip))throw new Error('nmap requires the validated pinned IP address');
  return [...(net.isIP(ip)===6?['-6']:[]),'-sT','-sV','--version-light','-Pn','--top-ports','1000','--open','-oX','-',ip];
 }
 const proxy=pin.proxyUrl;if(!proxy||!/^http:\/\/127\.0\.0\.1:\d+$/.test(proxy))throw new Error(tool+' requires the pinned loopback egress proxy');
 if(tool==='wapiti')return ['-u',url.origin,'--scope','url','--max-scan-time','60','--flush-session','--proxy',proxy];
 // -pt http: only HTTP-protocol templates, because network/ssl templates open raw sockets that bypass the proxy.
 // -t + -duc: use the image's pinned template release and never update it at runtime.
 // -ni: no third-party interactsh (OAST) callbacks, so no scan data leaves the authorized scope.
 if(tool==='nuclei')return ['-u',url.origin,'-jsonl','-silent','-severity','info,low,medium,high,critical','-timeout','10','-retries','1','-proxy',proxy,'-pt','http','-t',NUCLEI_TEMPLATES_DIR,'-duc','-ni'];
 return ['-u',url.toString(),'--batch','--level=1','--risk=1','--threads=1','--timeout=10','--retries=1','--output-dir=/tmp/sqlmap','--proxy='+proxy];
}

/** The template release baked into the image (version + git commit), recorded in nuclei evidence. */
export function nucleiTemplatesPin(dir:string=NUCLEI_TEMPLATES_DIR):{version:string;commit:string}|{version:'UNPINNED';commit:null}{
 try{const [version,commit]=readFileSync(dir+'/.aegis-pin','utf8').trim().split(/\s+/);if(version&&/^[0-9a-f]{40}$/.test(commit||''))return {version,commit:commit!}}catch{}
 return {version:'UNPINNED',commit:null};
}
