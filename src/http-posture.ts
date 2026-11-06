import crypto from 'node:crypto';

// HTTP security-posture checks over one live response. Shared by the server's posture probe
// and by scan-job results returned from a scanner worker (which only returns raw headers).
export function httpPostureFindings(assessmentId:string,url:URL,headers:Record<string,string>,evidenceHash:string,createdAt=new Date().toISOString()){
 const checks=[
  {bad:url.protocol!=='https:',title:'Transport is not HTTPS',severity:'HIGH',cvss:7.4,desc:'The authorized target uses plaintext HTTP.',rem:'Enforce HTTPS and redirect HTTP to HTTPS.'},
  {bad:!headers['strict-transport-security']&&url.protocol==='https:',title:'HSTS header not observed',severity:'MEDIUM',cvss:5.3,desc:'Strict-Transport-Security was not observed in the live HTTP response.',rem:'Enable HSTS after validating HTTPS coverage.'},
  {bad:!headers['content-security-policy'],title:'Content Security Policy not observed',severity:'MEDIUM',cvss:5.3,desc:'Content-Security-Policy was not observed in the live HTTP response.',rem:'Deploy a restrictive CSP appropriate to the application.'},
  {bad:!headers['x-content-type-options'],title:'MIME sniffing protection not observed',severity:'LOW',cvss:3.1,desc:'X-Content-Type-Options was not observed.',rem:'Set X-Content-Type-Options: nosniff.'},
  {bad:!headers['x-frame-options']&&!String(headers['content-security-policy']||'').includes('frame-ancestors'),title:'Framing protection not observed',severity:'MEDIUM',cvss:4.3,desc:'Neither X-Frame-Options nor CSP frame-ancestors was observed.',rem:'Set CSP frame-ancestors or X-Frame-Options.'},
  {bad:Boolean(headers['server']),title:'Server technology disclosed',severity:'LOW',cvss:2.6,desc:'The live response exposes a Server header: '+String(headers['server']||''),rem:'Minimize unnecessary server banner disclosure.'}
 ] as const;

 return checks.filter(x=>x.bad).map(x=>({id:crypto.randomUUID(),assessmentId,source:'http' as const,title:x.title,description:x.desc,severity:x.severity,cvss:x.cvss,asset:url.origin,evidenceHash,createdAt,mappings:{owasp:['A05:2025 Security Misconfiguration'],nistCsf:['PR.PS']},remediation:x.rem,status:'OPEN' as const}));
}
