import PDFDocument from 'pdfkit';
import {guardedDisposition} from './report-status.js';
import type {Assessment,Finding,Evidence} from './models.js';

const SEVERITIES=['CRITICAL','HIGH','MEDIUM','LOW','INFO'] as const;
function priority(s:string){return s==='CRITICAL'||s==='HIGH'?'P1':s==='MEDIUM'?'P2':'P3'}
function status(f:Finding){return String(f.status||'OBSERVED').replaceAll('_',' ')}
function refs(f:Finding){const m:any=f.mappings||{};return [...(m.owasp||[]),...(m.nist||m.nistCsf||[]),...(m.iso27001||[]),...(m.iso42001||[])].join(', ')||'N/A'}

export function renderDefensiveSecurityPdf(a:Assessment,fs:Finding[],ev:Evidence[]=[],trace:any=null){return new Promise<Buffer>((resolve,reject)=>{
 const d:any=new PDFDocument({size:'A4',margin:0,bufferPages:true,info:{Title:'AegisGRC Defensive Security Report',Author:'AegisGRC',Subject:'Evidence-driven defensive security remediation and verification report'}}),chunks:Buffer[]=[];d.on('data',(x:Buffer)=>chunks.push(x));d.on('end',()=>resolve(Buffer.concat(chunks)));d.on('error',reject);
 const ink='#222222',muted='#666666',navy='#17365D',cyan='#17365D',line='#555555',soft='#FFFFFF',tableBlue='#D9EAF7',green='#067647',amber='#B54708',red='#B42318';
 let sectionNo=0;
 const reportDate=new Date().toISOString().slice(0,10);const header=()=>{d.fillColor(muted).font('Times-Roman').fontSize(6.5).text('AEGISGRC DEFENSIVE SECURITY ASSESSMENT  |  CONFIDENTIAL',46,24,{width:503});d.x=46;};
 const page=()=>{d.addPage({size:'A4',margin:0});header();d.x=46;d.y=48;};
 const ensure=(h=80)=>{if(d.y+h>775)page()};
 const h1=(s:string)=>{ensure(55);sectionNo++;d.x=46;d.y+=8;d.fillColor(navy).font('Times-Bold').fontSize(14).text(sectionNo+'. '+s,46,d.y,{width:503,lineGap:1});d.y+=7};
 const subhead=(s:string)=>{ensure(34);d.x=46;d.y+=5;d.fillColor(navy).font('Times-Bold').fontSize(10).text(s,46,d.y,{width:503});d.y+=5};
 const p=(s:string)=>{d.x=46;d.fillColor(ink).font('Times-Roman').fontSize(9).text(s,46,d.y,{width:503,lineGap:1.5});};
 const label=(s:string)=>{d.x=46;d.fillColor(navy).font('Times-Bold').fontSize(8.5).text(s,46,d.y,{width:503});};
 const row=(cells:string[],widths:number[],header=false)=>{const hs=cells.map((x,i)=>d.font(header?'Times-Bold':'Times-Roman').fontSize(7).heightOfString(x,{width:widths[i]-10})+12),h=Math.max(25,...hs);ensure(h);const y=d.y;let x=46;cells.forEach((c,i)=>{d.rect(x,y,widths[i],h).fill(header?tableBlue:'#FFFFFF');d.strokeColor(line).lineWidth(.6).rect(x,y,widths[i],h).stroke();d.fillColor(ink).font(header?'Times-Bold':'Times-Roman').fontSize(7).text(c,x+5,y+6,{width:widths[i]-10});x+=widths[i]});d.x=46;d.y=y+h;};

 // Cover — intentionally mirrors the supplied white technical-report reference\n header();d.y=72;d.fillColor(navy).font('Times-Bold').fontSize(10).text('AEGISGRC DEFENSIVE SECURITY ASSESSMENT',46,d.y);d.moveDown(2.2);d.fillColor(navy).font('Times-Bold').fontSize(22).text('Updated Defensive Security Remediation',46,d.y,{width:503});d.moveDown(.25);d.fillColor(ink).font('Times-Roman').fontSize(11).text('Developer-readable remediation and retest plan',46,d.y,{width:503});d.moveDown(3);[['Assessment',a.id],['Target',a.target],['Assessment status',String(a.status)],['Authorized',String(a.authorizedAt)],['Generated',new Date().toISOString()],['Classification','Manager + Developer Technical Security Report']].forEach(([k,v])=>{const y=d.y;d.fillColor(muted).font('Times-Roman').fontSize(9).text(k,46,y,{width:120});d.fillColor(ink).font('Times-Bold').text(v,180,y,{width:360});d.y=Math.max(d.y,y+24)});d.moveDown(1.5);d.fillColor(navy).font('Times-Bold').fontSize(10).text('Assessment statement');d.moveDown(.35);p('This report is evidence-driven. It separates confirmed weaknesses from scanner observations, false positives, positive controls and unproven attack hypotheses. No breach, exploitation or data exfiltration is claimed unless persisted evidence demonstrates the impact. Missing or failed coverage is never interpreted as PASS.');\n page();

 h1('Document Control');
 row(['FIELD','VALUE'],[145,358],true);[['Document','Defensive Security Remediation & Verification Report'],['Assessment ID',a.id],['Target',a.target],['Classification','Confidential · Manager + Developer Technical Security Report'],['Assessment status',String(a.status)],['Authorization recorded',String(a.authorizedAt)],['Generated',new Date().toISOString()],['Evidence model','Persisted assessment evidence + governed analyst/retest trace']].forEach(x=>row(x,[145,358]));
 d.moveDown(.5);p('This document is a point-in-time security assessment record. Later configuration, asset, scanner, evidence, or finding changes require a new report snapshot.');

 h1('Defensive Summary');
 const open=fs.filter(f=>!['REMEDIATED','FALSE_POSITIVE'].includes(String(f.status||''))),critical=open.filter(f=>f.severity==='CRITICAL').length,high=open.filter(f=>f.severity==='HIGH').length;
 p('The current defensive posture contains '+open.length+' open evidence-backed finding(s), including '+critical+' critical and '+high+' high. Priority is assigned from persisted technical evidence. Closure remains evidence-gated: remediation requires a successful targeted retest against the same finding fingerprint; recommendations or automation cannot close a finding.');
 d.moveDown();label('Evidence sources');p([...new Set(ev.map(e=>String(e.source).toUpperCase()))].join(', ')||'No persisted scanner evidence');

 h1('System Architecture and Security Context');
 p('Authorized target: '+a.target+'. This report does not invent private architecture. Architecture, trust-boundary and technology conclusions require stored assessment evidence or uploaded architecture/configuration artifacts.');
 row(['LAYER / DOMAIN','DEFENSIVE SECURITY RELEVANCE'],[165,338],true);
 [['Web / API','Input handling, authentication/session controls, HTTP/TLS hardening, application exposure.'],['Network / Infrastructure','Ports, services, segmentation, host hardening and exposure.'],['Cloud / Identity','IAM, privilege, logging, encryption, storage and configuration posture.'],['Container / Supply Chain','Image/package vulnerabilities, SBOM, secrets, IaC and runtime hardening.'],['Endpoint / Detection','Endpoint telemetry, identity signals, detection and incident evidence.'],['Data / Database','Least privilege, access posture, encryption, service exposure and telemetry.']].forEach(x=>row(x,[165,338]));

 subhead('Assessment Scope and Coverage');
 p('Scope is limited to the authorized assessment target and persisted asset/evidence records. Capability support is not treated as proof that a control was executed for this assessment. Failed, missing, stale or unobserved coverage remains an explicit limitation.');
 row(['SCOPE ITEM','VALUE'],[165,338],true);[['Authorized target',a.target],['Persisted findings',String(fs.length)],['Persisted evidence records',String(ev.length)],['Open evidence-backed findings',String(open.length)],['Coverage interpretation','Authoritative assessment assurance only; capability presence is not PASS']].forEach(x=>row(x,[165,338]));

 h1('Findings Register');
 row(['ID','FINDING','EVIDENCE STATUS','RISK','CVSS','MAPPING'],[38,170,92,55,48,100],true);
 fs.forEach((f,i)=>row(['F-'+String(i+1).padStart(2,'0'),f.title,status(f),f.severity,String(f.cvss??'N/A'),refs(f)],[38,170,92,55,48,100]));
 d.moveDown(.5);p('A numeric CVSS value is shown only when normalized evidence supplies one. N/A is not a zero score and is not interpreted as PASS.');

 subhead('Detailed Finding Analysis');
 if(!fs.length)p('No persisted evidence-backed findings were recorded. This statement is not equivalent to vulnerability-free assurance; review the coverage and limitations sections.');
 fs.forEach((f,i)=>{ensure(150);const fid='F-'+String(i+1).padStart(2,'0');d.rect(46,d.y,503,26).fill(tableBlue);d.strokeColor(line).lineWidth(.6).rect(46,d.y,503,26).stroke();d.fillColor(navy).font('Times-Bold').fontSize(9).text(fid+' · '+f.severity+' · '+status(f),57,d.y+8,{width:480});d.y+=38;label(f.title);p(f.description||'No additional normalized finding description was persisted.');d.moveDown(.35);row(['ASSET','SOURCE','CONFIDENCE','CVSS'],[180,110,115,98],true);row([String(f.asset||'N/A'),String(f.source||'N/A').toUpperCase(),String(f.confidence||'N/A'),String(f.cvss??'N/A')],[180,110,115,98]);d.moveDown(.35);label('Control / vulnerability references');p([...(f.externalIds?.cve||[]),...(f.externalIds?.cwe||[]),refs(f)].filter(Boolean).join(', ')||'N/A');label('Evidence binding');p('SHA-256: '+String(f.evidenceHash||'N/A')+(f.fingerprint?' | Fingerprint: '+f.fingerprint:' | Fingerprint: not persisted'));label('Recommended mitigation');p(f.remediation||'Validate the affected defensive control and define a remediation appropriate to the authorized asset.');d.moveDown(.8)});

 h1('Developer Remediation Plan');
 row(['PRIORITY','ACTION','OWNER FOCUS','ACCEPTANCE EVIDENCE'],[60,205,95,143],true);
 fs.filter(f=>!['REMEDIATED','FALSE_POSITIVE'].includes(String(f.status||''))).forEach(f=>row([priority(f.severity),f.remediation||'Validate and remediate the affected defensive control.','Security / Platform','Successful same-source targeted retest bound to the same finding fingerprint, or governed residual-risk disposition.'],[60,205,95,143]));

 subhead('Remediation Priority and Ownership');
 row(['PRIORITY','SEVERITY','OPEN FINDINGS','RESPONSE EXPECTATION'],[70,85,90,258],true);(['P1','P2','P3'] as const).forEach(pr=>{const group=open.filter(f=>priority(f.severity)===pr);const sev=pr==='P1'?'CRITICAL / HIGH':pr==='P2'?'MEDIUM':'LOW / INFO';row([pr,sev,String(group.length),pr==='P1'?'Immediate engineering/security review; preserve evidence and retest after mitigation.':pr==='P2'?'Plan corrective action and evidence-backed retest.':'Track hardening or informational improvement according to risk context.'],[70,85,90,258])});
 p('Finding owners, due dates and risk acceptance remain governed workflow data. This report does not invent an owner or SLA when none is persisted.');

 h1('Verification Commands and Expected Evidence');
 p('Verification must be performed only against authorized assets. Retesting should repeat the originating defensive validation wherever possible and preserve the resulting evidence hash, scanner source, timestamp and finding fingerprint. A frontend refusal, recommendation, configuration change, or automated response alone does not prove remediation.');
 d.moveDown();row(['ENGINE / SOURCE','RECORDS','LAST EXIT','ASSURANCE'],[180,70,70,183],true);
 [...new Set(ev.map(e=>String(e.source).toUpperCase()))].forEach(src=>{const es=ev.filter(e=>String(e.source).toUpperCase()===src),last=es.at(-1);row([src,String(es.length),String(last?.exitCode??'N/A'),last?.exitCode===0?'Evidence recorded; interpret findings/coverage':'Failed/incomplete evidence must remain visible'],[180,70,70,183])});

 subhead('Retest Acceptance Criteria');
 row(['REQUIREMENT','ACCEPTANCE RULE'],[160,343],true);[['Authorization','Retest only the authorized assessment asset and registered inventory context.'],['Scanner provenance','Use the originating scanner/source where the governed workflow requires same-source verification.'],['Finding identity','The original vulnerability fingerprint must be absent from successful fresh evidence.'],['Freshness','Retest evidence must be newer than the original finding evidence.'],['Execution quality','Timeout, truncation, unavailable engine, malformed output or non-success execution cannot establish remediation.'],['Closure','REMEDIATED requires the server-governed analyst review gate; evidence capture alone cannot close the finding.']].forEach(x=>row(x,[160,343]));

 h1('Evidence Appendix');
 if(!ev.length)p('No persisted scanner evidence is available for this assessment.');
 ev.forEach((e,i)=>{ensure(75);label('E-'+String(i+1).padStart(2,'0')+' · '+String(e.source).toUpperCase());p('Recorded: '+e.createdAt+' | Exit: '+String(e.exitCode??'N/A'));d.fillColor(muted).fontSize(7).text('SHA-256: '+e.sha256);d.moveDown(.7)});

 subhead('Analyst Decisions and Targeted Retest Traceability');
 const chains=Array.isArray(trace?.chains)?trace.chains:[];if(!chains.length)p('No governed analyst/retest trace was available. Finding status alone is not treated as independent retest proof.');else chains.forEach((c:any)=>{const latest=Array.isArray(c.reviews)&&c.reviews.length?c.reviews[c.reviews.length-1]:null,retests=Array.isArray(c.retests)?c.retests:[];label((c.findingId||'Finding')+' · '+String(c.source||'unknown').toUpperCase()+' · '+(latest?.decision||'UNREVIEWED'));p('Targeted retests: '+retests.length+(latest?.rationale?' | Analyst rationale: '+latest.rationale:''));retests.forEach((r:any)=>p('Evidence '+r.evidence_id+' | '+r.scanner_source+' | fingerprint '+String(r.fingerprint||'').slice(0,24)+'… | '+String(r.created_at||''))) });
 subhead('Authoritative Assessment Coverage');
 const assurance=[['Infrastructure',trace?.infrastructureAssurance],['Endpoint',trace?.endpointAssurance],['Web',trace?.webAssurance],['API',trace?.apiAssurance],['Source Code',trace?.sourceCodeAssurance],['Dependencies',trace?.dependencyAssurance],['Container',trace?.containerAssurance],['Cloud',trace?.cloudAssurance],['Identity',trace?.identityAssurance],['Data Security',trace?.dataSecurityAssurance],['Privacy',trace?.privacyAssurance],['Attack Surface',trace?.attackSurfaceAssurance],['Breach Telemetry',trace?.breachTelemetryAssurance]];row(['LAYER','STATUS','EVIDENCE','ENGINES'],[135,90,70,208],true);assurance.forEach(([name,x]:any)=>{const y=x||{status:'NOT_STARTED',evidenceCount:0,engines:[],failureReasons:['Coverage record unavailable']};row([name,y.status,String(y.evidenceCount||0),(y.engines||[]).join(', ')||'None'],[135,90,70,208]);if(y.failureReasons?.length)p('Limitation: '+y.failureReasons.join('; '))});

 subhead('Residual Exposure and Limitations');
 const limitations=assurance.flatMap(([name,x]:any)=>{const y=x||{status:'NOT_STARTED',failureReasons:['Coverage record unavailable']};const reasons=Array.isArray(y.failureReasons)?y.failureReasons:[];return (String(y.status||'NOT_STARTED')==='COMPLETE'&&!reasons.length)?[]:[name+': '+String(y.status||'NOT_STARTED')+(reasons.length?' — '+reasons.join('; '):'')]} );
 if(!limitations.length)p('No assessment-layer coverage limitations were recorded in the authoritative trace. This does not imply absence of vulnerabilities outside the authorized scope or after the assessment time.');else limitations.forEach((x:string)=>p('• '+x));
 d.moveDown(.5);p('Residual exposure also includes accepted risk, unresolved findings, unobserved assets, scanner blind spots, and changes made after evidence collection.');

 h1('Management Conclusion');
 const guarded=guardedDisposition(a.status,critical||high?'REMEDIATION REQUIRED':open.length?'REMEDIATION / RETEST REQUIRED':'NO OPEN EVIDENCE-BACKED FINDINGS',critical||high?'RED':open.length?'AMBER':'GREEN',open.length);const disposition=guarded.text;const dispositionFill=guarded.tone==='RED'?'#FCE8E6':guarded.tone==='AMBER'?'#FFF4E5':'#E8F5E9',dispositionInk=guarded.tone==='RED'?red:guarded.tone==='AMBER'?'#B54708':green;
 d.rect(46,d.y,503,46).fill(dispositionFill);d.strokeColor(line).lineWidth(.6).rect(46,d.y,503,46).stroke();d.fillColor(dispositionInk).font('Times-Bold').fontSize(11).text(disposition,60,d.y+16,{width:475});d.y+=60;
 p('The conclusion is bounded by stored evidence and executed coverage. Findings must not be promoted to confirmed exploitation without evidence of impact. Unobserved surfaces and failed/not-run engines remain assurance limitations.');

 h1('Production Readiness: Defensive Controls Are Necessary but Not Sufficient');
 p('Individual hardening fixes do not establish complete production readiness. Defensive approval requires evidence across the relevant trust boundaries: exposed services, identity and privilege, application/tool authorization, telemetry, data access, infrastructure configuration and retest results.');
 
 h1('Production Readiness Checklist');
 row(['CATEGORY','CONTROL','CURRENT STATUS','REQUIRED NEXT STEP'],[110,145,105,143],true);
 const cats=[['HTTP / Application Hardening','Headers, TLS, input/session controls'],['Network Segmentation','Restricted services and unnecessary exposure'],['Identity / Least Privilege','Restricted human and service identities'],['Endpoint / Detection','Telemetry and detection coverage'],['Cloud / Container','Configuration, image and runtime posture'],['Data Security','Access, encryption and exposure controls'],['Observability','Traceable security-relevant events'],['Remediation Verification','Fingerprint-bound targeted retest']];
 const readinessCoverage:Record<string,any>={
 'HTTP / Application Hardening':trace?.webAssurance,
 'Network Segmentation':trace?.infrastructureAssurance,
 'Identity / Least Privilege':trace?.identityAssurance,
 'Endpoint / Detection':trace?.endpointAssurance,
 'Cloud / Container':{status:[trace?.cloudAssurance?.status,trace?.containerAssurance?.status].filter(Boolean).join(' / ')||'NOT_STARTED',evidenceCount:Number(trace?.cloudAssurance?.evidenceCount||0)+Number(trace?.containerAssurance?.evidenceCount||0),failureReasons:[...(trace?.cloudAssurance?.failureReasons||[]),...(trace?.containerAssurance?.failureReasons||[])]},
 'Data Security':trace?.dataSecurityAssurance,
 'Observability':trace?.breachTelemetryAssurance,
 'Remediation Verification':{status:chains.some((x:any)=>Array.isArray(x.retests)&&x.retests.length)?'EVIDENCE_RECORDED':'NOT_OBSERVED',evidenceCount:chains.reduce((n:number,x:any)=>n+(Array.isArray(x.retests)?x.retests.length:0),0),failureReasons:[]}
};cats.forEach(([cat,control])=>{const x=readinessCoverage[cat]||{status:'NOT_OBSERVED',evidenceCount:0,failureReasons:['Applicable authoritative coverage was not recorded']},state=String(x.status||'NOT_OBSERVED'),count=Number(x.evidenceCount||0),failed=(x.failureReasons||[]).length>0;const current=state+(count?' · '+count+' evidence':'')+(failed?' · LIMITATION':'');row([cat,control,current,state==='COMPLETE'||state==='EVIDENCE_RECORDED'?'Retain evidence and verify applicable open findings are dispositioned.':'Complete applicable coverage and retain successful evidence before approval.'],[110,145,105,143])});

 h1('Deployment Gate and Final Disposition');
 p('Recommended defensive deployment gate: critical/high evidence-backed findings are treated or explicitly accepted; failed/not-run coverage is visible; least-privilege and segmentation controls are validated where applicable; security telemetry is retained; and remediated findings have newer successful same-source retest evidence bound to the same vulnerability fingerprint. Final disposition: '+disposition+'.');
 d.moveDown();d.fillColor(navy).font('Times-Bold').fontSize(8.5).text('AUTOMATION AND ADVISORY BOUNDARY');p('Recommendations and automation are advisory unless backed by governed execution evidence. They cannot mark a finding remediated, manufacture successful evidence, or override the server-side closure gate.');

 const range=d.bufferedPageRange();for(let i=range.start;i<range.start+range.count;i++){d.switchToPage(i);header();d.save();d.rect(0,800,595.28,41.89).fill('#FFFFFF');d.fillColor(muted).font('Times-Roman').fontSize(7).text('AegisGRC  |  '+reportDate,46,812,{width:380,lineBreak:false});d.text('Page '+(i+1)+' of '+range.count,440,812,{width:109,align:'right',lineBreak:false});d.restore();}d.end();
})}
