import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

test('server applies baseline security headers without exposing framework banner',async()=>{
 const s=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');
 assert.match(s,/app\.disable\('x-powered-by'\)/);
 for(const header of ['Content-Security-Policy','X-Content-Type-Options','X-Frame-Options','Referrer-Policy','Permissions-Policy','Cross-Origin-Opener-Policy','Cross-Origin-Resource-Policy','Strict-Transport-Security'])assert.match(s,new RegExp(header));
});

test('only minimal readiness and authentication bootstrap routes bypass API authentication',async()=>{
 const s=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');
 const marker="app.use('/api',async(req,res,next)=>";
 const start=s.indexOf(marker);
 assert.notEqual(start,-1);
 const authMiddleware=s.slice(start,start+900);
 assert.match(authMiddleware,/\/ready/);
 assert.doesNotMatch(authMiddleware,/['"]\/health['"]/);
 assert.doesNotMatch(authMiddleware,/['"]\/integrations['"]/);
});


test('browser cross-site state changes are rejected before API handling',async()=>{
 const s=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');
 assert.match(s,/sec-fetch-site/);
 assert.match(s,/cross-site/);
 assert.match(s,/Cross-site state-changing requests are not allowed/);
 assert.match(s,/\['GET','HEAD','OPTIONS'\]/);
});


test('CSP denies dangerous embedding and external execution by default while inline migration remains explicit',async()=>{
 const s=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');
 const line=s.split('\n').find(x=>x.includes("Content-Security-Policy"))||'';
 for(const directive of ["default-src 'self'","object-src 'none'","frame-ancestors 'none'","base-uri 'self'","form-action 'self'","connect-src 'self'"]) assert.ok(line.includes(directive),directive+' missing');
 assert.ok(!/default-src[^;]*https?:/.test(line));
});


test('knowledge hub is strict-CSP ready with external scripts styles and delegated events',async()=>{
 const html=await readFile(new URL('../public/knowledge.html',import.meta.url),'utf8');
 const js=await readFile(new URL('../public/knowledge.js',import.meta.url),'utf8');
 assert.doesNotMatch(html,/<style\b/i);
 assert.doesNotMatch(html,/<script(?![^>]*\bsrc=)[^>]*>/i);
 assert.doesNotMatch(html,/\son[a-z]+\s*=/i);
 assert.doesNotMatch(html,/\sstyle\s*=/i);
 assert.match(html,/href="\/knowledge\.css"/);
 assert.match(html,/src="\/knowledge\.js"/);
 assert.match(js,/addEventListener\('click'/);
 assert.doesNotMatch(js,/onclick=/);
 assert.doesNotMatch(js,/style="/);
});


test('main dashboard keeps CSS external during CSP migration',async()=>{
 const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 const css=await readFile(new URL('../public/dashboard.css',import.meta.url),'utf8');
 assert.doesNotMatch(html,/<style\b/i);
 assert.match(html,/href="\/dashboard\.css"/);
 assert.ok(css.length>1000,'dashboard stylesheet should contain migrated CSS');
});


test('main dashboard keeps application JavaScript external during CSP migration',async()=>{
 const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 const js=await readFile(new URL('../public/dashboard.js',import.meta.url),'utf8');
 assert.doesNotMatch(html,/<script(?![^>]*\bsrc=)[^>]*>/i);
 assert.match(html,/src="\/dashboard\.js"/);
 assert.ok(js.length>10000,'dashboard application script should contain migrated JavaScript');
 for(const fn of ['confirmExport','cancelExport','openLearning','tab'])assert.match(js,new RegExp('function\\s+'+fn+'\\b'));
});


test('main dashboard static controls use delegated CSP-safe event metadata',async()=>{
 const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 const js=await readFile(new URL('../public/dashboard.js',import.meta.url),'utf8');
 const staticInline=[...html.matchAll(/\s(onclick|onchange)="([^"]*)"/gi)].filter(m=>!m[2].includes("'+"));
 assert.equal(staticInline.length,0,'static executable event attributes must not return');
 assert.match(html,/data-aegis-click=/);
 assert.match(html,/data-aegis-change=/);
 assert.match(js,/document\.addEventListener\('click'/);
 assert.match(js,/document\.addEventListener\('change'/);
 assert.match(js,/runAegisUiAction/);
});


test('dashboard contains no executable inline event handlers after CSP migration',async()=>{
 const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 const js=await readFile(new URL('../public/dashboard.js',import.meta.url),'utf8');
 const ops=await readFile(new URL('../public/enterprise-ops.js',import.meta.url),'utf8');
 assert.doesNotMatch(html,/\son[a-z]+\s*=/i);
 assert.doesNotMatch(js,/\son[a-z]+\s*=/i);
 assert.doesNotMatch(ops,/\son[a-z]+\s*=/i);
 assert.doesNotMatch(js,/\beval\s*\(/);
 assert.doesNotMatch(js,/\bFunction\s*\(/);
 for(const action of ['reviewPrivacyLegalEntry','advancePrivacyBreach','submitTprmQuestionnaire','runGrcTest','selectFramework','decideReview','securityAssessDoc']){
  assert.match(html+'\n'+js+'\n'+ops,new RegExp('data-action="'+action+'"'));
 }
});


test('global CSP forbids inline JavaScript while retaining temporary inline-style compatibility',async()=>{
 const server=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');
 const csp=server.match(/Content-Security-Policy',\"([^\"]+)\"/);
 assert.ok(csp,'CSP header must be configured');
 assert.match(csp[1],/script-src 'self';/);
 assert.doesNotMatch(csp[1],/script-src[^;]*'unsafe-inline'/);
 assert.match(csp[1],/style-src 'self' 'unsafe-inline'/);
});


test('main dashboard static markup contains no inline style attributes',async()=>{
 const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 const css=await readFile(new URL('../public/dashboard.css',import.meta.url),'utf8');
 assert.doesNotMatch(html,/\sstyle\s*=/i);
 for(const cls of ['u-mt-8','u-mt-12','u-w-full','u-justify-between','u-overflow-auto','u-table-full'])assert.match(css,new RegExp('\\.'+cls+'\\{'));
});


test('generated dashboard tables contain no inline style attributes',async()=>{
 const js=await readFile(new URL('../public/dashboard.js',import.meta.url),'utf8');
 assert.doesNotMatch(js,/style="/i);
 for(const cls of ['u-data-table','u-th','u-td','u-td-top','u-break-all'])assert.match(js,new RegExp('class="'+cls));
});


test('architecture workspace exposes synchronized CAD and 3D inspector UI',async()=>{
 const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 const js=await readFile(new URL('../public/architecture-3d.js',import.meta.url),'utf8');
 for(const id of ['architectureModelState','architectureComponentCount','architectureFlowCount','architectureInferenceCount','architectureInspectorTitle','architectureInspectorKind','architectureInspectorConfidence','architectureInspectorSource'])assert.match(html,new RegExp('id="'+id+'"'));
 assert.match(js,/function syncInspector\(/);
 assert.match(js,/function syncMetrics\(/);
 assert.match(js,/Synchronized selection across technical CAD and interactive 3D views/);
});


test('enterprise shell preserves navigation and exposes assurance context',async()=>{
 const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 for(const label of ['ENTERPRISE ASSURANCE','WORKSPACES','Protected session','ASSURANCE STATE','Evidence-first'])assert.match(html,new RegExp(label));
 for(const target of ['overview','offensive','defensive','grcops','evidence','architecture','grcreview','audittrace'])assert.match(html,new RegExp("tab\\('"+target+"'"));
 assert.match(html,/id="profileAvatar"/);
 assert.match(html,/id="profileMenu"/);
});


test('executive overview is summary-only while assessment intake lives in security workspaces',async()=>{
 const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 const overview=html.slice(html.indexOf('<section id="overview"'),html.indexOf('<section id="offensive"'));
 for(const id of ['risk','riskbar','count','state','integrations'])assert.match(overview,new RegExp('id="'+id+'"'));
 assert.doesNotMatch(overview,/id="target"|id="quickdoc"|authorize\(\)|scanQuickDoc\(\)/);
 for(const label of ['INTEGRATION ASSURANCE','Evidence before claims','MFA protected'])assert.match(html,new RegExp(label));
});


test('Enterprise GRC command center preserves governed operational modules',async()=>{
 const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 for(const label of ['Enterprise GRC Command Center','CONTROL','EVIDENCE','RISK','CAPA','REVIEW','Frameworks + SoA','Evidence + Testing','Risk + CAPA','TPRM + Privacy'])assert.ok(html.includes(label),label);
 for(const id of ['grcOrg','grcMetrics','grcScopes','grcSoa','grcEvidence','grcWork','enterpriseFrameworkSummary','grcControls','grcRemediation','tprmMetrics','privacyMetrics','grcTimeline'])assert.match(html,new RegExp('id="'+id+'"'));
});


test('offensive and defensive workspaces own their inputs and share evidence',async()=>{
 const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 const js=await readFile(new URL('../public/dashboard.js',import.meta.url),'utf8');
 for(const label of ['Scope → Discover → Validate → Evidence → Technical Report','Observe → Prioritize → Mitigate → Harden → Retest → Monitor','Evidence & Provenance Vault','INGEST','HASH','BIND','REVIEW'])assert.ok(html.includes(label),label);
 for(const id of ['target','auth','gate','offensiveDocs','offensiveCoverage','tool','findings','CRITICAL','HIGH','MEDIUM','LOW','INFO','defensiveTarget','defensiveDocs','defensiveReuse','defensivePlan','pie','bars','docs','doclist','raw'])assert.match(html,new RegExp('id="'+id+'"'));
 for(const action of ["scan()","authorizeDefensive()","loadDefensiveAnalysis()","uploadDocs()"])assert.ok(html.includes(action),action);
 assert.doesNotMatch(html.slice(html.indexOf('<section id="defensive"'),html.indexOf('<section id="incidents"')),/Dynamic GRC Report|Generate GRC View/);
 assert.match(js,/\/api\/assessments\/'\+assessmentId\+'\/security-workspace/);
 assert.match(js,/Re-upload required: NO/);
});


test('governed outputs review and audit UX preserve protected workflows',async()=>{
 const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 for(const label of ['Assurance Report Center','Framework Crosswalk Workspace','Consultant Review Center','Audit Evidence Chain','MFA EXPORT','HUMAN GOVERNANCE GATE'])assert.ok(html.includes(label),label);
 for(const id of ['fmt-grc','fmt-remediation','fmt-architecture','fmt-technical','fmt-executive','frameworkList','frameworkConsole','fwAssessment','reviewFramework','reviewQueue','auditTraceStats','auditTraceRows','breachImpactRows'])assert.match(html,new RegExp('id="'+id+'"'));
 for(const action of ["downloadKind('grc')","assessSelectedFramework()","submitCurrentForReview()","loadAuditTrace()","downloadAuditPackage('pdf')"])assert.ok(html.includes(action),action);assert.ok(!html.includes('Download Governed Report'));
});


test('enterprise finish layer includes accessibility responsive and reduced-motion states',async()=>{
 const css=await readFile(new URL('../public/dashboard.css',import.meta.url),'utf8');
 for(const token of [':focus-visible','prefers-reduced-motion','scrollbar-width','::selection','@media(max-width:560px)','--ui-accent'])assert.ok(css.includes(token),token);
 assert.match(css,/input:focus,select:focus,textarea:focus/);
 assert.match(css,/button:disabled,.btn:disabled/);
});


test('mobile navigation and AI assistant remain accessible and functional',async()=>{
 const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 const js=await readFile(new URL('../public/dashboard.js',import.meta.url),'utf8');
 const css=await readFile(new URL('../public/dashboard.css',import.meta.url),'utf8');
 for(const id of ['workspaceSidebar','mobileNavToggle','copilot','cpmode','voiceBtn','cpmsgs','cpq'])assert.match(html,new RegExp('id="'+id+'"'));
 assert.ok(html.includes('toggleMobileNav()'));
 assert.ok(js.includes('function toggleMobileNav(force)'));
 assert.ok(js.includes('toggleMobileNav(false)'));
 assert.ok(css.includes('.side.mobile-open'));
 assert.ok(css.includes('.copilot-controls'));
 assert.ok(html.includes('Context-aware workspace assistant'));
});


test('dashboard HTML has clean external-script boundaries and enterprise ops bundle',async()=>{
 const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 const ops=await readFile(new URL('../public/enterprise-ops.js',import.meta.url),'utf8');
 assert.equal((html.match(/<style\b/gi)||[]).length,0);
 assert.equal((html.match(/<script(?![^>]*\bsrc=)[^>]*>/gi)||[]).length,0);
 assert.equal((html.match(/<\/style>/gi)||[]).length,0);
 assert.ok(html.includes('<script src="/architecture-3d.js" defer></script>'));
 assert.ok(html.includes('<script src="/enterprise-ops.js"></script>'));
 for(const fn of ['loadPrivacyOps','loadTprm','createPrivacyBreach','createTprmRemediation'])assert.ok(ops.includes('function '+fn),fn);
 assert.ok(!html.includes('async function loadPrivacyOps'));
});

test('offensive workspace exposes real asset-aware operations without a second datastore',async()=>{const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8'),js=await readFile(new URL('../public/dashboard.js',import.meta.url),'utf8'),server=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');for(const id of ['securityAssetType','securityAssetKey','containerImageRef','prowlerFile','infraEvidenceFile'])assert.match(html,new RegExp('id="'+id+'"'));for(const fn of ['registerSecurityAsset','runContainerAssessment','importProwlerEvidence','importOperationalEvidence'])assert.match(js,new RegExp('function '+fn));assert.match(server,/\/api\/assessments\/:assessmentId\/security-assets/);assert.match(server,/\/api\/assessments\/:assessmentId\/security-coverage\/reconcile/);assert.match(js,/reconcileSecurityCoverage/);assert.match(js,/\/trivy-image/);assert.match(js,/\/prowler-report/);assert.match(html,/value="openvas-report"/);assert.match(html,/value="wazuh-report"/);assert.match(js,/assessmentId\+'\/\'\+kind/);assert.doesNotMatch(html,/Supabase|Neon|Firebase|MongoDB|Redis/);});

test('URL offensive workflow automatically runs full evidence assessment and presents CVSS truth states',async()=>{
 const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 const js=await readFile(new URL('../public/dashboard.js',import.meta.url),'utf8');
 const server=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');
 assert.match(html,/Authorize \+ Run Full URL Analysis/);
 assert.match(html,/id="urlAnalysisSummary"/);
 assert.match(js,/tool\.value='all';await scan\(\)/);
 assert.match(js,/highest\.toFixed\(1\)/);
 assert.match(js,/NOT ESTABLISHED/);
 assert.match(js,/async function pollFullAssessment/);
 assert.match(js,/server-side assessment accepted/);
 assert.match(js,/evidenceRows\.length\+' evidence record\(s\) rendered'/);
 assert.doesNotMatch(js,/raw\.textContent='FULL URL ASSESSMENT · '\+status/);
 assert.match(server,/const activeFullScans=new Map<string,Promise<void>>/);
 assert.match(server,/res\.status\(202\)\.json\(\{execution:'REAL_FULL_ASSESSMENT',status:'RUNNING'/);
 // Scanner argument profiles moved to src/scanner-args.ts (DNS-pinned: nmap by IP, HTTP scanners via the egress proxy).
 const scannerArgsSrc=await readFile(new URL('../src/scanner-args.ts',import.meta.url),'utf8');
 assert.match(scannerArgsSrc,/--top-ports','1000'/);
 assert.match(scannerArgsSrc,/tool==='nuclei'\)return \['-u',url\.origin,'-jsonl'/);
 assert.match(server,/run\(tool,scannerArgs\(tool,safeTarget\.url,\{proxyUrl:p\.proxyUrl\}\)\)/);
 assert.match(server,/tool==='sqlmap'\?sqlmapTextFindings/);
 const css=await readFile(new URL('../public/enhancements.css',import.meta.url),'utf8');
 assert.match(css,/Enterprise density \+ account placement v6/);
 assert.match(css,/\.top-actions\{order:2/);
});


test('authorized assessments are tenant-bound and access denials cannot crash async read routes',async()=>{
 const server=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');
 const store=await readFile(new URL('../src/store.ts',import.meta.url),'utf8');
 assert.match(server,/const u=await currentUser\(req\);if\(!u\)return res\.status\(401\)\.json\(\{error:'User session required'\}\);/);
 assert.match(server,/assessmentAuthorizationAllowed\(u\.userId/);
 assert.match(server,/if\(req\.body\?\.authorized!==true\)/);
 assert.match(server,/createdBy:u\.userId,organizationId:org\.id/);
 assert.match(server,/ASSESSMENT_AUTHORIZED',actor:u\.userId/);
 assert.match(store,/created_by,organization_id/);
 assert.match(store,/meta\.createdBy\|\|null,meta\.organizationId\|\|null/);
 for(const route of ["audit","evidence","documents"]){
  const marker="app.get('/api/assessments/:id/"+route+"'";
  const start=server.indexOf(marker);assert.ok(start>=0,marker);
  const block=server.slice(start,start+650);
  assert.match(block,/try\{/);
  assert.match(block,/catch\(e:any\)\{res\.status\(e\.statusCode\|\|400\)\.json/);
 }
});


test('offensive workspace renders persisted execution evidence during load and polling',async()=>{
 const ui=await readFile(new URL('../public/dashboard.js',import.meta.url),'utf8');
 assert.match(ui,/async function loadExecutionEvidence\(\)/);
 assert.match(ui,/\/api\/assessments\/'\+assessmentId\+'\/evidence/);
 assert.match(ui,/rows\.map\(evidenceView\)/);
 assert.match(ui,/await loadExecutionEvidence\(\);transientErrors=0/);
 assert.match(ui,/renderFindings\(r\.findings\|\|\[\]\);await loadExecutionEvidence\(\)/);
 assert.match(ui,/provenanceFingerprint/);
 assert.match(ui,/full record remains stored/);
 assert.match(ui,/const evidenceRows=await loadExecutionEvidence\(\)/);
 assert.match(ui,/evidenceRows\.length\+' evidence record\(s\) rendered'/);
 assert.match(ui,/if\(\['COMPLETED','PARTIAL','FAILED'\]\.includes\(status\)\)\{await loadExecutionEvidence\(\);await loadSecurityAssets\(\);return status\}/);
 assert.doesNotMatch(ui,/raw\.textContent='FULL URL ASSESSMENT · '\+status/);
});


test('professional security exports preserve report purpose and evidence boundaries',async()=>{
 const server=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');
 const pdf=await readFile(new URL('../src/pdf.ts',import.meta.url),'utf8');
 const exporters=await readFile(new URL('../src/exporters.ts',import.meta.url),'utf8');
 assert.match(server,/renderPdf\(a,fs,ev,kind\)/);
 assert.match(pdf,/Offensive Security Technical Assessment/);
 assert.match(pdf,/Tool Execution & Evidence Provenance/);
 assert.match(pdf,/Raw console output is supporting evidence, not the assessment narrative/);
 assert.match(pdf,/complete persisted evidence record remains in the AegisGRC evidence store/);
 assert.match(exporters,/Executive Security Summary/);
 assert.match(exporters,/Tool Execution & Coverage Matrix/);
 assert.match(exporters,/Professional Findings Register/);
 assert.match(exporters,/Detailed Technical Findings/);
 assert.match(exporters,/Remediation & Retest Criteria/);
 assert.match(exporters,/Evidence & Provenance Appendix/);
 assert.match(exporters,/Failed, unavailable and not-run paths are not treated as PASS/);
 assert.match(exporters,/Raw console output is supporting evidence rather than the report narrative/);
});


test('defensive workspace restores newest persisted authorized assessment without recreating scan authority',async()=>{
 const ui=await readFile(new URL('../public/dashboard.js',import.meta.url),'utf8');
 const store=await readFile(new URL('../src/store.ts',import.meta.url),'utf8');
 assert.match(store,/ORDER BY a\.authorized_at DESC/);
 assert.match(ui,/async function restoreLatestAssessment\(\)/);
 assert.match(ui,/const rows=await jf\('\/api\/assessments'\)/);
 assert.match(ui,/assessmentId=a\.id;targetOrigin=a\.target;sessionToken=null/);
 assert.match(ui,/await loadSecurityWorkspace\(\);await loadSecurityAssets\(\);await loadDefensiveAnalysis\(\)/);
 assert.match(ui,/await restoreLatestAssessment\(\)/);
});


test('security report visual system is structured and scanner runtime uses writable tool directories',async()=>{
 const pdf=await readFile(new URL('../src/pdf.ts',import.meta.url),'utf8');
 const server=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');
 assert.match(pdf,/SECURITY ASSESSMENT REPORT/);
 assert.match(pdf,/EVIDENCE ASSURANCE STATEMENT/);
 assert.match(pdf,/const section=/);
 assert.match(pdf,/const card=/);
 assert.match(pdf,/const tableRow=/);
 assert.match(pdf,/const badge=/);
 assert.match(pdf,/Professional Findings Register/);
 assert.match(pdf,/Evidence & Provenance Appendix/);
 assert.match(pdf,/Page '\+pageNo/);
 assert.match(server,/HOME:'\/tmp\/aegis-tools'/);
 assert.match(server,/XDG_CONFIG_HOME:'\/tmp\/aegis-tools\/config'/);
});


test('technical PDF derives final disposition from findings and execution coverage',async()=>{
 const pdf=await readFile(new URL('../src/pdf.ts',import.meta.url),'utf8');
 assert.match(pdf,/Technical Assessment Conclusion & Final Disposition/);
 assert.match(pdf,/FINAL DISPOSITION/);
 assert.match(pdf,/OVERALL SECURITY POSTURE/);
 assert.match(pdf,/COVERAGE & ASSURANCE LIMITATIONS/);
 assert.match(pdf,/FINAL TECHNICAL CONCLUSION/);
 assert.match(pdf,/RETEST \/ CLOSURE GATE/);
 assert.match(pdf,/failedEngines/);
 assert.match(pdf,/failure is not interpreted as PASS/);
 assert.match(pdf,/No breach, exploitation, data theft/);
});


test('defensive workspace renders shared evidence remediation workflow without GRC export',async()=>{
 const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 const ui=await readFile(new URL('../public/dashboard.js',import.meta.url),'utf8');
 const engine=await readFile(new URL('../src/security-operations.ts',import.meta.url),'utf8');
 const defensive=html.slice(html.indexOf('<section id="defensive"'),html.indexOf('<section id="incidents"'));
 assert.match(defensive,/Same evidence, no duplicate upload required/);
 assert.match(defensive,/Download Defensive Security Report/);
 assert.doesNotMatch(defensive,/downloadKind\('grc'\)/);
 assert.match(ui,/function renderDefensiveAnalysis\(d\)/);
 assert.match(ui,/Prioritized remediation & targeted retest/);
 assert.match(ui,/Detection & hardening guidance/);
 assert.match(ui,/Assurance boundary/);
 assert.match(engine,/A finding is not considered remediated until a successful targeted retest and governed closure/);
 assert.match(engine,/reuploadRequired:false/);
});


test('defensive PDF is a remediation deliverable rather than a renamed offensive report',async()=>{
 const pdf=await readFile(new URL('../src/pdf.ts',import.meta.url),'utf8');
 assert.match(pdf,/Defensive Security Remediation & Hardening Report/);
 assert.match(pdf,/Defensive Remediation Register/);
 assert.match(pdf,/Detailed Mitigation, Hardening & Retest Actions/);
 assert.match(pdf,/Prioritized Defensive Treatment & Retest Plan/);
 assert.match(pdf,/Defensive Security Conclusion & Residual-Risk Disposition/);
 assert.match(pdf,/RETEST \/ RESIDUAL-RISK CLOSURE GATE/);
});
