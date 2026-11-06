// Governed lifecycle panel: the 12-step flow from the target architecture, per finding,
// plus deep-scan approvals, scan-job progress, the promotion policy and the Phase 1 gate.
// Reads only stored records through the API. DOM is built with textContent (no HTML injection).
(function(){
 'use strict';
 const $=id=>document.getElementById(id);
 const STATE_LABEL={DONE:'Done',PENDING:'Pending',BLOCKED:'Blocked',NOT_APPLICABLE:'N/A',WARNING:'Check'};
 function el(tag,attrs,text){const e=document.createElement(tag);for(const [k,v] of Object.entries(attrs||{}))e.setAttribute(k,v);if(text!=null)e.textContent=String(text);return e}
 function btn(label,cls,fn){const b=el('button',{class:'btn'+(cls?' '+cls:''),type:'button'},label);b.addEventListener('click',fn);return b}
 async function call(url,opt){const r=await fetch(url,Object.assign({credentials:'same-origin',headers:{'Content-Type':'application/json'}},opt||{}));let d={};try{d=await r.json()}catch{}if(!r.ok)throw new Error(d.error||('HTTP '+r.status));return d}
 // assessmentId and activeGrcOrg are top-level `let` bindings in dashboard.js (shared by name, not on globalThis).
 const currentAssessment=()=>(typeof assessmentId!=='undefined'&&assessmentId)||'';
 const currentOrg=()=>(typeof activeGrcOrg!=='undefined'&&activeGrcOrg)||'';
 const msg=t=>{const m=$('lcMsg');if(m)m.textContent=t};

 function ensurePanel(){
  let p=$('lifecyclePanel');if(p)return p;
  p=el('div',{id:'lifecyclePanel',class:'target-auth-panel lifecycle-panel',role:'dialog','aria-modal':'true','aria-labelledby':'lcTitle'});
  const card=el('div',{class:'target-auth-card lifecycle-card'});
  const head=el('div',{class:'lc-head'});head.append(el('h3',{id:'lcTitle'},'Governed lifecycle'),btn('Refresh','alt',()=>refresh()),btn('Close','alt',()=>{p.hidden=true}));
  card.append(head,el('p',{class:'muted'},'No finding closes and no report signs without fresh evidence. Each step is marked done only when its record exists.'));
  card.append(el('p',{id:'lcMsg',class:'muted','aria-live':'polite'}));
  for(const [id,title] of [['lcGate','Phase 1 evidence gate'],['lcApprovals','Deep scans awaiting approval'],['lcJobs','Scan jobs for this assessment'],['lcPolicy','Automatic issue, risk and CAPA'],['lcFindings','Findings through the lifecycle']]){const s=el('section',{class:'lc-section'});s.append(el('h4',{},title),el('div',{id}));card.append(s)}
  p.append(card);document.body.append(p);return p;
 }

 async function renderGate(){
  const box=$('lcGate');box.replaceChildren();if(!currentOrg())return box.append(el('p',{class:'muted'},'Select an organization in Enterprise GRC.'));
  try{const g=await call('/api/grc/organizations/'+encodeURIComponent(currentOrg())+'/lifecycle-gate');
   box.append(el('span',{class:'chip lc-'+(g.passed?'DONE':'PENDING')},g.passed?'PASSED':'NOT YET'),el('span',{class:'muted'},g.passed?' Finding '+g.findingId+' completed all 12 steps with a signed report.':' '+g.requirement));
  }catch(e){box.append(el('p',{class:'muted'},e.message))}
 }
 async function renderApprovals(){
  const box=$('lcApprovals');box.replaceChildren();if(!currentOrg())return;
  try{const d=await call('/api/grc/organizations/'+encodeURIComponent(currentOrg())+'/scan-approvals');
   if(!d.items.length)return box.append(el('p',{class:'muted'},'Nothing waiting.'));
   for(const j of d.items){const row=el('div',{class:'target-auth-row'});row.append(el('span',{class:'mono'},j.origin),el('span',{class:'chip'},j.profile),el('span',{class:'muted'},new Date(j.created_at).toLocaleString()));
    if(d.canApprove&&j.requested_by!==d.userId)row.append(btn('Approve','',()=>decide(j.id,'APPROVE')),btn('Reject','alt',()=>decide(j.id,'REJECT')));
    else row.append(el('span',{class:'muted'},j.requested_by===d.userId?'You requested this; another approver must sign off':'Needs an org admin or GRC manager'));
    box.append(row)}
  }catch(e){box.append(el('p',{class:'muted'},e.message))}
 }
 async function decide(id,decision){try{const note=decision==='REJECT'?(prompt('Reason for rejecting this deep scan')||''):'';await call('/api/scan-jobs/'+encodeURIComponent(id)+'/decision',{method:'POST',body:JSON.stringify({decision,note})});msg('Decision recorded.');await refresh()}catch(e){msg(e.message)}}
 async function renderJobs(){
  const box=$('lcJobs');box.replaceChildren();const a=currentAssessment();if(!a)return box.append(el('p',{class:'muted'},'Authorize a target in Offensive Security to start an assessment.'));
  try{const d=await call('/api/assessments/'+encodeURIComponent(a)+'/scan-jobs');
   if(!d.jobs.length)return box.append(el('p',{class:'muted'},'No queued scan jobs yet. Choose a profile in Offensive Security and run it.'));
   for(const j of d.jobs.slice(0,5)){const row=el('div',{class:'lc-job'});row.append(el('strong',{},j.profile+' · '+j.status),el('span',{class:'muted'},' '+new Date(j.created_at).toLocaleString()));
    const tasks=el('div',{class:'lc-tasks'});for(const t of j.tasks){tasks.append(el('span',{class:'chip lc-'+(t.state==='SUCCEEDED'?'DONE':['FAILED','TIMEOUT','CANCELLED'].includes(t.state)?'BLOCKED':'PENDING'),title:t.error||''},t.tool+(t.options&&t.options.zapMode?' ('+t.options.zapMode+')':'')+': '+t.state))}
    row.append(tasks);box.append(row)}
  }catch(e){box.append(el('p',{class:'muted'},e.message))}
 }
 async function renderPolicy(){
  const box=$('lcPolicy');box.replaceChildren();if(!currentOrg())return;
  try{const {policy}=await call('/api/grc/organizations/'+encodeURIComponent(currentOrg())+'/promotion-policy');
   const on=el('input',{type:'checkbox',id:'lcPolicyOn'});on.checked=Boolean(policy.enabled);
   const sev=el('select',{id:'lcPolicySev','aria-label':'Minimum severity'});for(const s of ['CRITICAL','HIGH','MEDIUM','LOW']){const o=el('option',{value:s},s+' and above');if(s===policy.min_severity)o.selected=true;sev.append(o)}
   const lab=el('label',{class:'lc-inline'});lab.append(on,el('span',{},' Confirmed findings automatically raise an issue, a draft risk and a CAPA'));
   box.append(lab,sev,btn('Save policy','',async()=>{try{await call('/api/grc/organizations/'+encodeURIComponent(currentOrg())+'/promotion-policy',{method:'PUT',body:JSON.stringify({enabled:on.checked,minSeverity:sev.value})});msg('Promotion policy saved. Automation runs under your authority.')}catch(e){msg(e.message)}}));
  }catch(e){box.append(el('p',{class:'muted'},e.message))}
 }
 async function renderFindings(){
  const box=$('lcFindings');box.replaceChildren();const a=currentAssessment();if(!a)return;
  try{const d=await call('/api/grc/assessments/'+encodeURIComponent(a)+'/lifecycle');
   box.append(el('p',{class:'muted'},d.summary.findings+' finding(s) · '+d.summary.canonical+' unique · '+d.summary.closedAndReported+' closed and reported · '+d.summary.falsePositives+' false positive(s)'));
   const list=d.findings.filter(f=>!f.duplicateOf).slice(0,50);
   for(const f of list){
    const item=el('details',{class:'lc-finding'});const sum=el('summary',{});
    const done=f.steps.filter(s=>s.state==='DONE'||s.state==='NOT_APPLICABLE').length;
    sum.append(el('span',{class:'chip'},f.severity),el('span',{},' '+f.title+' '),el('span',{class:'muted'},'('+f.source+') · '+done+'/12'));item.append(sum);
    const ol=el('ol',{class:'lc-steps'});
    for(const s of f.steps){const li=el('li',{class:'lc-step lc-'+s.state});li.append(el('strong',{},s.title),el('span',{class:'chip lc-'+s.state},STATE_LABEL[s.state]||s.state));if(s.note)li.append(el('small',{class:'muted'},s.note));ol.append(li)}
    item.append(ol);box.append(item);
   }
  }catch(e){box.append(el('p',{class:'muted'},e.message))}
 }
 async function refresh(){msg('');await Promise.all([renderGate(),renderApprovals(),renderJobs(),renderPolicy(),renderFindings()])}
 function openLifecycle(){const p=ensurePanel();p.hidden=false;refresh()}
 globalThis.openLifecycle=openLifecycle;
})();
