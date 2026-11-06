// Compliance & SoA panel (Phase 2): framework coverage, evidence freshness, open risks, CAPA ageing,
// the Statement of Applicability with all five control gates (signed export), scan schedules and reminders.
(function(){
 'use strict';
 const $=id=>document.getElementById(id);
 function el(tag,attrs,text){const e=document.createElement(tag);for(const [k,v] of Object.entries(attrs||{}))e.setAttribute(k,v);if(text!=null)e.textContent=String(text);return e}
 function btn(label,cls,fn){const b=el('button',{class:'btn'+(cls?' '+cls:''),type:'button'},label);b.addEventListener('click',fn);return b}
 async function call(url,opt){const r=await fetch(url,Object.assign({credentials:'same-origin',headers:{'Content-Type':'application/json'}},opt||{}));let d={};try{d=await r.json()}catch{}if(!r.ok)throw new Error(d.error||('HTTP '+r.status));return d}
 const org=()=>(typeof activeGrcOrg!=='undefined'&&activeGrcOrg)||'';
 const scope=()=>(typeof activeGrcScope!=='undefined'&&activeGrcScope)||'';
 const assessment=()=>(typeof assessmentId!=='undefined'&&assessmentId)||'';
 const msg=t=>{const m=$('cpMsg');if(m)m.textContent=t};
 const base=()=>'/api/grc/organizations/'+encodeURIComponent(org());

 function ensurePanel(){
  let p=$('compliancePanel');if(p)return p;
  p=el('div',{id:'compliancePanel',class:'target-auth-panel lifecycle-panel',role:'dialog','aria-modal':'true','aria-labelledby':'cpTitle'});
  const card=el('div',{class:'target-auth-card lifecycle-card'});
  const head=el('div',{class:'lc-head'});head.append(el('h3',{id:'cpTitle'},'Compliance & Statement of Applicability'),btn('Refresh','alt',()=>refresh()),btn('Close','alt',()=>{p.hidden=true}));
  card.append(head,el('p',{id:'cpMsg',class:'muted','aria-live':'polite'}));
  for(const [id,title] of [['cpDash','Compliance dashboard'],['cpSoa','Statement of Applicability · five control gates'],['cpSched','Recurring scans'],['cpNotes','Reminders']]){const s=el('section',{class:'lc-section'});s.append(el('h4',{},title),el('div',{id}));card.append(s)}
  p.append(card);document.body.append(p);return p;
 }
 function stat(label,value,tone){const d=el('div',{class:'cp-stat'+(tone?' lc-'+tone:'')});d.append(el('strong',{},value),el('small',{class:'muted'},label));return d}
 async function renderDash(){
  const box=$('cpDash');box.replaceChildren();if(!org())return box.append(el('p',{class:'muted'},'Select an organization in Enterprise GRC.'));
  try{const d=await call(base()+'/compliance-dashboard');
   const row=el('div',{class:'cp-stats'});row.append(stat('Controls passing',d.controls.pass,'DONE'),stat('Conditional',d.controls.conditional,'WARNING'),stat('Action required',d.controls.actionRequired,'BLOCKED'),stat('Not applicable',d.controls.notApplicable));box.append(row);
   const fw=el('div',{class:'cp-bars'});
   for(const f of d.frameworks){const r=el('div',{class:'cp-bar'});r.append(el('span',{},f.framework+' '+f.version),el('meter',{min:'0',max:'100',value:String(f.coveragePercent),'aria-label':f.framework+' coverage'}),el('span',{class:'muted'},f.passing+'/'+f.inScope+' in-scope requirements ('+f.coveragePercent+'%)'));fw.append(r)}
   if(!d.frameworks.length)fw.append(el('p',{class:'muted'},'No scoped controls yet. Add controls to an active scope.'));box.append(fw);
   const ev=d.evidenceFreshness,cap=d.capaAgeing;
   box.append(el('p',{class:'muted'},'Evidence: '+ev.current+' current · '+ev.expiringIn30Days+' expiring in 30 days · '+ev.expired+' expired'));
   box.append(el('p',{class:'muted'},'Open risks: '+d.openRisksByRating.map(r=>r.rating+' '+r.open).join(' · ')));
   box.append(el('p',{class:'muted'},'CAPA ageing: 0–30d '+cap.d0_30+' · 31–60d '+cap.d31_60+' · 61–90d '+cap.d61_90+' · 90d+ '+cap.d90_plus+' · overdue '+cap.overdue));
  }catch(e){box.append(el('p',{class:'muted'},e.message))}
 }
 async function renderSoa(){
  const box=$('cpSoa');box.replaceChildren();if(!org()||!scope())return box.append(el('p',{class:'muted'},'Select an active scope in Enterprise GRC to generate the SoA.'));
  try{const s=await call(base()+'/scopes/'+encodeURIComponent(scope())+'/soa-gates');const gate=await call(base()+'/phase-two-gate');
   const bar=el('div',{class:'lc-head'});bar.append(el('span',{class:'chip lc-'+(gate.passed?'DONE':'PENDING')},'Phase 2 gate: '+(gate.passed?'PASSED':'NOT YET')),el('span',{class:'muted'},s.summary.total+' controls · PASS '+s.summary.pass+' · CONDITIONAL '+s.summary.conditional+' · ACTION_REQUIRED '+s.summary.actionRequired+' · N/A '+s.summary.notApplicable));
   for(const f of ['pdf','xlsx'])bar.append(btn('Export signed '+f.toUpperCase(),'alt',()=>{location.href=base()+'/scopes/'+encodeURIComponent(scope())+'/soa-gates.'+f;setTimeout(refresh,2500)}));
   box.append(bar);
   const table=el('table',{class:'cp-table'});const thead=el('tr',{});for(const h of ['Control','Status',...s.gateNames])thead.append(el('th',{scope:'col'},h));table.append(thead);
   for(const c of s.controls){const tr=el('tr',{});const name=el('td',{});name.append(el('strong',{},c.controlKey),el('br'),el('small',{class:'muted'},c.title));tr.append(name,el('td',{},c.status));
    for(const g of c.gates){const td=el('td',{class:'lc-'+(g.passed?'DONE':'BLOCKED'),title:g.reason});td.append(el('span',{'aria-hidden':'true'},g.passed?'✓ ':'✗ '),el('small',{},g.reason));tr.append(td)}table.append(tr)}
   const wrap=el('div',{class:'cp-scroll'});wrap.append(table);box.append(wrap,el('p',{class:'muted'},s.disclaimer));
  }catch(e){box.append(el('p',{class:'muted'},e.message))}
 }
 async function renderSched(){
  const box=$('cpSched');box.replaceChildren();if(!org())return;
  try{const rows=await call(base()+'/scan-schedules');
   for(const r of rows){const row=el('div',{class:'target-auth-row'});row.append(el('span',{class:'mono'},r.target),el('span',{class:'chip'},r.profile+' every '+r.interval_days+'d'),el('span',{class:'muted'},'next '+new Date(r.next_run_at).toLocaleString()+(r.last_result?' · last: '+r.last_result:'')),btn(r.enabled?'Pause':'Resume','alt',async()=>{try{await call(base()+'/scan-schedules/'+r.id+'/enabled',{method:'POST',body:JSON.stringify({enabled:!r.enabled})});renderSched()}catch(e){msg(e.message)}}));box.append(row)}
   if(!rows.length)box.append(el('p',{class:'muted'},'No recurring scans.'));
   if(assessment()){const prof=el('select',{'aria-label':'Profile'});for(const p of ['QUICK','STANDARD','DEEP'])prof.append(el('option',{value:p},p));const days=el('input',{type:'number',min:'1',max:'365',value:'7','aria-label':'Interval in days',class:'cp-days'});
    const f=el('div',{class:'lc-head'});f.append(el('span',{class:'muted'},'Schedule the current assessment:'),prof,days,el('span',{class:'muted'},'days'),btn('Add schedule','',async()=>{try{await call('/api/assessments/'+encodeURIComponent(assessment())+'/scan-schedules',{method:'POST',body:JSON.stringify({profile:prof.value,intervalDays:Number(days.value)})});msg('Recurring scan scheduled. Target authorization is re-checked on every run.');renderSched()}catch(e){msg(e.message)}}));box.append(f)}
  }catch(e){box.append(el('p',{class:'muted'},e.message))}
 }
 async function renderNotes(){
  const box=$('cpNotes');box.replaceChildren();if(!org())return;
  try{const rows=await call(base()+'/notifications?mine=1');if(!rows.length)return box.append(el('p',{class:'muted'},'No reminders for you.'));
   for(const n of rows.slice(0,30)){const row=el('div',{class:'target-auth-row'});row.append(el('span',{class:'chip'},n.kind.replace(/_/g,' ')),el('span',{},n.subject),el('small',{class:'muted'},new Date(n.created_at).toLocaleDateString()+' · email '+n.status));box.append(row)}
  }catch(e){box.append(el('p',{class:'muted'},e.message))}
 }
 async function refresh(){msg('');await Promise.all([renderDash(),renderSoa(),renderSched(),renderNotes()])}
 globalThis.openCompliance=function(){ensurePanel().hidden=false;refresh()};
})();
