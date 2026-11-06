// Target authorization panel: prove control of a hostname, then get a second-person approval.
// Opened from the Offensive gate, or automatically when the server answers
// TARGET_AUTHORIZATION_REQUIRED. Uses only same-origin JSON APIs and builds DOM nodes with textContent only.
(function(){
 'use strict';
 let ctx={orgId:'',targetUrl:''};
 const $=id=>document.getElementById(id);
 async function call(url,opt){const r=await fetch(url,Object.assign({credentials:'same-origin',headers:{'Content-Type':'application/json'}},opt||{}));let d={};try{d=await r.json()}catch{}if(!r.ok&&r.status!==409)throw new Error(d.error||('HTTP '+r.status));return {status:r.status,data:d}}
 function el(tag,attrs,text){const e=document.createElement(tag);for(const [k,v] of Object.entries(attrs||{}))e.setAttribute(k,v);if(text!=null)e.textContent=String(text);return e}
 function orgId(){return ctx.orgId||globalThis.activeGrcOrg||''}

 function ensurePanel(){
  let p=$('targetAuthPanel');if(p)return p;
  p=el('div',{id:'targetAuthPanel',class:'target-auth-panel',role:'dialog','aria-modal':'true','aria-labelledby':'targetAuthTitle'});
  const card=el('div',{class:'target-auth-card'});
  card.append(el('h3',{id:'targetAuthTitle'},'Target authorization'));
  card.append(el('p',{class:'muted'},'Scanning needs proof that your organization controls the hostname, plus approval from a GRC manager or org admin other than the requester.'));
  const form=el('div',{class:'target-auth-form'});
  const url=el('input',{id:'taUrl',class:'target',placeholder:'https://app.example.com','aria-label':'Target URL'});
  const method=el('select',{id:'taMethod','aria-label':'Verification method'});
  method.append(el('option',{value:'DNS_TXT'},'DNS TXT record'),el('option',{value:'HTTP_FILE'},'File at /.well-known/'));
  const just=el('input',{id:'taJustification',placeholder:'Engagement, ticket or contract reference','aria-label':'Justification'});
  const req=el('button',{class:'btn',type:'button'},'Request verification challenge');req.addEventListener('click',()=>requestChallenge());
  form.append(url,method,just,req);card.append(form);
  card.append(el('div',{id:'taChallenge',class:'target-auth-challenge',hidden:''}));
  card.append(el('p',{id:'taMsg',class:'muted','aria-live':'polite'}));
  card.append(el('h4',{},'Authorizations in this organization'));
  card.append(el('div',{id:'taList',class:'target-auth-list'}));
  const close=el('button',{class:'btn alt',type:'button'},'Close');close.addEventListener('click',()=>{p.hidden=true});
  card.append(close);p.append(card);document.body.append(p);return p;
 }
 function msg(t){const m=$('taMsg');if(m)m.textContent=t}
 function showChallenge(item){
  const box=$('taChallenge');box.replaceChildren();box.hidden=false;const c=item.challenge||{};
  box.append(el('strong',{},item.hostname+' · '+(c.method==='DNS_TXT'?'publish this DNS record':'serve this file')));
  const rows=c.method==='DNS_TXT'?[['Type','TXT'],['Name',c.recordName],['Value',c.recordValue]]:[['URL',c.url],['Exact content',c.fileContent]];
  const dl=el('dl',{});for(const [k,v] of rows){dl.append(el('dt',{},k),el('dd',{class:'mono'},v))}box.append(dl);
  const verify=el('button',{class:'btn',type:'button'},'Check verification now');verify.addEventListener('click',()=>verifyItem(item.id));box.append(verify);
 }
 async function requestChallenge(){
  try{if(!orgId())return msg('Select an organization in Enterprise GRC first.');
   const {data}=await call('/api/grc/organizations/'+encodeURIComponent(orgId())+'/target-authorizations',{method:'POST',body:JSON.stringify({targetUrl:$('taUrl').value,method:$('taMethod').value,justification:$('taJustification').value})});
   showChallenge(data);msg('Challenge created. Publish it, then check verification.');await refresh();
  }catch(e){msg(e.message)}
 }
 async function verifyItem(id){
  try{const {data}=await call('/api/grc/organizations/'+encodeURIComponent(orgId())+'/target-authorizations/'+encodeURIComponent(id)+'/verify',{method:'POST',body:'{}'});
   if(data.verified)msg('Ownership verified. A GRC manager or org admin other than you must now approve it.');
   else{msg('Not verified yet: the challenge value was not observed. DNS can take a few minutes to propagate.');if(data.challenge)showChallenge({id,hostname:'',challenge:data.challenge})}
   await refresh();
  }catch(e){msg(e.message)}
 }
 async function decide(id,decision){
  try{const note=decision==='REJECT'?(prompt('Reason for rejection')||''):'';await call('/api/grc/organizations/'+encodeURIComponent(orgId())+'/target-authorizations/'+encodeURIComponent(id)+'/decision',{method:'POST',body:JSON.stringify({decision,note})});msg('Decision recorded.');await refresh()}catch(e){msg(e.message)}
 }
 async function revoke(id){
  try{const reason=prompt('Reason for revoking this target authorization')||'';if(!reason)return;await call('/api/grc/organizations/'+encodeURIComponent(orgId())+'/target-authorizations/'+encodeURIComponent(id)+'/revoke',{method:'POST',body:JSON.stringify({reason})});msg('Authorization revoked. Scans of this target are now refused.');await refresh()}catch(e){msg(e.message)}
 }
 async function refresh(){
  const list=$('taList');if(!list||!orgId())return;
  try{const {data}=await call('/api/grc/organizations/'+encodeURIComponent(orgId())+'/target-authorizations');list.replaceChildren();
   if(data.mode==='attest')list.append(el('p',{class:'muted'},'This deployment runs in self-attestation mode; verification is recommended but not yet enforced.'));
   if(!data.items.length)list.append(el('p',{class:'muted'},'No target authorizations yet.'));
   for(const x of data.items){
    const row=el('div',{class:'target-auth-row'});
    const state=x.active?'APPROVED · expires '+new Date(x.expires_at).toLocaleDateString():x.status==='APPROVED'?'EXPIRED':x.status;
    row.append(el('span',{class:'mono'},x.hostname),el('span',{class:'chip'},state),el('span',{class:'muted'},x.method==='DNS_TXT'?'DNS TXT':'HTTP file'));
    if(x.status==='PENDING_VERIFICATION'){const b=el('button',{class:'btn alt',type:'button'},'Verify');b.addEventListener('click',()=>verifyItem(x.id));row.append(b)}
    if(x.status==='VERIFIED'&&data.canApprove&&x.requested_by!==data.userId){const a=el('button',{class:'btn',type:'button'},'Approve');a.addEventListener('click',()=>decide(x.id,'APPROVE'));const r=el('button',{class:'btn alt',type:'button'},'Reject');r.addEventListener('click',()=>decide(x.id,'REJECT'));row.append(a,r)}
    else if(x.status==='VERIFIED')row.append(el('span',{class:'muted'},'Awaiting approval by another manager'));
    if(data.canApprove&&['PENDING_VERIFICATION','VERIFIED','APPROVED'].includes(x.status)){const v=el('button',{class:'btn alt',type:'button'},'Revoke');v.addEventListener('click',()=>revoke(x.id));row.append(v)}
    list.append(row);
   }
  }catch(e){list.replaceChildren(el('p',{class:'muted'},e.message))}
 }
 function openTargetAuthorizations(prefill){
  const p=ensurePanel();p.hidden=false;
  if(prefill&&prefill.organizationId)ctx.orgId=prefill.organizationId;
  const t=(prefill&&prefill.targetUrl)||($('target')&&$('target').value)||'';if(t)$('taUrl').value=t;
  if(prefill&&prefill.code==='TARGET_AUTHORIZATION_REQUIRED')msg('This target is not yet verified and approved for scanning. Request a challenge below.');
  refresh();
 }
 globalThis.openTargetAuthorizations=openTargetAuthorizations;
})();
