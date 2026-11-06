import {pool} from './db-pool.js';
import {requireOrgPermission} from './grc-organizations.js';

// Statement of Applicability with the five control gates from the target architecture.
// A control reports PASS only when all five gates hold:
//  1. Applicability decided, with justification, approved by someone other than the owner.
//  2. Implementation status recorded (IMPLEMENTED) with an accountable control owner.
//  3. Current evidence linked and independently validated (validator ≠ submitter, not expired),
//     or an independently reviewed CAPA-closure retest linked to the control.
//  4. The latest deterministic control test passes.
//  5. No related open risk, issue or CAPA.
// Until then the control is ACTION_REQUIRED (gate 1 or 2 fails, or an overdue CAPA) or CONDITIONAL.

export type GateResult={gate:1|2|3|4|5;name:string;passed:boolean;reason:string};
export type ControlGateStatus='PASS'|'CONDITIONAL'|'ACTION_REQUIRED'|'NOT_APPLICABLE';
export const GATE_NAMES=['Applicability approved','Implementation recorded','Evidence validated','Control test passing','Risks and CAPA closed'] as const;

export type GateInputs={
 applicability:string;justification:string|null;approvedBy:string|null;ownerUserId:string|null;implementation:string;
 evidence:{validatedBy:string|null;submittedBy:string|null;validUntil:string|null;status:string}[];
 closureEvidence:number;latestTest:{result:string;executedAt:string}|null;
 openIssues:number;openCapa:number;overdueCapa:number;openRisks:number;now?:Date;
};

export function evaluateControlGates(x:GateInputs):{status:ControlGateStatus;gates:GateResult[]}{
 const now=x.now||new Date();
 const g1ok=x.applicability!=='PENDING'&&String(x.justification||'').trim().length>=5&&Boolean(x.approvedBy)&&x.approvedBy!==x.ownerUserId;
 const g1:GateResult={gate:1,name:GATE_NAMES[0],passed:g1ok,reason:g1ok?'Approved by an independent approver':x.applicability==='PENDING'?'Applicability not decided':!String(x.justification||'').trim()?'Justification missing':!x.approvedBy?'Not approved':'Approved by the control owner (needs someone else)'};
 if(g1ok&&x.applicability==='NOT_APPLICABLE')return {status:'NOT_APPLICABLE',gates:[g1,...[2,3,4,5].map(n=>({gate:n as 2|3|4|5,name:GATE_NAMES[n-1],passed:true,reason:'Not applicable (approved exclusion)'}))]};
 const g2ok=x.implementation==='IMPLEMENTED'&&Boolean(x.ownerUserId);
 const g2:GateResult={gate:2,name:GATE_NAMES[1],passed:g2ok,reason:g2ok?'Implemented, owner assigned':!x.ownerUserId?'No control owner':'Implementation is '+x.implementation};
 const current=x.evidence.filter(e=>e.status==='VALID'&&e.validatedBy&&e.validatedBy!==e.submittedBy&&(!e.validUntil||new Date(e.validUntil)>now));
 const g3ok=current.length>0||x.closureEvidence>0;
 const expired=x.evidence.some(e=>e.validUntil&&new Date(e.validUntil)<=now);
 const g3:GateResult={gate:3,name:GATE_NAMES[2],passed:g3ok,reason:g3ok?(current.length?current.length+' current, independently validated evidence item(s)':'Independently reviewed closure retest linked'):expired?'Evidence expired':x.evidence.length?'Evidence not independently validated':'No evidence linked'};
 const g4ok=x.latestTest?.result==='PASS';
 const g4:GateResult={gate:4,name:GATE_NAMES[3],passed:g4ok,reason:x.latestTest?'Latest test '+x.latestTest.result:'No control test run'};
 const g5ok=x.openIssues===0&&x.openCapa===0&&x.openRisks===0;
 const g5:GateResult={gate:5,name:GATE_NAMES[4],passed:g5ok,reason:g5ok?'Nothing open':[x.openIssues&&x.openIssues+' open issue(s)',x.openCapa&&x.openCapa+' open CAPA',x.openRisks&&x.openRisks+' open risk(s)'].filter(Boolean).join(', ')};
 const gates=[g1,g2,g3,g4,g5];
 const status:ControlGateStatus=gates.every(g=>g.passed)?'PASS':(!g1ok||!g2ok||x.overdueCapa>0)?'ACTION_REQUIRED':'CONDITIONAL';
 return {status,gates};
}

export async function soaWithGates(userId:string,orgId:string,scopeId:string){
 await requireOrgPermission(userId,orgId,'read');
 const scope=(await pool.query('SELECT id,name,status FROM grc_scopes WHERE id=$1 AND organization_id=$2',[scopeId,orgId])).rows[0];
 if(!scope)throw Object.assign(new Error('Scope not found'),{statusCode:404});
 const rows=(await pool.query(`SELECT sc.id,sc.applicability,sc.applicability_justification,sc.implementation,sc.owner_user_id,sc.approved_by,sc.approved_at,sc.related_risk_ids,sc.evidence_refs,c.control_key,c.title,c.domain,
  COALESCE((SELECT json_agg(json_build_object('framework',fr.framework,'version',fr.framework_version,'key',fr.requirement_key,'title',fr.title) ORDER BY fr.framework,fr.requirement_key) FROM grc_control_framework_mappings m JOIN grc_framework_requirements fr ON fr.id=m.requirement_id WHERE m.control_id=c.id AND fr.active),'[]'::json) AS mappings
  FROM grc_scope_controls sc JOIN grc_canonical_controls c ON c.id=sc.control_id WHERE sc.organization_id=$1 AND sc.scope_id=$2 ORDER BY c.control_key`,[orgId,scopeId])).rows;
 const ids=rows.map((r:any)=>r.id);
 const ev=ids.length?(await pool.query(`SELECT r.scope_control_id,v.validated_by,v.submitted_by,v.valid_until,r.status FROM grc_evidence_requests r JOIN grc_evidence_versions v ON v.evidence_request_id=r.id WHERE r.scope_control_id=ANY($1::uuid[])`,[ids])).rows:[];
 const tests=ids.length?(await pool.query(`SELECT DISTINCT ON (d.scope_control_id) d.scope_control_id,r.result,r.executed_at FROM grc_control_test_definitions d JOIN grc_control_test_runs r ON r.test_definition_id=d.id WHERE d.scope_control_id=ANY($1::uuid[]) AND d.active ORDER BY d.scope_control_id,r.executed_at DESC`,[ids])).rows:[];
 const issues=ids.length?(await pool.query(`SELECT i.scope_control_id,count(*) FILTER (WHERE i.status<>'CLOSED') AS open_issues,
  count(c.id) FILTER (WHERE c.status<>'CLOSED') AS open_capa,count(c.id) FILTER (WHERE c.status<>'CLOSED' AND c.due_at<now()) AS overdue_capa
  FROM grc_issues i LEFT JOIN grc_capa c ON c.issue_id=i.id WHERE i.scope_control_id=ANY($1::uuid[]) GROUP BY i.scope_control_id`,[ids])).rows:[];
 const riskIds=[...new Set(rows.flatMap((r:any)=>Array.isArray(r.related_risk_ids)?r.related_risk_ids.map(String):[]))];
 const openRisks=riskIds.length?new Set((await pool.query(`SELECT id::text FROM grc_enterprise_risks WHERE id::text=ANY($1::text[]) AND status NOT IN ('ACCEPTED','CLOSED')`,[riskIds])).rows.map((r:any)=>r.id)):new Set<string>();
 const controls=rows.map((r:any)=>{
  const iss=issues.find((x:any)=>x.scope_control_id===r.id);const t=tests.find((x:any)=>x.scope_control_id===r.id);
  const out=evaluateControlGates({applicability:r.applicability,justification:r.applicability_justification,approvedBy:r.approved_by,ownerUserId:r.owner_user_id,implementation:r.implementation,
   evidence:ev.filter((e:any)=>e.scope_control_id===r.id).map((e:any)=>({validatedBy:e.validated_by,submittedBy:e.submitted_by,validUntil:e.valid_until?new Date(e.valid_until).toISOString():null,status:e.status})),
   closureEvidence:(Array.isArray(r.evidence_refs)?r.evidence_refs:[]).filter((x:any)=>String(x?.type||'').startsWith('CAPA_CLOSURE')).length,
   latestTest:t?{result:t.result,executedAt:new Date(t.executed_at).toISOString()}:null,
   openIssues:Number(iss?.open_issues||0),openCapa:Number(iss?.open_capa||0),overdueCapa:Number(iss?.overdue_capa||0),
   openRisks:(Array.isArray(r.related_risk_ids)?r.related_risk_ids:[]).filter((x:any)=>openRisks.has(String(x))).length});
  return {scopeControlId:r.id,controlKey:r.control_key,title:r.title,domain:r.domain,applicability:r.applicability,justification:r.applicability_justification,implementation:r.implementation,ownerUserId:r.owner_user_id,approvedBy:r.approved_by,mappings:r.mappings,...out};
 });
 const count=(s:ControlGateStatus)=>controls.filter(c=>c.status===s).length;
 return {organizationId:orgId,scope:{id:scope.id,name:scope.name,status:scope.status},generatedAt:new Date().toISOString(),gateNames:GATE_NAMES,controls,
  summary:{total:controls.length,pass:count('PASS'),conditional:count('CONDITIONAL'),actionRequired:count('ACTION_REQUIRED'),notApplicable:count('NOT_APPLICABLE')},
  disclaimer:'Statement of Applicability generated from stored records. Internal gate status is not external certification. ISO control text is not reproduced; consult your licensed standard.'};
}
