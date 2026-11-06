import type {Finding} from './models.js';
import {findingFingerprint} from './finding-correlation.js';

// Persisted fingerprint deduplication. The first finding with a fingerprint in an organization
// becomes canonical; later ones (other scanners, re-runs, retests) are recorded as occurrences and
// carry duplicateOf. Nothing is deleted: duplicates stay as evidence-backed observations.
type Q={query:(sql:string,params?:any[])=>Promise<{rows:any[]}>};
export async function assignFingerprintLineage(q:Q,findings:Finding[]):Promise<Finding[]>{
 if(!findings.length)return findings;
 const orgByAssessment=new Map<string,string|null>();
 const out:Finding[]=[];
 for(const f0 of findings){
  const f={...f0,fingerprint:f0.fingerprint||findingFingerprint(f0)};
  if(!orgByAssessment.has(f.assessmentId))orgByAssessment.set(f.assessmentId,(await q.query('SELECT organization_id FROM assessments WHERE id=$1',[f.assessmentId])).rows[0]?.organization_id||null);
  const org=orgByAssessment.get(f.assessmentId);
  if(!org){out.push(f);continue}
  const r=(await q.query(`INSERT INTO finding_fingerprints(organization_id,fingerprint,canonical_finding_id,canonical_assessment_id,latest_finding_id,sources)
   VALUES($1,$2,$3,$4,$3,ARRAY[$5]::text[])
   ON CONFLICT(organization_id,fingerprint) DO UPDATE SET latest_finding_id=EXCLUDED.latest_finding_id,last_seen_at=now(),occurrences=finding_fingerprints.occurrences+1,
    sources=ARRAY(SELECT DISTINCT unnest(finding_fingerprints.sources||EXCLUDED.sources) ORDER BY 1)
   RETURNING canonical_finding_id,occurrences`,[org,f.fingerprint,f.id,f.assessmentId,String(f.source)])).rows[0];
  out.push(String(r.canonical_finding_id)===f.id?f:{...f,duplicateOf:String(r.canonical_finding_id),occurrence:Number(r.occurrences)} as Finding);
 }
 return out;
}
