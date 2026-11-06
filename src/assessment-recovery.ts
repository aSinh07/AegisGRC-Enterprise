import crypto from 'node:crypto';
import { pool } from './db-pool.js';

// Full URL assessments execute inside the API process. If the process restarts
// (deploy, crash, OOM) the in-memory task is lost and the persisted row would stay
// RUNNING forever. This recovery marks such orphaned rows INTERRUPTED with an audit
// event so reports can never present a perpetually "in progress" assessment.

export const INTERRUPTED_REASON =
  'Assessment execution was interrupted (API process restarted or execution exceeded its maximum duration). No completion is inferred; re-run the assessment.';

export function maxFullAssessmentMs() {
  const raw = Number(process.env.FULL_ASSESSMENT_MAX_MS || 2 * 60 * 60 * 1000);
  return Number.isFinite(raw) && raw >= 60_000 ? Math.trunc(raw) : 2 * 60 * 60 * 1000;
}

/**
 * Marks RUNNING assessments as INTERRUPTED.
 * @param activeIds assessment ids still executing in this process (never touched)
 * @param olderThanMs only rows whose last update is older than this are recovered (0 = all, used at boot)
 * @param reason recorded in payload and audit
 */
export async function recoverInterruptedAssessments(activeIds: Iterable<string>, olderThanMs: number, reason = INTERRUPTED_REASON) {
  const active = [...activeIds];
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const rows = (
      await client.query(
        `UPDATE assessments
            SET status='INTERRUPTED',
                updated_at=now(),
                payload=payload || jsonb_build_object('status','INTERRUPTED','interruptedAt',to_char(now() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),'interruptionReason',$3::text)
          WHERE status='RUNNING'
            AND NOT (id = ANY($1::uuid[]))
            AND updated_at <= now() - ($2::text || ' milliseconds')::interval
        RETURNING id`,
        [active, String(Math.max(0, Math.trunc(olderThanMs))), reason],
      )
    ).rows;
    for (const r of rows) {
      const createdAt = new Date().toISOString(),
        id = crypto.randomUUID();
      await client.query('INSERT INTO audit_events(id,assessment_id,action,created_at,payload) VALUES($1,$2,$3,$4,$5)', [
        id,
        r.id,
        'ASSESSMENT_INTERRUPTED',
        createdAt,
        { id, assessmentId: r.id, action: 'ASSESSMENT_INTERRUPTED', actor: 'system:assessment-recovery', createdAt, metadata: { reason, olderThanMs } },
      ]);
    }
    await client.query('COMMIT');
    return rows.map((r: any) => String(r.id));
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}
