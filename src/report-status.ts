// Report honesty helpers. A report generated before an assessment reaches a terminal
// state is an interim snapshot: it must never present a clean/green conclusion.
export const TERMINAL_ASSESSMENT_STATES = Object.freeze(['COMPLETED', 'PARTIAL', 'FAILED', 'INTERRUPTED'] as const);

export function normalizedAssessmentStatus(status: unknown) {
  return String(status || 'UNKNOWN').trim().toUpperCase();
}

export function isTerminalAssessment(status: unknown) {
  return (TERMINAL_ASSESSMENT_STATES as readonly string[]).includes(normalizedAssessmentStatus(status));
}

export type DispositionTone = 'RED' | 'AMBER' | 'GREEN';

/**
 * Applies assessment-state guards on top of a findings-based disposition.
 * - Non-terminal (RUNNING/AUTHORIZED/QUEUED/UNKNOWN): always labelled INTERIM, never green.
 * - FAILED / INTERRUPTED: no assurance conclusion is possible, never green.
 * - Otherwise the findings-based disposition is kept.
 */
export function guardedDisposition(status: unknown, base: string, baseTone: DispositionTone, findingCount: number) {
  const s = normalizedAssessmentStatus(status);
  if (!isTerminalAssessment(s)) {
    const text = findingCount
      ? `INTERIM SNAPSHOT · ASSESSMENT ${s} · ${base}`
      : `INTERIM SNAPSHOT · ASSESSMENT ${s} · NO CONCLUSION UNTIL EXECUTION COMPLETES`;
    return { text, tone: (baseTone === 'RED' ? 'RED' : 'AMBER') as DispositionTone, interim: true };
  }
  if (s === 'FAILED' || s === 'INTERRUPTED') {
    const text = findingCount
      ? `ASSESSMENT ${s} · ${base} · COVERAGE INCOMPLETE`
      : `ASSESSMENT ${s} · NO ASSURANCE CONCLUSION · RE-RUN REQUIRED`;
    return { text, tone: (baseTone === 'RED' ? 'RED' : 'AMBER') as DispositionTone, interim: false };
  }
  return { text: base, tone: baseTone, interim: false };
}

export function interimNotice(status: unknown) {
  const s = normalizedAssessmentStatus(status);
  return isTerminalAssessment(s)
    ? null
    : `INTERIM REPORT: assessment status is ${s}. Scanner execution had not reached a terminal state when this report was generated; results are a point-in-time snapshot and are not a final disposition.`;
}
