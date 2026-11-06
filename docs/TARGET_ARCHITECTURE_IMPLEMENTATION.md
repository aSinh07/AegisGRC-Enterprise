# Target architecture: implementation map

This maps *AegisGRC Enterprise — Target Architecture* (Nov 6, 2026) to the code. Regression gates:
`tests/governed-lifecycle.test.ts`, `tests/governance-depth.test.ts`, `tests/open-gap-closure.test.ts`.

## The 12-step governed lifecycle

"No finding closes and no report signs without fresh evidence." The **Governed Lifecycle** panel
(`public/lifecycle.js`) and `GET /api/grc/assessments/:id/lifecycle` show each step per finding. A step is
DONE only when its stored record exists (`src/lifecycle.ts`).

| # | Step | Implementation |
|---|---|---|
| 1 | Target verified | `src/target-authorization.ts`: DNS TXT or `/.well-known` proof plus a second-person approval, which expires and can be revoked |
| 2 | Scan job queued, approver signs off | `src/url-scan-jobs.ts`: QUICK/STANDARD run under the target approval. DEEP (active ZAP + sqlmap) needs a per-job approval by someone other than the requester (DB CHECK) |
| 3 | Worker scans (pinned IP, profile) | `src/scan-runner.ts` runs embedded in the app, or remotely via `src/worker/scanner-worker.ts` (pull-only, signed requests and results) |
| 4 | Signed evidence | `src/scan-job-persistence.ts` and `src/evidence-signing.ts`: HMAC on the system of record, append-only triggers, worker attestation in the metadata |
| 5 | Finding created (fingerprint dedupe) | `src/finding-dedupe.ts`: one lineage per organization and fingerprint (`finding_fingerprints`), with `duplicateOf` on repeats |
| 6 | Analyst review | `src/finding-review.ts`: CONFIRMED, or FALSE_POSITIVE with a written reason (never reaches a risk) |
| 7 | Issue + risk | `src/finding-promotion.ts`: an opt-in policy auto-raises the issue, a draft risk and links the CFG-01/VUL-01 control |
| 8 | CAPA + fix | CAPA with owner and SLA due date. A retest that still detects the finding sends it back (`CHANGES_REQUESTED`) |
| 9 | Fresh retest | Same source, newer than the finding, bound to the fingerprint (`finding_retests`) |
| 10 | Closure review by a second person | `closeCapa`: creator, owner, submitter and retest operator are all excluded |
| 11 | Control evidence | Closure appends the retest evidence to the scoped control's `evidence_refs` |
| 12 | Signed report | `src/report-records.ts`: bytes, SHA-256 and HMAC, verifiable by id or by upload |

**Phase 1 gate:** `GET /api/grc/organizations/:orgId/lifecycle-gate` passes when one confirmed finding has
completed all 12 steps. A real-PostgreSQL test drives a finding through every step, including the
still-present loop.

## Platform tiers

| Tier | Component | Where |
|---|---|---|
| Edge | Cloudflare Tunnel + Access, Caddy | `docker-compose.production.yml` profile `tunnel`, `deploy/Caddyfile.tunnel`, `docs/HYBRID_DEPLOYMENT.md` |
| App | Job dispatcher with leases and stuck-job recovery | `url_scan_jobs` / `url_scan_tasks`, `recoverExpiredScanLeases`. Assessments with active jobs survive restarts |
| App | Automation engine | `src/scheduler.ts`: recurring scans, evidence freshness, SLA/CAPA and policy reminders, deep-scan approval nudges |
| Data | Least-privilege DB role, append-only evidence, hash-chained audit | `scripts/init-db.ts`, `db/schema.sql`, `src/audit-chain.ts` |
| Scan | Scanner worker VM | `docker-compose.worker.yml`, `deploy/worker/*`. No ports, no DB credentials, no persistent storage |
| Ops | Encrypted backups and restore drill | `scripts/backup-encrypted.sh`, `scripts/restore-drill-encrypted.sh` (age + GCS) |
| Ops | Monitoring | Uptime Kuma (profile `monitoring`), with suggested monitors in the deployment guide |

## Phase 2: GRC depth

| Item | Implementation |
|---|---|
| ISO/IEC 27001:2022 base library | `src/iso-library.ts`: 93 Annex A controls, plus ISO/IEC 42001 Annex A objectives and ISO/IEC 27701 categories mapped onto the same controls. Own guidance only, no ISO text |
| SoA generator, five control gates | `src/soa-gates.ts`. Signed PDF/XLSX/JSON export via `GET .../scopes/:scopeId/soa-gates.:format` |
| Phase 2 gate | `GET /api/grc/organizations/:orgId/phase-two-gate`: a signed SoA export exists |
| Compliance dashboard | `GET .../compliance-dashboard`: framework coverage, evidence freshness, risks by rating, CAPA ageing |
| Policies | Existing approval and attestation, plus version history (`POST .../policies/:id/revise`) |
| Assets | Existing inventory, plus links to controls, risks, issues, findings and third parties |
| Scheduler and alerts | `src/scheduler.ts`, with in-app notifications and SMTP email |

## Not yet done
- Modular rebuild of `src/server.ts` and replacing source-regex tests with behavioural tests. New code is
  modular and tested behaviourally, but the legacy server file is still large.
- New visual theme and role-based navigation. The new panels reuse the current theme tokens.
- Phase 3: OIDC SSO, a proven failover test, an external penetration test and customer security docs.
- Owner actions: Cloudflare and Google Cloud accounts, the tunnel, Access apps, the bucket, the age key and the worker VM.
