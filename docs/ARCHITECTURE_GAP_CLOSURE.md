# Architecture Gap Closure (vs. "Architecture, Flow & Evidence Proof" pack)

This release closes the gaps where the code contradicted claims made in the architecture/evidence pack.
Regression gate: `tests/architecture-gap-closure.test.ts` (static checks plus a real PostgreSQL test in CI).

| # | Gap | Fix |
|---|---|---|
| 1 | A killed or timed-out scanner reported `exitCode: null`. `Number(null) === 0`, so a timed-out retest with no findings could close a finding as REMEDIATED. | `retestEvidenceIsComplete()` requires the exit code to be exactly the number `0`, and the run must not be timed out or truncated. Closure fails otherwise. |
| 2 | Reports ignored the RUNNING state. A RUNNING assessment with 0 findings printed a green "NO MATERIAL FINDINGS OBSERVED". | `report-status.ts` adds an INTERIM label, an interim notice, and a non-green disposition for any non-terminal assessment. FAILED and INTERRUPTED never show green. This applies to the technical, remediation and defensive PDFs. |
| 3 | Full assessments run in-process. A restart or deploy left them RUNNING forever. | `assessment-recovery.ts` runs at boot and every `ASSESSMENT_RECOVERY_POLL_MS` (5 min). It marks orphaned RUNNING rows INTERRUPTED and writes an `ASSESSMENT_INTERRUPTED` audit event. Assessments still active in this process are skipped. The maximum run time is set by `FULL_ASSESSMENT_MAX_MS` (default 2 h). The assessment upsert now bumps `updated_at`. |
| 4 | ZAP is a required engine but was not part of the production deployment, so every full assessment ended PARTIAL. Caddy was not codified either. | `docker-compose.production.yml` adds an internal-only `zap` service with its API key enforced and sets `ZAP_URL`. `deploy-gce.sh` requires `ZAP_API_KEY` and starts ZAP. An opt-in `caddy` service (profile `edge`) mounts the Caddyfile, whose hostname comes from `AEGIS_DOMAIN`. |
| 5 | The Evidence Vault was "immutable" only by convention: evidence could be updated or cascade-deleted, documents could be hard-deleted, and 8 audit events recorded `actor: 'operator'`. | Database triggers make `evidence` and `audit_events` append-only (no UPDATE, DELETE or TRUNCATE). Deleting a document now withdraws it: the bytes and hash are kept. Evidence and document foreign keys use `ON DELETE RESTRICT`. Audits record the real user ID. A governed purge requires `SET LOCAL aegis.allow_evidence_purge='on'` inside a transaction. |

## Operator actions on deploy
1. Add `ZAP_API_KEY` (32+ random bytes) to `.env.production`. `AEGIS_DOMAIN` and `FULL_ASSESSMENT_MAX_MS` are optional.
2. Run `scripts/deploy-gce.sh`. The container runs `db:init`, which installs the triggers idempotently.
3. If Caddy currently runs on the host, keep it, or migrate it with `docker compose -f docker-compose.production.yml --profile edge up -d caddy` once the host Caddy is stopped.
4. Allow about 1.5 GB of extra memory for ZAP on the VM.

## Second release: previously open gaps, now closed
Regression gate: `tests/open-gap-closure.test.ts` (unit, source and real-PostgreSQL tests).

| # | Gap | Fix |
|---|---|---|
| 6 | Evidence used plain SHA-256 and the audit trail had no hash chain. | Evidence is HMAC-SHA256 signed with `EVIDENCE_HMAC_KEY` over a canonical record (`src/evidence-signing.ts`). The MAC is stored in `evidence.hmac_sha256`. A `BEFORE INSERT` trigger hash-chains every `audit_events` row under an advisory lock, and HMAC-signed chain-head checkpoints are written every `AUDIT_CHECKPOINT_INTERVAL_MS`. Verify with `GET /api/admin/audit-chain/verify` and `GET /api/assessments/:id/evidence/verify`. Production refuses to start without a real key. |
| 7 | Target authorization was a self-attested checkbox. | `src/target-authorization.ts`: the requester proves control with a DNS TXT record at `_aegis-challenge.<host>` or a file at `/.well-known/aegis-verification.txt`. An `ORG_ADMIN`/`GRC_MANAGER` who is not the requester (also enforced by a DB CHECK) then approves it. Approvals expire after `TARGET_AUTHORIZATION_TTL_DAYS` (default 90) and can be revoked. In `enforce` mode, the production default, assessment authorization and every active URL scan require an active approval. A UI panel is in the Offensive gate. |
| 8 | There were no Security Analyst or Developer roles. | `SECURITY_ANALYST` can scan and triage. `DEVELOPER` can only read and retest. A new `retest` permission guards all finding-retest endpoints. |
| 9 | HTTP-posture and sqlmap findings had no deterministic retest. | The targeted retest covers `http` (pinned posture probe) and `sqlmap`. A failed probe has exit code 1 and can never close a finding. |
| 10 | Scanners re-resolved DNS after scope validation (DNS rebinding). | `src/pinned-egress.ts`: nmap scans the validated IP. wapiti, nuclei and sqlmap use a per-scan proxy that only accepts the authorized host and ports and connects to the pinned IP. ZAP's upstream proxy is pinned per scan (`ZAP_EGRESS_PROXY_HOST`) and fails closed without it. testssl uses `--ip`. Egress decisions are recorded in the evidence. |
| 11 | Nuclei templates were not pinned. | The image clones `nuclei-templates` at a fixed tag, verifies the commit SHA, and makes it read-only. Nuclei runs with `-t /opt/nuclei-templates -duc -pt http -ni`, and the pin is recorded in the evidence. |
| 12 | Finding → Risk → CAPA promotion was manual. | `src/finding-promotion.ts`: an opt-in per-organization policy (minimum severity, risk and CAPA toggles) promotes analyst-CONFIRMED findings automatically, under the policy owner's re-checked authority. Use `GET/PUT /api/grc/organizations/:orgId/promotion-policy` and `POST .../promotion/run`. |
| 13 | Offensive, Defensive and Enterprise PDFs were not persisted or signed. | `report_records` (append-only) stores the exact bytes, the SHA-256 and an HMAC (`REPORT_SIGNING_KEY`) for every governed PDF. Responses carry `X-Aegis-Report-*` headers. Verify with `GET /api/reports/:id/verify` or `POST /api/reports/verify` (upload). |
| 14 | Database triggers did not stop the owner/superuser runtime role. | `db:init` migrates as the owner (`MIGRATION_DATABASE_URL`) and provisions `AEGIS_DB_RUNTIME_ROLE` with DML only and no UPDATE/DELETE on evidence tables. The server performs no DDL as a non-owner. The purge override is owner-only. `AEGIS_REQUIRE_NON_OWNER_DB_ROLE=true` makes an owner or superuser runtime role fatal. |

## Operator actions for the second release
1. Make sure `EVIDENCE_HMAC_KEY` and `REPORT_SIGNING_KEY` are real 32+ character secrets. Production now refuses to start or to issue reports without them.
2. Create the least-privilege role: set `MIGRATION_DATABASE_URL` (owner), `AEGIS_DB_RUNTIME_ROLE=aegis_app`, `AEGIS_DB_RUNTIME_PASSWORD`, `DATABASE_URL` (as `aegis_app`) and `AEGIS_REQUIRE_NON_OWNER_DB_ROLE=true` in `.env.production`. `deploy-gce.sh` validates the split.
3. Target authorization is enforced in production. Before the next scan, each organization must verify its targets and have them approved in **Offensive → Target Authorizations**. `TARGET_AUTHORIZATION_MODE=attest` restores the legacy checkbox and is not recommended.
4. `ZAP_EGRESS_PROXY_HOST=aegis` is already set in the compose files. Keep it if you change service names.
5. Optional: enable promotion automation per organization through the promotion-policy API.

## Remaining limitations
- Hash-chain checkpoints prove integrity up to the last signed head. Rows appended after the latest checkpoint are protected only by the chain until the next checkpoint.
- Nuclei runs only HTTP-protocol templates (`-pt http`) and no OAST callbacks (`-ni`), so that all traffic stays inside the pinned scope. Network, SSL and blind out-of-band templates are not run.
- ZAP's own add-ons can still reach the internet directly for updates. Only target traffic is pinned.
- There is no UI yet for the promotion policy (API only).
- 19 source-regex UI/auth tests were already failing on `main` before both releases. They are test drift, not regressions.
