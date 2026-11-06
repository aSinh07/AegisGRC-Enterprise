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

## Still open (not closed by this change)
- Scanner evidence hashes are plain SHA-256 (`EVIDENCE_HMAC_KEY` is not used to sign evidence), and the audit trail has no hash chain.
- Target authorization is a self-attested checkbox. There is no domain-ownership verification and no approver.
- No Security Analyst or Developer organization roles. Developers need GRC Analyst rights to retest.
- HTTP-posture and sqlmap findings have no deterministic retest path.
- Scanners re-resolve DNS after scope validation, which leaves a DNS-rebinding window.
- Nuclei templates are not pinned in the image.
- Finding → Risk → CAPA promotion is manual.
- Offensive, Defensive and Enterprise PDFs are not persisted or signed as report records.
- Database triggers do not stop a PostgreSQL superuser. Run the app as a non-owner role to make this a hard control.
- 19 source-regex UI/auth tests were already failing on `main` before this change. They are test drift, not regressions from this change.
