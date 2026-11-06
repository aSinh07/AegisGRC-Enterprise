# AegisGRC Security

Production-oriented GRC and authorized security-assessment platform.

## Design rules
- One authorization/scope gate at assessment entry.
- No arbitrary shell endpoint and no user-supplied scanner flags.
- Real scanner output is labeled **REAL** only when a scanner process actually executes.
- AI analysis is labeled **AI ANALYSIS**, never as scanner evidence.
- Unconfigured integrations fail closed and are shown as **UNAVAILABLE**.
- Raw evidence, exit code, timestamps and SHA-256 provenance are preserved.

## Initial real capabilities
- Nmap: constrained TCP/service discovery profile.
- Wapiti: constrained web assessment profile.
- HTTP/TLS/security-header evidence.
- GRC normalization layer for CWE/CVSS/OWASP and framework mappings.
- Gemini-compatible AI gateway when a server-side API key is configured.
- Docker runtime and GitHub Actions build verification.

## Safety / authorization
Use only on systems you own or have explicit permission to assess. In production, a target must pass DNS/HTTP ownership verification and be approved by a second authorized user before any scan (see `docs/ARCHITECTURE_GAP_CLOSURE.md`). Scanners connect only to the validated, pinned address. Private, loopback, link-local, multicast and reserved destinations are blocked by default. Redirects and resolved addresses must remain in the authorized scope.

## Local development
```bash
cp .env.example .env
docker compose up --build
```

Open http://localhost:8080 and submit an authorized target through the assessment gate.

## Architecture
Browser -> API -> authorization/scope validation -> scanner service -> real tool process -> evidence hash -> normalized findings -> GRC mapping -> optional AI explanation.

Metasploit exploitation, credential attacks, persistence, evasion and arbitrary command execution are intentionally not exposed.


## Production persistence
Set `DATABASE_URL` to enable PostgreSQL. The container runs the idempotent schema initializer before starting the API. Without `DATABASE_URL`, local development falls back to the file store.

## Deployment
`docker-compose.production.yml` and `scripts/deploy-gce.sh` are the supported production path for the Google Cloud Compute Engine VM. Create `.env.production` from `.env.production.example`, use strong server-side secrets, and preserve the named `aegis-db` PostgreSQL volume. The deployment script rebuilds the application container without deleting the database volume and verifies `/api/ready` before declaring the release healthy.

## Data trust model
Evidence is HMAC-signed, the audit trail is hash-chained with signed checkpoints, and every governed PDF is stored as a signed report record. The app runs as a non-owner database role, so the append-only triggers are a hard control.

Scanner stdout/stderr is evidence. Parsed findings reference its SHA-256. Deterministic framework mappings and optional AI remediation are downstream interpretations and never replace raw evidence.
