# Hybrid deployment: local system of record + cloud scanner worker

This guide implements the target architecture in *AegisGRC Enterprise — Target Architecture*:
confidential data lives only on the local server, scanning runs on a disposable cloud worker, and
the public reaches the app through a zero-trust edge with no open ports.

```
Users ──► Cloudflare edge (Tunnel + Access) ──► caddy-tunnel ──► aegis (API + UI) ──► PostgreSQL / Evidence Vault
                                                                       ▲
Scanner worker VM (GCE) ── pulls jobs over HTTPS, returns signed raw output ┘   (worker stores nothing)
Backups ── pg_dump │ age (encrypted locally) ──► Google Cloud Storage            (key never in the cloud)
```

## 1. Local server (system of record)

1. Ubuntu 24.04 with Docker, full-disk encryption (LUKS) and a UPS.
2. Copy `.env.production.example` to `.env.production` and fill every secret. Use the least-privilege DB role
   (`MIGRATION_DATABASE_URL`, `AEGIS_DB_RUNTIME_ROLE`, `AEGIS_REQUIRE_NON_OWNER_DB_ROLE=true`).
3. Set `SCAN_WORKER_MODE=remote` when the cloud worker runs the scans, and list the worker in
   `AEGIS_WORKER_KEYS=gce-worker-1:<32+ random chars>`. With `embedded` (the default) the app scans by itself.
4. Deploy: `scripts/deploy-gce.sh` (works on any Docker host despite the name).

## 2. Zero-trust edge (Cloudflare Tunnel + Access)

1. Cloudflare Zero Trust → Networks → Tunnels → create a tunnel (cloudflared). Copy the token.
2. Public hostname: `aegis.<your-domain>` → service `http://caddy-tunnel:80`.
3. Start the edge (no ports are opened on the router):
   ```bash
   export CLOUDFLARE_TUNNEL_TOKEN=...      # or put it in the compose .env file
   docker compose -f docker-compose.production.yml --profile tunnel up -d caddy-tunnel cloudflared
   ```
4. Access → Applications → Self-hosted, `aegis.<your-domain>`: policy **Allow** for your staff emails
   (one-time PIN, or Google/GitHub). Users then pass Access, then the app login, then TOTP MFA.
5. A second Access application for `aegis.<your-domain>/api/worker/*` with a **Service Auth** policy and a
   service token. Put its id/secret in the worker's `CF_ACCESS_CLIENT_ID` / `CF_ACCESS_CLIENT_SECRET`.
   Do the same for `/api/security/telemetry/*` if Wazuh posts telemetry from outside.
6. Remove the router port-forward and any host-level Caddy once the tunnel serves traffic.

## 3. Scanner worker on Google Cloud

The worker has no database credentials, publishes no ports and keeps output in memory only. Each request
is HMAC-signed (path, body digest, timestamp, single-use nonce), and each result carries an output
signature that is stored with the evidence as a worker attestation.

```bash
cp .env.worker.example .env.worker      # AEGIS_URL, AEGIS_WORKER_ID/SECRET, CF Access token, ZAP_API_KEY
PROJECT=my-project REPO=https://github.com/aSinh07/AegisGRC-Enterprise.git REF=<commit-sha> \
  deploy/worker/create-worker-vm.sh
```

* `e2-small` is the smallest size that runs ZAP. The VM has no external IP; outbound HTTPS uses Cloud NAT
  (commands are printed by the script). Its service account has no roles.
* For a local test without GCE: `docker compose -f docker-compose.worker.yml --env-file .env.worker up -d --build`.
* Check the server sees it: `scanner_workers.last_seen_at` updates on every poll.

## 4. Encrypted backups and restore drills

```bash
age-keygen -o ~/aegis-backup.key      # keep OFFLINE; put only the public key (age1...) on the server
AGE_RECIPIENT=age1... BACKUP_BUCKET=gs://aegis-backups/prod ./scripts/backup-encrypted.sh
```

* Cron it nightly (example in the script header). The plaintext dump is streamed into `age` and never written to disk.
* Monthly drill: `AGE_IDENTITY=~/aegis-backup.key BACKUP_OBJECT=gs://.../aegis-<ts>.dump.age ./scripts/restore-drill-encrypted.sh`.
  It verifies the digest, decrypts and restores into a throwaway container, never production.
* Give the bucket a retention policy and object versioning; the server's GCS credential only needs `storage.objects.create`.

## 5. Monitoring

`docker compose -f docker-compose.production.yml --profile monitoring up -d uptime-kuma` (bound to 127.0.0.1:3001).
Publish it on its own Access-protected hostname through the tunnel. Suggested monitors:

| Monitor | Check |
|---|---|
| App readiness | HTTP `GET /api/ready` returns `"mode":"postgres"` |
| Scanner worker | DB query `SELECT now()-max(last_seen_at) < interval '5 minutes' FROM scanner_workers` |
| Stuck scan jobs | `SELECT count(*) FROM url_scan_tasks WHERE state='LEASED' AND lease_expires_at<now()` equals 0 |
| Audit chain | `GET /api/admin/audit-chain/verify` (reviewer session) returns `INTACT` |
| Backups | newest object in `BACKUP_BUCKET` younger than 26 h |
| Certificates | handled by Cloudflare; monitor the public hostname |

## 6. What is still manual

Creating the Cloudflare and Google Cloud accounts, the tunnel, Access applications, the bucket and the
`age` key are owner actions. Prices change: check them at sign-up.
