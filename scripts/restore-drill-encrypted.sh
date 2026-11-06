#!/usr/bin/env bash
# Monthly restore drill: download an encrypted backup, verify its digest, decrypt with the owner's
# age identity and restore into an isolated temporary PostgreSQL container (never production).
#   AGE_IDENTITY=~/aegis-backup.key BACKUP_OBJECT=gs://bucket/path/aegis-...dump.age ./scripts/restore-drill-encrypted.sh
set -euo pipefail
: "${AGE_IDENTITY:?AGE_IDENTITY (path to the age private key) is required}"
: "${BACKUP_OBJECT:?BACKUP_OBJECT (gs://.../aegis-*.dump.age) is required}"
work="$(mktemp -d)"; name="aegis-restore-drill-$$"
cleanup(){ docker rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$work"; }
trap cleanup EXIT
gcloud storage cp "$BACKUP_OBJECT" "$BACKUP_OBJECT.sha256" "$work/"
f="$work/$(basename "$BACKUP_OBJECT")"
[ "$(sha256sum "$f" | awk '{print $1}')" = "$(cat "$f.sha256")" ] || { echo "Digest mismatch: backup altered or incomplete"; exit 1; }
docker run -d --name "$name" -e POSTGRES_PASSWORD=drill -e POSTGRES_DB=drill postgres:16-alpine >/dev/null
for i in $(seq 1 30); do docker exec "$name" pg_isready -U postgres -d drill >/dev/null 2>&1 && break; sleep 1; done
age -d -i "$AGE_IDENTITY" "$f" | docker exec -i "$name" pg_restore --no-owner --no-privileges -U postgres -d drill
tables="$(docker exec "$name" psql -U postgres -d drill -Atqc "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")"
audits="$(docker exec "$name" psql -U postgres -d drill -Atqc "SELECT count(*) FROM audit_events")"
[ "$tables" -gt 20 ] || { echo "Restore drill failed: only $tables tables"; exit 1; }
echo "RESTORE DRILL PASSED: $tables tables, $audits audit events restored from $(basename "$f")"
echo "Next: verify the audit hash chain on a staging app pointed at the restored copy (GET /api/admin/audit-chain/verify)."
