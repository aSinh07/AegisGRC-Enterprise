#!/usr/bin/env bash
# Nightly encrypted off-site backup (target architecture: "Backups leave encrypted").
#   1. pg_dump (custom format) from the running postgres service, read-only.
#   2. Encrypt locally with age to AGE_RECIPIENT (public key). The private key never leaves the server owner.
#   3. Upload the .age file and its SHA-256 to Google Cloud Storage (BACKUP_BUCKET), then prune local copies.
# Cron example (02:17 daily):  17 2 * * *  cd /opt/aegis && ./scripts/backup-encrypted.sh >> /var/log/aegis-backup.log 2>&1
set -euo pipefail
cd "$(dirname "$0")/.."
: "${AGE_RECIPIENT:?AGE_RECIPIENT (age public key, age1...) is required}"
: "${BACKUP_BUCKET:?BACKUP_BUCKET (gs://bucket/path) is required}"
command -v age >/dev/null || { echo "age is required (apt install age)"; exit 1; }
command -v gcloud >/dev/null || { echo "gcloud is required for the upload"; exit 1; }
[[ "$AGE_RECIPIENT" == age1* ]] || { echo "AGE_RECIPIENT must be an age public key"; exit 1; }
OUT="${AEGIS_BACKUP_DIR:-/var/backups/aegis}"; KEEP_LOCAL="${AEGIS_BACKUP_KEEP_LOCAL:-3}"
umask 077; mkdir -p "$OUT"
ts="$(date -u +%Y%m%dT%H%M%SZ)"; file="$OUT/aegis-$ts.dump.age"
# Plaintext is streamed straight into age and is never written to disk.
docker compose -f docker-compose.production.yml exec -T postgres sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc' | age -r "$AGE_RECIPIENT" -o "$file"
test -s "$file" || { echo "Encrypted backup is empty; aborting"; rm -f "$file"; exit 1; }
sha256sum "$file" | awk '{print $1}' > "$file.sha256"
gcloud storage cp "$file" "$file.sha256" "${BACKUP_BUCKET%/}/"
echo "Uploaded $(basename "$file") ($(stat -c %s "$file") bytes, sha256 $(cat "$file.sha256"))"
ls -1t "$OUT"/aegis-*.dump.age 2>/dev/null | tail -n +"$((KEEP_LOCAL+1))" | while read -r old; do rm -f "$old" "$old.sha256"; done
