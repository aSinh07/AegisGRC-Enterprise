#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
test -f .env.production || { echo ".env.production is required"; exit 1; }

required=(POSTGRES_USER POSTGRES_PASSWORD POSTGRES_DB DATABASE_URL ASSESSMENT_SESSION_SECRET EVIDENCE_HMAC_KEY REPORT_SIGNING_KEY GRC_AUTOMATION_SECRET TOTP_ENCRYPTION_KEY ZAP_API_KEY)
for key in "${required[@]}"; do
  value="$(grep -E "^${key}=" .env.production | tail -1 | cut -d= -f2- || true)"
  normalized="$(printf '%s' "$value" | tr '[:lower:]' '[:upper:]')"
  if [ -z "$value" ] || [[ "$normalized" == REPLACE_* ]] || [[ "$normalized" == CHANGE_THIS* ]] || [[ "$normalized" == CHANGEME* ]]; then
    echo "Missing or placeholder production secret: $key"; exit 1
  fi
done

[ "$(grep -E '^NODE_ENV=' .env.production | tail -1 | cut -d= -f2- || true)" = "production" ] || { echo "NODE_ENV must be production"; exit 1; }

env_value(){ grep -E "^$1=" .env.production | tail -1 | cut -d= -f2- || true; }
if [ -n "$(env_value MIGRATION_DATABASE_URL)" ]; then
  for key in AEGIS_DB_RUNTIME_ROLE AEGIS_DB_RUNTIME_PASSWORD; do
    value="$(env_value "$key")"; normalized="$(printf '%s' "$value" | tr '[:lower:]' '[:upper:]')"
    if [ -z "$value" ] || [[ "$normalized" == REPLACE_* ]]; then echo "Missing or placeholder production secret: $key"; exit 1; fi
  done
  runtime_user="$(env_value DATABASE_URL | sed -E 's#^[a-z]+://([^:@/]+).*#\1#')"
  [ "$runtime_user" = "$(env_value AEGIS_DB_RUNTIME_ROLE)" ] || { echo "DATABASE_URL must connect as AEGIS_DB_RUNTIME_ROLE (least-privilege runtime role)"; exit 1; }
  [ "$runtime_user" != "$(env_value POSTGRES_USER)" ] || { echo "DATABASE_URL must not use the schema owner when MIGRATION_DATABASE_URL is set"; exit 1; }
else
  echo "WARNING: MIGRATION_DATABASE_URL is not set; the application runs as the schema owner and database triggers are not a hard control."
fi
[ "$(grep -E '^COOKIE_SECURE=' .env.production | tail -1 | cut -d= -f2- || true)" = "true" ] || { echo "COOKIE_SECURE must be true"; exit 1; }

totp_key="$(grep -E '^TOTP_ENCRYPTION_KEY=' .env.production | tail -1 | cut -d= -f2- || true)"
totp_bytes="$(printf '%s' "$totp_key" | base64 -d 2>/dev/null | wc -c | tr -d ' ' || true)"
[ "$totp_bytes" = "32" ] || { echo "TOTP_ENCRYPTION_KEY must be valid base64 decoding to exactly 32 bytes"; exit 1; }

echo "Checking existing PostgreSQL service without modifying it..."
docker compose -f docker-compose.production.yml ps --status running postgres 2>/dev/null | grep -q postgres || {
  echo "Existing PostgreSQL service is not running; refusing application-only deployment."; exit 1;
}
docker compose -f docker-compose.production.yml exec -T postgres sh -c 'pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB"' >/dev/null || {
  echo "Existing PostgreSQL is not ready; refusing deployment."; exit 1;
}
docker compose -f docker-compose.production.yml exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1 -Atqc "SELECT 1"' | grep -qx 1 || {
  echo "Existing PostgreSQL read-only validation failed; refusing deployment."; exit 1;
}

if [ "${AEGIS_PREDEPLOY_BACKUP:-0}" = "1" ]; then
  BACKUP_DIR="${BACKUP_DIR:-./backups}"; mkdir -p "$BACKUP_DIR"
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"; backup_path="$BACKUP_DIR/aegis-$stamp.dump"
  echo "Optional backup requested; creating $backup_path ..."
  docker compose -f docker-compose.production.yml exec -T postgres sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc' > "$backup_path"
  test -s "$backup_path" || { echo "Backup is empty; refusing deployment."; rm -f "$backup_path"; exit 1; }
fi

release="$(git rev-parse HEAD)"
if [ -n "${AEGIS_RELEASE_SHA:-}" ] && [ "$release" != "$AEGIS_RELEASE_SHA" ]; then
  echo "Release mismatch: checked-out HEAD is $release but AEGIS_RELEASE_SHA requires $AEGIS_RELEASE_SHA"; exit 1
fi
echo "Deploying already checked-out release $release (deployment does not move Git HEAD)"

echo "Building application image only..."
docker compose -f docker-compose.production.yml build aegis

echo "Ensuring OWASP ZAP (required full-assessment engine) is running..."
docker compose -f docker-compose.production.yml up -d --no-deps zap

echo "Starting/updating AegisGRC only; PostgreSQL and other services are not restarted..."
docker compose -f docker-compose.production.yml up -d --no-deps aegis

echo "Waiting for local readiness..."
for i in $(seq 1 30); do
  if body="$(curl -fsS http://127.0.0.1:8080/api/ready 2>/dev/null)" && echo "$body" | grep -q '"mode":"postgres"'; then
    echo "AegisGRC $release is ready with the existing PostgreSQL service."
    docker compose -f docker-compose.production.yml ps
    exit 0
  fi
  sleep 2
done

echo "Readiness failed; showing Aegis application logs only."
docker compose -f docker-compose.production.yml logs --tail=100 aegis
exit 1
