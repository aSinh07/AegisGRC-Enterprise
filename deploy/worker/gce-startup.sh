#!/usr/bin/env bash
# GCE startup script for the AegisGRC scanner worker VM (Ubuntu 24.04).
# Reads the worker env from the instance metadata key "aegis-worker-env" (set by create-worker-vm.sh),
# builds the pinned release and starts the worker. The VM stores no customer data.
set -euo pipefail
MD=http://metadata.google.internal/computeMetadata/v1/instance/attributes
get(){ curl -fsS -H 'Metadata-Flavor: Google' "$MD/$1"; }
if ! command -v docker >/dev/null; then
  apt-get update && apt-get install -y --no-install-recommends ca-certificates curl git docker.io docker-compose-v2
  systemctl enable --now docker
fi
REPO="$(get aegis-repo)"; REF="$(get aegis-ref)"
install -d -m 700 /opt/aegis-worker
cd /opt/aegis-worker
if [ ! -d src/.git ]; then git clone --quiet "$REPO" src; fi
cd src && git fetch --quiet origin && git checkout --quiet --detach "$REF"
umask 077; get aegis-worker-env > .env.worker
docker compose -f docker-compose.worker.yml --env-file .env.worker up -d --build
