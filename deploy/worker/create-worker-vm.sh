#!/usr/bin/env bash
# Creates the scanner worker VM on Google Cloud. Requires gcloud authenticated as a principal that may
# create instances in PROJECT. The VM gets no external inbound firewall rules (pull-only) and a
# dedicated service account with no roles.
set -euo pipefail
: "${PROJECT:?PROJECT is required}"; : "${ZONE:=asia-south1-a}"; : "${NAME:=aegis-scanner-worker}"
: "${REPO:?REPO (git URL of the AegisGRC repo) is required}"; : "${REF:?REF (commit SHA or tag to deploy) is required}"
test -f .env.worker || { echo ".env.worker is required (copy .env.worker.example)"; exit 1; }
grep -q 'REPLACE_WITH' .env.worker && { echo ".env.worker still has placeholders"; exit 1; }
SA="aegis-worker@${PROJECT}.iam.gserviceaccount.com"
gcloud iam service-accounts describe "$SA" --project "$PROJECT" >/dev/null 2>&1 || \
  gcloud iam service-accounts create aegis-worker --project "$PROJECT" --display-name "AegisGRC scanner worker (no roles)"
gcloud compute instances create "$NAME" --project "$PROJECT" --zone "$ZONE" \
  --machine-type e2-small --image-family ubuntu-2404-lts-amd64 --image-project ubuntu-os-cloud \
  --boot-disk-size 30GB --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring \
  --service-account "$SA" --scopes cloud-platform --no-address \
  --metadata "aegis-repo=$REPO,aegis-ref=$REF,block-project-ssh-keys=true,enable-oslogin=true" \
  --metadata-from-file "startup-script=deploy/worker/gce-startup.sh,aegis-worker-env=.env.worker"
echo "Note: --no-address means the VM needs Cloud NAT for outbound HTTPS. Create it once per region:"
echo "  gcloud compute routers create aegis-nat-router --project $PROJECT --region ${ZONE%-*} --network default"
echo "  gcloud compute routers nats create aegis-nat --project $PROJECT --router aegis-nat-router --region ${ZONE%-*} --auto-allocate-nat-external-ips --nat-all-subnet-ip-ranges"
