#!/usr/bin/env bash
# Build the image from ./Dockerfile with Cloud Build and deploy it to Cloud Run
# with scale-to-zero and the smallest resources Cloud Run accepts.
set -euo pipefail

PROJECT="${SEMGATE_EXAMPLE_PROJECT:?set SEMGATE_EXAMPLE_PROJECT to the target Google Cloud project ID}"
REGION="${SEMGATE_EXAMPLE_REGION:-asia-northeast1}"
SERVICE="${SEMGATE_EXAMPLE_SERVICE:-semgate-example}"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Cloud Run rejects a CPU below 1 unless concurrency is 1, billing is
# request-based (--cpu-throttling), and the gen1 execution environment is used;
# gen1 is also required for memory below 512Mi.
# --min/--max cap the whole service; --max-instances would cap each revision,
# so old and new revisions could run at once during a rollout.
# --no-allow-unauthenticated requires an IAM identity token on every request;
# reach the service through `gcloud run services proxy` (see README).
gcloud run deploy "$SERVICE" \
  --project "$PROJECT" \
  --region "$REGION" \
  --source "$REPO_ROOT" \
  --port 8080 \
  --cpu 0.08 \
  --memory 128Mi \
  --concurrency 1 \
  --execution-environment gen1 \
  --cpu-throttling \
  --no-cpu-boost \
  --min 0 \
  --max 1 \
  --no-allow-unauthenticated \
  --quiet
