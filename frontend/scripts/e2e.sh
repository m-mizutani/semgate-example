#!/usr/bin/env bash
# Build the frontend and the single binary (SPA embedded), start the server,
# run the Playwright E2E suite against it, and tear everything down.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ADDR="127.0.0.1:8091"
BIN="$(mktemp -d)/semgate-example"

cd "$REPO_ROOT/frontend"
pnpm install --frozen-lockfile
pnpm build

cd "$REPO_ROOT"
go build -o "$BIN" .

"$BIN" serve --addr "$ADDR" &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null || true' EXIT

# Wait for the server to accept connections.
for _ in $(seq 1 30); do
  if curl -sf "http://$ADDR/" >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done

cd "$REPO_ROOT/frontend"
PLAYWRIGHT_BASE_URL="http://$ADDR" pnpm test:e2e
