#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"

echo "[1/5] Start containers"
docker compose -f "$COMPOSE_FILE" up -d --build

echo "[2/5] Wait for dashboard to become healthy"
for i in {1..30}; do
  STATUS=$(docker inspect -f "{{.State.Health.Status}}" netsec-dashboard 2>/dev/null || echo "starting")
  echo "  dashboard health: $STATUS"
  [ "$STATUS" = "healthy" ] && break
  sleep 2
done
[ "${STATUS:-}" = "healthy" ] || { echo "Dashboard never became healthy"; docker compose -f "$COMPOSE_FILE" logs --tail=120 dashboard; exit 1; }

echo "[3/5] Run quick evaluation"
docker compose -f "$COMPOSE_FILE" exec -T dashboard python main.py evaluate --max-samples 5 --delay 1

echo "[4/5] Verify output files were generated"
docker compose -f "$COMPOSE_FILE" exec -T dashboard sh -lc "ls -1 outputs/run_*_metrics.json outputs/run_*_details.json >/dev/null"

echo "[5/5] Check dashboard HTTP"
curl -fsS http://localhost:5001 >/dev/null

echo "Smoke test passed."