#!/bin/sh
set -eu

DEST="${1:-/data/backups/backup-$(date +%Y%m%d%H%M%S).sqlite3}"

if command -v docker >/dev/null 2>&1 && docker compose ps --services 2>/dev/null | grep -q gateway; then
    docker compose exec -T gateway python -m app.admin backup "$DEST"
elif command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' 2>/dev/null | grep -qE '^(ai-gateway-v1|gateway|ai-gateway-v1-production)$'; then
    CONTAINER_NAME="$(docker ps --format '{{.Names}}' | grep -m1 -E '^(ai-gateway-v1|gateway|ai-gateway-v1-production)$')"
    docker exec -T "$CONTAINER_NAME" python -m app.admin backup "$DEST"
else
    python -m app.admin backup "$DEST"
fi
