#!/bin/sh
set -eu

DEST="${1:-/data/backups/backup-$(date +%Y%m%d%H%M%S).sqlite3}"

if command -v docker >/dev/null 2>&1 && docker compose ps --services 2>/dev/null | grep -q gateway; then
    docker compose exec -T gateway python -m app.admin backup "$DEST"
else
    python -m app.admin backup "$DEST"
fi
