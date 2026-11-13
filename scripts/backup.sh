#!/bin/sh
set -eu

# Target backup file on the HOST (outside the container volume)
TIMESTAMP="$(date +%Y%m%d%H%M%S)"
HOST_BACKUP_DIR="${HOST_BACKUP_DIR:-./backups}"
DEST="${1:-${HOST_BACKUP_DIR}/backup-${TIMESTAMP}.sqlite3}"

mkdir -p "$(dirname "$DEST")"

if command -v docker >/dev/null 2>&1 && docker compose ps --services 2>/dev/null | grep -q gateway; then
    # Mode 1: Docker Compose
    CONTAINER_TEMP="/tmp/online-backup-${TIMESTAMP}.sqlite3"
    echo "Creating online backup inside Compose gateway container..."
    docker compose exec -T gateway python -m app.admin backup "$CONTAINER_TEMP"

    # Copy backup out of the container volume onto the host
    CONTAINER_ID="$(docker compose ps -q gateway)"
    echo "Transferring backup from container to host destination: $DEST"
    docker cp "${CONTAINER_ID}:${CONTAINER_TEMP}" "$DEST"

    # Verify backup on host
    chmod 0600 "$DEST"
    if [ ! -s "$DEST" ]; then
        echo "ERROR: Backup file on host is empty or missing!" && exit 1
    fi

    if command -v sqlite3 >/dev/null 2>&1; then
        INTEGRITY="$(sqlite3 "$DEST" "PRAGMA integrity_check;")"
        if [ "$INTEGRITY" != "ok" ]; then
            echo "ERROR: Backup integrity check failed on host: $INTEGRITY" && exit 1
        fi
        echo "Backup integrity verified: ok"
    fi

    # Delete temporary backup file inside container only after host verification succeeds
    docker compose exec -T gateway rm -f "$CONTAINER_TEMP"
    echo "Temporary backup inside container removed."

elif command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' 2>/dev/null | grep -qE '^(ai-gateway-v1|gateway|ai-gateway-v1-production|ai-gateway-v1-phase-d-candidate)$'; then
    # Mode 2: Docker Run (standalone container) - WITHOUT -T
    CONTAINER_NAME="$(docker ps --format '{{.Names}}' | grep -m1 -E '^(ai-gateway-v1|gateway|ai-gateway-v1-production|ai-gateway-v1-phase-d-candidate)$')"
    CONTAINER_TEMP="/tmp/online-backup-${TIMESTAMP}.sqlite3"
    echo "Creating online backup inside Docker container ${CONTAINER_NAME}..."
    docker exec "$CONTAINER_NAME" python -m app.admin backup "$CONTAINER_TEMP"

    # Copy backup out of the container volume onto the host
    echo "Transferring backup from container to host destination: $DEST"
    docker cp "${CONTAINER_NAME}:${CONTAINER_TEMP}" "$DEST"

    # Verify backup on host
    chmod 0600 "$DEST"
    if [ ! -s "$DEST" ]; then
        echo "ERROR: Backup file on host is empty or missing!" && exit 1
    fi

    if command -v sqlite3 >/dev/null 2>&1; then
        INTEGRITY="$(sqlite3 "$DEST" "PRAGMA integrity_check;")"
        if [ "$INTEGRITY" != "ok" ]; then
            echo "ERROR: Backup integrity check failed on host: $INTEGRITY" && exit 1
        fi
        echo "Backup integrity verified: ok"
    fi

    # Delete temporary backup file inside container only after host verification succeeds
    docker exec "$CONTAINER_NAME" rm -f "$CONTAINER_TEMP"
    echo "Temporary backup inside container removed."

else
    # Mode 3: Local Bare-Metal / Native Python
    echo "Creating online backup directly on local filesystem: $DEST"
    python -m app.admin backup "$DEST"
    chmod 0600 "$DEST" 2>/dev/null || true
    if [ ! -s "$DEST" ]; then
        echo "ERROR: Local backup file is empty or missing!" && exit 1
    fi
    if command -v sqlite3 >/dev/null 2>&1; then
        INTEGRITY="$(sqlite3 "$DEST" "PRAGMA integrity_check;")"
        if [ "$INTEGRITY" != "ok" ]; then
            echo "ERROR: Backup integrity check failed: $INTEGRITY" && exit 1
        fi
        echo "Backup integrity verified: ok"
    fi
fi

# Compute and display SHA-256 of verified host backup
if command -v sha256sum >/dev/null 2>&1; then
    BACKUP_SHA="$(sha256sum "$DEST" | awk '{print $1}')"
    echo "Backup created and verified successfully on host: $DEST (SHA-256: ${BACKUP_SHA})"
else
    echo "Backup created and verified successfully on host: $DEST"
fi
