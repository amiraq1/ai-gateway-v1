#!/bin/sh
set -eu

URL="${1:-http://127.0.0.1:8000/healthz}"

if command -v curl >/dev/null 2>&1; then
    RESP="$(curl -fsS "$URL" 2>/dev/null)" || { echo "Health check failed: unable to reach gateway"; exit 1; }
elif command -v wget >/dev/null 2>&1; then
    RESP="$(wget -qO- "$URL" 2>/dev/null)" || { echo "Health check failed: unable to reach gateway"; exit 1; }
else
    echo "Error: curl or wget is required for health check"
    exit 1
fi

case "$RESP" in
    *'"status":"ok"'*|*'"status": "ok"'*)
        echo "Gateway is healthy: $RESP"
        exit 0
        ;;
    *)
        echo "Gateway returned unhealthy status: $RESP"
        exit 1
        ;;
esac
