#!/bin/sh
set -eu

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SECRETS_DIR="$REPO_ROOT/secrets"
PEPPER_FILE="$SECRETS_DIR/gateway_pepper"

mkdir -p "$SECRETS_DIR"
chmod 0750 "$SECRETS_DIR" 2>/dev/null || true

if [ -s "$PEPPER_FILE" ]; then
    echo "secrets/gateway_pepper already configured."
    exit 0
fi

if command -v openssl >/dev/null 2>&1; then
    PEPPER="$(openssl rand -hex 32)"
else
    PEPPER="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
fi

umask 077
printf "%s" "$PEPPER" > "$PEPPER_FILE"
chmod 0400 "$PEPPER_FILE" 2>/dev/null || true
echo "secrets/gateway_pepper initialized with secure local pepper."
