#!/bin/sh
set -eu

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="$REPO_ROOT/.env"

if [ -f "$ENV_FILE" ] && grep -q '^GATEWAY_PEPPER=[^#[:space:]]\{32,\}' "$ENV_FILE"; then
    echo "GATEWAY_PEPPER already configured in .env."
    exit 0
fi

if command -v openssl >/dev/null 2>&1; then
    PEPPER="$(openssl rand -hex 32)"
else
    PEPPER="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
fi

if [ -f "$ENV_FILE" ]; then
    if grep -q '^GATEWAY_PEPPER=' "$ENV_FILE"; then
        sed -i.bak "s/^GATEWAY_PEPPER=.*/GATEWAY_PEPPER=${PEPPER}/" "$ENV_FILE" && rm -f "${ENV_FILE}.bak"
    else
        printf "\nGATEWAY_PEPPER=%s\n" "$PEPPER" >> "$ENV_FILE"
    fi
else
    cp "$REPO_ROOT/.env.example" "$ENV_FILE" 2>/dev/null || touch "$ENV_FILE"
    sed -i.bak "s/^GATEWAY_PEPPER=.*/GATEWAY_PEPPER=${PEPPER}/" "$ENV_FILE" 2>/dev/null && rm -f "${ENV_FILE}.bak" || printf "GATEWAY_PEPPER=%s\n" "$PEPPER" > "$ENV_FILE"
fi

chmod 0600 "$ENV_FILE" 2>/dev/null || true
echo ".env initialized with secure local pepper."
