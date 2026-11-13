#!/bin/sh
set -eu

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Check if production initialization requested
if [ "${1:-}" = "--production" ] || [ "${1:-}" = "--prod" ]; then
    SECRETS_DIR="${SECRETS_DIR:-/etc/ai-gateway/secrets}"
    echo "Initializing PRODUCTION file-based secrets directory in ${SECRETS_DIR}..."
    sudo install -m 0750 -o root -g 10001 -d "${SECRETS_DIR}"

    PEPPER_FILE="${SECRETS_DIR}/pepper"
    if [ -s "${PEPPER_FILE}" ]; then
        echo "Production pepper already exists at ${PEPPER_FILE} (skipping generation to prevent key invalidation)."
    else
        echo "Generating secure production pepper..."
        if command -v openssl >/dev/null 2>&1; then
            PEPPER="$(openssl rand -hex 32)"
        else
            PEPPER="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
        fi
        echo -n "${PEPPER}" | sudo tee "${PEPPER_FILE}" > /dev/null
        sudo chown 10001:10001 "${PEPPER_FILE}"
        sudo chmod 0400 "${PEPPER_FILE}"
        echo "Production pepper initialized at ${PEPPER_FILE} with mode 0400 (owned by 10001:10001)."
    fi

    echo "NOTE: To configure OpenRouter API key for production, run:"
    echo "  echo -n 'YOUR_KEY' | sudo tee ${SECRETS_DIR}/openrouter_key > /dev/null"
    echo "  sudo chown 10001:10001 ${SECRETS_DIR}/openrouter_key && sudo chmod 0400 ${SECRETS_DIR}/openrouter_key"
    exit 0
fi

# Local Development Mode ONLY
ENV_FILE="$REPO_ROOT/.env"
echo "================================================================================"
echo "WARNING: scripts/init_env.sh is running in LOCAL DEVELOPMENT mode."
echo "Production deployments MUST NOT store secrets in .env or environment variables."
echo "For production file-based secrets, run: ./scripts/init_env.sh --production"
echo "================================================================================"

if [ -f "$ENV_FILE" ] && grep -q '^GATEWAY_PEPPER=[^#[:space:]]\{32,\}' "$ENV_FILE"; then
    echo "GATEWAY_PEPPER already configured in .env for local development."
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
echo ".env initialized for LOCAL DEVELOPMENT ONLY."
