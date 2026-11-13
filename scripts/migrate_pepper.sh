#!/usr/bin/env bash
# ==============================================================================
# AI Gateway V1 — Production Pepper Atomic Migration Protocol
# ==============================================================================
set -Eeuo pipefail

CURRENT_CONTAINER="${1:?Usage: $0 <CURRENT_CONTAINER_NAME_OR_ID>}"
SECRETS_DIR="${SECRETS_DIR:-/etc/ai-gateway/secrets}"
FINAL_PEPPER="${SECRETS_DIR}/pepper"
TEMP_PEPPER="${SECRETS_DIR}/.pepper.tmp.$$"

cleanup() {
    rm -f "${TEMP_PEPPER}"
}
trap cleanup EXIT ERR INT TERM

echo "=== STEP 1: PREPARING PROTECTED DIRECTORY AND TEMP FILE ==="
sudo install -m 0750 -o root -g 10001 -d "${SECRETS_DIR}"
sudo install -m 0400 -o 10001 -g 10001 /dev/null "${TEMP_PEPPER}"

echo "=== STEP 2: EXTRACTING RAW BYTES FROM RUNNING CONTAINER ENVIRONMENT ==="
docker exec "${CURRENT_CONTAINER}" python -c '
import os, sys
raw_bytes = os.environb.get(b"GATEWAY_PEPPER")
if raw_bytes is None:
    sys.exit("ABORT: GATEWAY_PEPPER environment variable is missing from container")
if len(raw_bytes) < 32:
    sys.exit(f"ABORT: GATEWAY_PEPPER length is {len(raw_bytes)} bytes; minimum required is 32 bytes")
if b"\n" in raw_bytes or b"\r" in raw_bytes:
    sys.exit("ABORT: GATEWAY_PEPPER contains line break characters (CR/LF); aborting to prevent key corruption")
sys.stdout.buffer.write(raw_bytes)
' | sudo tee "${TEMP_PEPPER}" > /dev/null

echo "=== STEP 3: INDEPENDENT SIZE AND NON-EMPTY VERIFICATION ==="
SRC_SIZE=$(docker exec "${CURRENT_CONTAINER}" python -c '
import os, sys
b = os.environb.get(b"GATEWAY_PEPPER", b"")
sys.stdout.write(str(len(b)))
')
DST_SIZE=$(sudo wc -c < "${TEMP_PEPPER}")

if [ -z "${SRC_SIZE}" ] || [ "${SRC_SIZE}" -lt 32 ]; then
    echo "ERROR: Source Pepper size is invalid: ${SRC_SIZE} bytes." && exit 1
fi

if [ "${SRC_SIZE}" -ne "${DST_SIZE}" ]; then
    echo "ERROR: Size mismatch! Source=${SRC_SIZE} bytes, Destination=${DST_SIZE} bytes." && exit 1
fi
echo "Size verification passed: exactly ${DST_SIZE} bytes."

echo "=== STEP 4: INDEPENDENT SHA-256 INTEGRITY VERIFICATION ==="
SRC_SHA=$(docker exec "${CURRENT_CONTAINER}" python -c '
import os, hashlib, sys
b = os.environb.get(b"GATEWAY_PEPPER", b"")
if len(b) < 32:
    sys.exit(1)
sys.stdout.write(hashlib.sha256(b).hexdigest())
')
DST_SHA=$(sudo sha256sum "${TEMP_PEPPER}" | awk '{print $1}')

EMPTY_SHA="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
if [ "${SRC_SHA}" = "${EMPTY_SHA}" ] || [ "${DST_SHA}" = "${EMPTY_SHA}" ]; then
    echo "ERROR: SHA-256 matches empty string! Aborting." && exit 1
fi

if [ "${SRC_SHA}" != "${DST_SHA}" ] || [ -z "${SRC_SHA}" ]; then
    echo "ERROR: SHA-256 mismatch! Source=${SRC_SHA}, Destination=${DST_SHA}" && exit 1
fi
echo "SHA-256 integrity verification passed."

echo "=== STEP 5: FUNCTIONAL HMAC EQUIVALENCE CHECK (ZERO LEAKAGE) ==="
CANARY_TOKEN="test_verification_token_$(date +%s)"
HMAC_CHECK=$(python3 -c '
import subprocess, sys

token = sys.argv[1].encode("utf-8")
container = sys.argv[2]
temp_file = sys.argv[3]

src_cmd = ["docker", "exec", container, "python", "-c", """
import os, hmac, hashlib, sys
p = os.environb.get(b"GATEWAY_PEPPER", b"")
token = sys.argv[1].encode("utf-8")
sys.stdout.write(hmac.new(p, token, hashlib.sha256).hexdigest())
""", sys.argv[1]]
src_hmac = subprocess.check_output(src_cmd, text=True).strip()

with open(temp_file, "rb") as f:
    dst_pepper = f.read()
import hmac, hashlib
dst_hmac = hmac.new(dst_pepper, token, hashlib.sha256).hexdigest()

if src_hmac == dst_hmac and len(src_hmac) == 64:
    sys.stdout.write("MATCH")
else:
    sys.stdout.write("MISMATCH")
' "${CANARY_TOKEN}" "${CURRENT_CONTAINER}" "${TEMP_PEPPER}")

if [ "${HMAC_CHECK}" != "MATCH" ]; then
    echo "ERROR: HMAC functional equivalence check failed!" && exit 1
fi
echo "Functional HMAC equivalence verification passed."

echo "=== STEP 6: ATOMIC PROMOTION TO FINAL DESTINATION ==="
sudo mv "${TEMP_PEPPER}" "${FINAL_PEPPER}"
sudo chown 10001:10001 "${FINAL_PEPPER}"
sudo chmod 0400 "${FINAL_PEPPER}"

echo "PEPPER_ATOMIC_MIGRATION=SUCCESS (Verified byte-for-byte, HMAC equivalent, 0400 permissions preserved)"
