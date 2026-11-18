# Security Policy

## Threat Model & Security Posture

AI Gateway V1 acts as a hardened, lightweight local reverse proxy between client applications and OpenAI-compatible LLM providers.

### 1. Protected Assets
- **Client API Keys**: Generated with 256 bits of CSPRNG entropy (`secrets.token_urlsafe(32)`). The raw key is returned exactly once during creation and is never persisted. Only the HMAC-SHA-256 digest keyed with a 256-bit server-side Pepper is stored in SQLite.
- **Server Pepper**: Stored outside the repository in `.env` (or via Docker secret files) and guarded by filesystem permissions (`0600` / `0400`).
- **Provider API Keys**: Stored in environment variables matching strict naming rules (`*_API_KEY`) and never logged, echoed, or included in client error messages.
- **Request Metadata & SQLite Database**: Request logs contain only operational metadata (timestamps, latency, status codes, token usage). Prompts, messages, model responses, and keys are strictly excluded.

### 2. Trust Boundaries & Attack Vectors
- **Untrusted Ingress**: Clients send `Authorization: Bearer <key>`. Timing attacks against client lookup are mitigated via constant-time dummy HMAC computation for non-existent or revoked clients.
- **Rate Limiting**: Rate limits (RPM) are enforced atomically in SQLite using `BEGIN IMMEDIATE` transactions to prevent race conditions.
- **SSRF Prevention**: Upstream `api_base` URLs are canonically parsed and strictly validated. Plain HTTP, user credentials, queries, fragments, private IP ranges (RFC 1918), loopback, link-local / cloud metadata (`169.254.169.254`), and CGNAT (`100.64.0.0/10`) are forbidden. Outbound TCP connections are pinned to validated IPs to prevent DNS rebinding.
- **Denial of Service (DoS)**: Ingress request bodies are capped by `BoundedBodyMiddleware` (1MB default). Non-streaming upstream responses are capped at 10MB to prevent memory exhaustion (OOM).

### 3. Container Hardening
- Base image: Minimal Python slim image pinned with SHA-256 digest.
- Non-root user: Executes as UID/GID `10001:10001` (`gateway`).
- Filesystem: Root filesystem mounted `read_only: true` with a 64MB `tmpfs` for `/tmp`.
- Capabilities: All Linux capabilities dropped (`cap_drop: [ALL]`), `no-new-privileges: true`.
- Network: Custom isolated bridge network (`gateway_internal`). Published host ports are strictly bound to loopback: `127.0.0.1:8000:8000`.

## Reporting a Vulnerability

If you discover a security vulnerability within this project:
1. Do not open a public GitHub issue.
2. Privately notify the project maintainers with reproduction steps and proof-of-concept.
