# Architecture & Request Lifecycle

## Overview

AI Gateway V1 is a lightweight, zero-trust reverse proxy designed to expose a secure OpenAI-compatible interface backed by SQLite and FastAPI.

## Request Flow Diagram

```mermaid
flowchart TD
    Client["Client Application"] -->|HTTP POST /v1/chat/completions| BoundedBody["BoundedBodyMiddleware (<= 1MB)"]
    BoundedBody -->|Within Limit| AuthCheck["Authentication Layer (app.auth)"]
    BoundedBody -->|> 1MB| Err413["413 Payload Too Large"]
    
    AuthCheck -->|Resolve GATEWAY_PEPPER| HMACComp["HMAC-SHA-256 Digest Verification"]
    HMACComp -->|Equalized Timing Check| DBCheck["SQLite clients lookup"]
    DBCheck -->|Invalid Key or Revoked| Err401["401 Unauthorized"]
    
    DBCheck -->|Valid Client| RateLimiter["Rate Limiter (SQLite BEGIN IMMEDIATE)"]
    RateLimiter -->|Count >= RPM| Err429["429 Rate Limit Exceeded (Retry-After)"]
    
    RateLimiter -->|Allowed| Router["Provider Router & Model Alias"]
    Router -->|No active providers| Err404["404 Model Not Found"]
    
    Router -->|Primary Provider| Upstream1["Primary Upstream (HTTPS)"]
    Upstream1 -->|200 OK| ResponseHandler["Client Response (JSON / SSE)"]
    
    Upstream1 -->|429 / 5xx / Timeout| FallbackCheck{"Attempt < 2 and First Byte Not Sent?"}
    FallbackCheck -->|Yes| Upstream2["Secondary Upstream Fallback"]
    FallbackCheck -->|No| Err502["502 Gateway Error / SSE Error"]
    Upstream2 -->|200 OK| ResponseHandler
    Upstream2 -->|Failure| Err502
    
    ResponseHandler --> AuditLog["Audit Logger (database.log_request)"]
    AuditLog --> SQLiteLogs["SQLite request_logs table (30-day retention)"]
```

## Core Modules

- `app.main`: FastAPI application factory, routing, streaming loop, and error handling.
- `app.auth`: Key generation (`secrets`), HMAC verification with constant-time dummy comparison for missing clients, and log payload preparation.
- `app.database`: SQLite connection management (WAL, FULL sync, 5s busy timeout), atomic rate limiting, schema migrations (`PRAGMA user_version`), and live backup.
- `app.config`: YAML schema loading, environment variable overrides, strict model and provider key allowlisting.
- `app.ssrf`: Canonical URL validation, rejection of forbidden IP spaces (RFC 1918, RFC 3927 metadata, RFC 6598 CGNAT, RFC 1122 loopback), and DNS rebinding prevention via IP-pinned network transport.
- `app.providers`: Upstream HTTP communication, retryable fallback loop, stream forwarding, and response size capping.
- `app.secret_loader`: Sanitized secret loader supporting direct environment variables or file-based secrets with strict permission verification.
- `app.admin`: Local management CLI for client creation, revocation, usage auditing, and database backup.
