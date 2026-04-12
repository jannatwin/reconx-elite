# Design Document: Production Readiness

## Overview

This document describes the technical design for making ReconX Elite production-ready. The work spans eight concern areas: container hardening, security hardening, observability, performance tuning, reliability, CI/CD pipeline maturity, environment configuration management, and frontend production serving.

The platform is a Docker Compose-orchestrated stack: FastAPI/uvicorn backend, Celery worker, PostgreSQL, Redis, and a React/Vite frontend served by nginx. Most changes are additive (new files, new middleware, new config fields) with targeted modifications to existing Dockerfiles, `docker-compose.yml`, `config.py`, `database.py`, `main.py`, and the CI workflow.

---

## Architecture

### Current State

```
Internet
  └─> frontend (nginx :5173) ──> backend (uvicorn :8000)
                                      ├─> PostgreSQL :5432
                                      ├─> Redis :6379
                                      └─> Celery worker
                                            └─> recon CLI tools
```

### Target State

```
Internet
  └─> Reverse Proxy (nginx/Traefik, TLS :443, redirect :80)
        ├─> frontend (nginx :80, non-root, hardened headers)
        └─> backend (uvicorn :8000, non-root, JSON logs, /metrics)
                  ├─> PostgreSQL :5432 (pooling via env vars)
                  ├─> Redis :6379 (caching layer)
                  └─> Celery worker (non-root, graceful shutdown, /metrics)

Observability sidecar (docker-compose.monitoring.yml):
  Prometheus :9090 ──scrapes──> backend /metrics, worker /metrics
  Grafana    :3000 ──reads───> Prometheus
  Alertmanager :9093 ──fires──> webhook

CI/CD (GitHub Actions):
  secret-scan → backend tests → frontend lint/test/build
  → Docker build → CVE scan → push to registry (main only)

DB Backup (docker-compose service):
  pg_dump cron → compressed .sql.gz → retention cleanup
```

---

## Components and Interfaces

### 1. Container Hardening

**Backend Dockerfile** (`backend/Dockerfile`)
- Add `RUN groupadd -r appuser && useradd -r -g appuser -u 1001 appuser`
- `COPY --chown=appuser:appuser` all app files
- `USER appuser` before `CMD`
- Add `HEALTHCHECK CMD curl -fsS http://localhost:8000/health || exit 1`

**Worker Dockerfile** (`worker/Dockerfile`) — multi-stage rewrite
- Stage 1 (`tools-builder`): `python:3.12-slim` with `curl`/`unzip` to download and verify all four CLI binaries
- Stage 2 (`runtime`): `python:3.12-slim`, copy binaries from stage 1, install Python deps, add non-root user, `USER appuser`
- `HEALTHCHECK CMD celery -A app.tasks.celery_app.celery_app inspect ping -d celery@$HOSTNAME || exit 1`

**Frontend Dockerfile** (`frontend/Dockerfile`)
- Already multi-stage; add non-root user in nginx stage: `RUN addgroup -S appuser && adduser -S appuser -G appuser`
- `USER appuser` (nginx 1.27-alpine supports non-root with `listen 8080` or via `nginx -g`)
- `HEALTHCHECK CMD wget -qO- http://localhost:80/ || exit 1`

**Migrate Service** (`docker-compose.yml`)
- Add `user: "1001:1001"` to the migrate service definition

**docker-compose.yml** additions
- `cap_drop: [ALL]` on backend, worker, frontend, migrate services
- `stop_grace_period: 35s` on backend, `310s` on worker

### 2. TLS / Reverse Proxy

**`nginx/nginx.conf`** (new file, optional compose service)
- HTTP→HTTPS 301 redirect on port 80
- TLS termination on port 443 with `ssl_protocols TLSv1.2 TLSv1.3`
- `ssl_ciphers` restricted to AEAD suites
- Proxy pass to `backend:8000` and `frontend:80`
- HSTS header injection: `add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always`

**`docker-compose.yml`** — optional `reverse-proxy` service using `nginx:1.27-alpine` mounting `./nginx/nginx.conf` and a `./certs/` volume.

### 3. Security Headers

**Backend** (`app/main.py` — `SecurityHeadersMiddleware`)
- Already emits `X-Content-Type-Options`, `X-Frame-Options`, `CSP`, `Referrer-Policy`, `X-XSS-Protection`
- Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` (only when behind TLS proxy; gated on `HTTPS_BEHIND_PROXY=true` env var)

**Frontend nginx** (`frontend/nginx.conf`)
- Add `add_header` directives for all required headers
- Add `server_tokens off` to suppress nginx version
- Add gzip block
- Add cache-control rules for `/assets/` and `index.html`

### 4. Secrets Management

**`app/core/config.py`**
- Add startup validation: if `jwt_secret_key == "change-me-in-production"` raise `RuntimeError` (or `SystemExit(1)`) with a clear message
- Add `db_pool_size`, `db_max_overflow`, `db_pool_recycle`, `db_pool_timeout` fields reading from env vars

**`app/core/database.py`**
- Replace hardcoded pool params with `settings.db_pool_size` etc.
- Add 503 handling when pool is exhausted (`QueuePool` timeout → HTTP 503)

**`.env.example`**
- Add all new variables with placeholder values and comments
- Group by service section

### 5. Structured JSON Logging

**`app/core/logging_config.py`** (new file)
- Configure Python `logging` with a `JSONFormatter` (using `python-json-logger` library)
- Fields: `timestamp` (ISO-8601), `level`, `logger`, `message`, plus optional `task_name` for worker context
- Filter out `Authorization` header values and `password` fields
- Called from `app/main.py` at startup and from Celery app init

**`app/core/middleware.py`** — `RequestLoggingMiddleware`
- Already logs method/path/status/duration; ensure it uses the JSON logger and adds `user_id`

**Celery** (`app/tasks/celery_app.py`)
- Add `after_setup_logger` signal to apply JSON logging config to Celery's logger
- Worker log records include `task_name` via `task_prerun` signal

### 6. Metrics and Monitoring

**`app/core/metrics.py`** (new file)
- Use `prometheus-client` library
- Define: `http_requests_total` (Counter, labels: method, path, status), `http_request_duration_seconds` (Histogram), `db_pool_connections` (Gauge)
- Expose `/metrics` endpoint via `prometheus_client.make_asgi_app()` mounted on the FastAPI app

**Worker metrics** — use `celery-prometheus-exporter` or a custom signal-based approach:
- `celery_tasks_total` (Counter, labels: task_name, state)
- `celery_task_queue_depth` (Gauge, polled via Celery inspect)
- Expose on a separate port (`:9540`) via a lightweight HTTP server thread

**`docker-compose.monitoring.yml`** (new file)
- `prometheus` service with `prometheus.yml` scrape config targeting `backend:8000/metrics` and `worker:9540/metrics`
- `grafana` service with provisioned datasource pointing at Prometheus
- `alertmanager` service with `alertmanager.yml` webhook receiver

**`monitoring/prometheus.yml`** (new file)
**`monitoring/alertmanager.yml`** (new file)
**`monitoring/alerts.yml`** (new file) — Prometheus alerting rules:
- `BackendHighErrorRate`: `rate(http_requests_total{status=~"5.."}[5m]) / rate(http_requests_total[5m]) > 0.05`
- `WorkerHighFailureRate`: `rate(celery_tasks_total{state="failure"}[5m]) > 10/60`
- `DBPoolHighUtilization`: `db_pool_connections / (pool_size + max_overflow) > 0.8`
- `ContainerUnhealthy`: Docker health state via cAdvisor or node exporter

### 7. Redis Caching

**`app/core/cache.py`** (new file)
- `get_cached(key)` / `set_cached(key, value, ttl)` / `invalidate(key)` helpers wrapping `redis.asyncio`
- On `RedisError`: log warning, return `None` (caller falls back to DB)
- Cache key format: `reconx:{user_id}:{resource}:{params_hash}`

**Router-level integration** — decorate read-only list endpoints (targets, vulnerabilities) with cache get/set logic; invalidate on write operations.

### 8. Graceful Shutdown

**Backend** — uvicorn already handles SIGTERM; ensure `--timeout-graceful-shutdown 30` is passed in CMD.

**Worker** — Celery handles SIGTERM with `--max-tasks-per-child` and warm shutdown; set `CELERYD_TASK_SOFT_TIME_LIMIT` and ensure `stop_grace_period: 310s` in compose.

### 9. Error Handling

**`app/core/exception_handlers.py`** (new file)
- RFC 7807 Problem Details handler for `HTTPException` and unhandled exceptions
- Response shape: `{"type": "...", "title": "...", "status": 400, "detail": "...", "instance": "/path"}`
- Register on `app` in `main.py`

### 10. Database Backup

**`backup/backup.sh`** (new file)
- `pg_dump` with `--format=custom` piped to `gzip`
- Writes to `$BACKUP_DEST_PATH` (default `/backups`)
- Logs filename, size, timestamp on success; exits non-zero on failure
- Prunes files older than `$BACKUP_RETENTION_DAYS` (default 7)

**`docker-compose.yml`** — `db-backup` service using `postgres:16-alpine` image, running the script via `crond` or a simple loop.

### 11. CI/CD Pipeline

**`.github/workflows/ci.yml`** — extended:
- Job order: `secret-scan` → `backend` → `frontend` → `docker-build` → `cve-scan` → `push` (main only)
- `secret-scan`: `trufflesecurity/trufflehog` action
- `docker-build`: `docker/build-push-action` for backend, worker, frontend images
- `cve-scan`: `aquasecurity/trivy-action` with `exit-code: 1` on `CRITICAL`
- `push`: conditional on `github.ref == 'refs/heads/main'` and all prior jobs passing
- Caching: `actions/cache` for pip (`~/.cache/pip`) and npm (`~/.npm`)
- `env-check` step: Python script that diffs `Settings` field names against `.env.example` keys

### 12. Frontend nginx Hardening

**`frontend/nginx.conf`** — full rewrite:
```nginx
server_tokens off;
gzip on; gzip_types text/html text/css application/javascript application/json;
location /assets/ { add_header Cache-Control "public, max-age=31536000, immutable"; }
location = /index.html { add_header Cache-Control "no-cache"; }
add_header X-Content-Type-Options nosniff always;
add_header X-Frame-Options DENY always;
add_header Content-Security-Policy "default-src 'self'; ..." always;
add_header Referrer-Policy strict-origin-when-cross-origin always;
```

---

## Data Models

No new database tables are introduced. The following configuration fields are added to `Settings`:

| Field | Env Var | Default | Description |
|---|---|---|---|
| `db_pool_size` | `DB_POOL_SIZE` | `20` | SQLAlchemy pool_size |
| `db_max_overflow` | `DB_MAX_OVERFLOW` | `30` | SQLAlchemy max_overflow |
| `db_pool_recycle` | `DB_POOL_RECYCLE` | `3600` | Connection recycle seconds |
| `db_pool_timeout` | `DB_POOL_TIMEOUT` | `30` | Pool checkout timeout |
| `https_behind_proxy` | `HTTPS_BEHIND_PROXY` | `false` | Enables HSTS header |
| `redis_cache_ttl` | `REDIS_CACHE_TTL` | `60` | Default cache TTL seconds |
| `backup_dest_path` | `BACKUP_DEST_PATH` | `/backups` | Backup output directory |
| `backup_retention_days` | `BACKUP_RETENTION_DAYS` | `7` | Days to retain backups |
| `metrics_enabled` | `METRICS_ENABLED` | `true` | Toggle /metrics endpoint |

Prometheus metrics (in-process, no persistence):
- `http_requests_total{method, path, status}` — Counter
- `http_request_duration_seconds{method, path}` — Histogram
- `db_pool_connections` — Gauge
- `celery_tasks_total{task_name, state}` — Counter
- `celery_task_queue_depth` — Gauge

---

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system — essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: Non-root UID invariant

*For any* container in the platform (backend, worker, frontend, migrate), the effective UID of the running process must be ≥ 1000.

**Validates: Requirements 1.1, 1.2, 1.3, 1.4**

### Property 2: JWT secret guard

*For any* backend startup where `JWT_SECRET_KEY` equals `"change-me-in-production"`, the process must exit with a non-zero status code before serving any request.

**Validates: Requirements 5.3**

### Property 3: CORS wildcard rejection

*For any* backend startup where `CORS_ALLOWED_ORIGINS` contains `"*"`, the process must raise a `RuntimeError` and must not serve any requests.

**Validates: Requirements 6.2**

### Property 4: CORS origin enforcement

*For any* cross-origin HTTP request from an origin not present in `CORS_ALLOWED_ORIGINS`, the backend must respond with HTTP 403 (or omit the `Access-Control-Allow-Origin` header).

**Validates: Requirements 6.3**

### Property 5: JSON log structure invariant

*For any* log record emitted by the backend, the serialized output must be valid JSON containing at minimum the fields `timestamp`, `level`, `logger`, and `message`.

**Validates: Requirements 7.1**

### Property 6: Sensitive field redaction

*For any* HTTP request containing an `Authorization` header or a `password` field, no log record emitted during that request must contain the literal value of those fields.

**Validates: Requirements 7.5**

### Property 7: Rate limit response invariant

*For any* request that exceeds a configured rate limit, the backend must respond with HTTP 429 and the response must include a `Retry-After` header with a positive integer value.

**Validates: Requirements 11.3**

### Property 8: Cache key user-scoping

*For any* two authenticated requests from different user IDs for the same resource path, the cache keys used must be distinct (i.e., one user's cached data must never be returned to another user).

**Validates: Requirements 12.4**

### Property 9: Cache invalidation on write

*For any* write operation that modifies a cached resource, a subsequent read of that resource must not return the pre-write cached value (i.e., the cache entry must be invalidated within 1 second).

**Validates: Requirements 12.2**

### Property 10: Redis fallback

*For any* read request when Redis is unavailable, the backend must return a valid response sourced from the database and must not return HTTP 5xx due to the Redis outage alone.

**Validates: Requirements 12.3**

### Property 11: RFC 7807 error shape

*For any* 4xx or 5xx response from the backend, the response body must be valid JSON conforming to the RFC 7807 Problem Details schema (containing at minimum `status` and `detail` fields).

**Validates: Requirements 14.5**

### Property 12: Backup retention

*For any* backup run where the retention period has elapsed for one or more backup files, those files must be deleted and must not appear in the backup destination after the run completes.

**Validates: Requirements 15.5**

---

## Error Handling

### Startup Failures
- Missing required env vars → `pydantic_settings` raises `ValidationError`; process exits non-zero with field name in message.
- `JWT_SECRET_KEY == "change-me-in-production"` → explicit `SystemExit(1)` with log message `"FATAL: JWT_SECRET_KEY must be changed from the default value"`.
- `CORS_ALLOWED_ORIGINS` contains `*` → `RuntimeError` already raised in `main.py`; no change needed.

### Runtime Failures
- DB pool exhausted → `sqlalchemy.exc.TimeoutError` caught in a FastAPI exception handler → HTTP 503 with RFC 7807 body.
- Redis unavailable → `redis.exceptions.RedisError` caught in `cache.py` helpers → log warning, return `None`, caller queries DB.
- Celery task unhandled exception → `task_failure` signal increments failure counter; `_fail_scan` marks scan as failed; worker process continues.
- External tool non-zero exit → `ToolExecutionResult.returncode != 0` → `_append_warning` or `_fail_scan` depending on stage criticality.

### HTTP Error Responses
All `HTTPException` and unhandled exceptions are caught by the RFC 7807 handler registered in `main.py`. The handler maps:
- `HTTPException` → `{"status": exc.status_code, "detail": exc.detail, "title": http_status_phrase, "type": "about:blank"}`
- Unhandled `Exception` → HTTP 500, generic detail, full traceback logged as single JSON record (not exposed to client).

---

## Testing Strategy

### Unit Tests (stdlib `unittest`, no DB required)

Focus on specific examples and edge cases:

- `test_production_readiness.py`:
  - `test_jwt_secret_guard`: instantiate `Settings` with default key, assert startup validation raises.
  - `test_cors_wildcard_raises`: assert `RuntimeError` when `CORS_ALLOWED_ORIGINS="*"`.
  - `test_json_log_fields`: emit a log record through the JSON formatter, parse output, assert required fields present.
  - `test_sensitive_field_redaction`: emit a log record with `Authorization` value, assert value absent from output.
  - `test_rate_limit_429_has_retry_after`: mock a rate-limited response, assert `Retry-After` header present.
  - `test_rfc7807_shape`: call the exception handler with an `HTTPException`, assert response body has `status` and `detail`.
  - `test_cache_key_user_scoping`: call `build_cache_key(user_id=1, ...)` and `build_cache_key(user_id=2, ...)`, assert keys differ.
  - `test_backup_retention_deletes_old_files`: create temp files with old mtimes, run retention logic, assert deleted.

### Property-Based Tests

Use `hypothesis` library (add to `backend/requirements.txt`). Minimum 100 examples per test. Each test is tagged with a comment referencing the design property.

- **Feature: production-readiness, Property 5: JSON log structure invariant**
  - For any string `message` and any log level, the JSON formatter output must parse as JSON with required fields.

- **Feature: production-readiness, Property 6: Sensitive field redaction**
  - For any `Authorization` header value (arbitrary string), no log record emitted during request processing contains that value verbatim.

- **Feature: production-readiness, Property 7: Rate limit response invariant**
  - For any rate-limited endpoint and any request count exceeding the limit, the response is HTTP 429 with a positive-integer `Retry-After` header.

- **Feature: production-readiness, Property 8: Cache key user-scoping**
  - For any two distinct user IDs and any resource path, `build_cache_key` returns distinct strings.

- **Feature: production-readiness, Property 11: RFC 7807 error shape**
  - For any HTTP status code in 400–599 and any detail string, the RFC 7807 handler returns a body parseable as JSON with `status` and `detail` fields matching the inputs.

- **Feature: production-readiness, Property 12: Backup retention**
  - For any set of backup files with arbitrary timestamps and any retention period, after running the retention cleanup, no file older than the retention period remains.

### Integration / Smoke Tests

- Docker Compose `up` with test `.env` → assert all healthchecks pass within 60 seconds.
- `GET /metrics` → assert `200 OK` and body contains `http_requests_total`.
- `GET /health` → assert `{"status": "ok"}`.
- CI pipeline dry-run: assert secret-scan job runs before backend/frontend jobs.

### Property-Based Testing Configuration

Library: `hypothesis` (Python). Each property test must run a minimum of 100 examples (`@settings(max_examples=100)`). Tag format in comments:

```python
# Feature: production-readiness, Property N: <property_text>
```
