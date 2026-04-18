# Implementation Tasks: Production Readiness

## Task List

- [x] 1. Container Hardening — Non-Root Users
  - [x] 1.1 Add non-root user (`appuser`, UID 1001) to `backend/Dockerfile` and set `USER appuser` before `CMD`
  - [x] 1.2 Rewrite `worker/Dockerfile` as multi-stage build: `tools-builder` stage downloads binaries, `runtime` stage copies them and adds non-root user
  - [x] 1.3 Add non-root user to `frontend/Dockerfile` nginx stage and set `USER appuser`
  - [x] 1.4 Add `user: "1001:1001"` to the `migrate` service in `docker-compose.yml`
  - [x] 1.5 Add `cap_drop: [ALL]` to backend, worker, frontend, and migrate services in `docker-compose.yml`

- [x] 2. Container Healthchecks
  - [x] 2.1 Add `HEALTHCHECK` to `backend/Dockerfile` calling `curl -fsS http://localhost:8000/health`
  - [x] 2.2 Add `HEALTHCHECK` to `worker/Dockerfile` calling `celery inspect ping`
  - [x] 2.3 Add `HEALTHCHECK` to `frontend/Dockerfile` calling `wget -qO- http://localhost:80/`

- [x] 3. Graceful Shutdown and Compose Grace Periods
  - [x] 3.1 Update backend `CMD` in `docker-compose.yml` to pass `--timeout-graceful-shutdown 30` to uvicorn
  - [x] 3.2 Add `stop_grace_period: 35s` to the backend service in `docker-compose.yml`
  - [x] 3.3 Add `stop_grace_period: 310s` to the worker service in `docker-compose.yml`

- [x] 4. Migration Service Reliability
  - [x] 4.1 Confirm `migrate` service has `restart: "no"` in `docker-compose.yml`
  - [x] 4.2 Confirm backend and worker declare `depends_on: migrate: condition: service_completed_successfully`

- [x] 5. Secrets Management — Startup Guards
  - [x] 5.1 Add startup validation in `app/core/config.py`: if `jwt_secret_key == "change-me-in-production"` call `sys.exit(1)` with a fatal log message
  - [x] 5.2 Add `db_pool_size`, `db_max_overflow`, `db_pool_recycle`, `db_pool_timeout`, `https_behind_proxy`, `redis_cache_ttl`, `backup_dest_path`, `backup_retention_days`, `metrics_enabled` fields to `Settings` in `app/core/config.py`

- [x] 6. Database Connection Pool — Env-Var Tuning
  - [x] 6.1 Update `app/core/database.py` to read pool parameters from `settings.db_pool_size`, `settings.db_max_overflow`, `settings.db_pool_recycle`, `settings.db_pool_timeout`
  - [x] 6.2 Add a FastAPI exception handler for `sqlalchemy.exc.TimeoutError` that returns HTTP 503 with RFC 7807 body

- [x] 7. RFC 7807 Error Handling
  - [x] 7.1 Create `app/core/exception_handlers.py` with a handler that converts `HTTPException` and unhandled exceptions to RFC 7807 Problem Details JSON (`{"type", "title", "status", "detail", "instance"}`)
  - [x] 7.2 Register the RFC 7807 handler and the DB timeout handler on the FastAPI `app` in `main.py`

- [x] 8. Structured JSON Logging
  - [x] 8.1 Add `python-json-logger` to `backend/requirements.txt`
  - [x] 8.2 Create `app/core/logging_config.py` with a `configure_logging()` function that installs a `JsonFormatter` on the root logger, emitting `timestamp`, `level`, `logger`, `message` fields and filtering `Authorization`/`password` values
  - [x] 8.3 Call `configure_logging()` at the top of `app/main.py` before the app is constructed
  - [x] 8.4 Add Celery `after_setup_logger` signal in `app/tasks/celery_app.py` to apply JSON logging config; add `task_prerun` signal to inject `task_name` into log context

- [x] 9. Prometheus Metrics
  - [x] 9.1 Add `prometheus-client` to `backend/requirements.txt`
  - [x] 9.2 Create `app/core/metrics.py` defining `http_requests_total`, `http_request_duration_seconds`, and `db_pool_connections` metrics
  - [x] 9.3 Add a Starlette middleware in `main.py` (or update `RequestLoggingMiddleware`) to record request count and duration into the Prometheus metrics
  - [x] 9.4 Mount `prometheus_client.make_asgi_app()` at `/metrics` in `main.py`, gated on `settings.metrics_enabled`
  - [x] 9.5 Add Celery signal handlers in `app/tasks/celery_app.py` to track `celery_tasks_total` (success/failure) and expose a `/metrics` endpoint on port 9540 via a background thread

- [x] 10. Monitoring Stack
  - [x] 10.1 Create `monitoring/prometheus.yml` with scrape configs for `backend:8000/metrics` and `worker:9540/metrics`
  - [x] 10.2 Create `monitoring/alerts.yml` with Prometheus alerting rules for 5xx rate, worker failure rate, DB pool utilization, and container unhealthy state
  - [x] 10.3 Create `monitoring/alertmanager.yml` with a webhook receiver template
  - [x] 10.4 Create `docker-compose.monitoring.yml` with `prometheus`, `grafana`, and `alertmanager` services pre-configured to use the files above

- [x] 11. Redis Caching Layer
  - [x] 11.1 Create `app/core/cache.py` with `get_cached(key)`, `set_cached(key, value, ttl)`, and `invalidate(key)` helpers using `redis.asyncio`; on `RedisError` log a warning and return `None`
  - [x] 11.2 Apply cache get/set to the target list and vulnerability list read endpoints; invalidate on corresponding write operations
  - [x] 11.3 Ensure all cache keys include the authenticated user ID as a scope component

- [x] 12. Security Headers — HSTS
  - [x] 12.1 Update `SecurityHeadersMiddleware` in `main.py` to add `Strict-Transport-Security: max-age=31536000; includeSubDomains` when `settings.https_behind_proxy` is `True`

- [x] 13. Frontend nginx Hardening
  - [x] 13.1 Rewrite `frontend/nginx.conf` to add `server_tokens off`, gzip compression for html/css/js/json, `Cache-Control: public, max-age=31536000, immutable` for `/assets/`, `Cache-Control: no-cache` for `/index.html`, and security headers (`X-Content-Type-Options`, `X-Frame-Options`, `CSP`, `Referrer-Policy`)

- [x] 14. TLS / Reverse Proxy Configuration
  - [x] 14.1 Create `nginx/nginx.conf` with HTTP→HTTPS 301 redirect, TLS termination on port 443, `ssl_protocols TLSv1.2 TLSv1.3`, HSTS header injection, and proxy pass to backend and frontend
  - [x] 14.2 Add an optional `reverse-proxy` service to `docker-compose.yml` using `nginx:1.27-alpine` mounting `./nginx/nginx.conf` and a `./certs/` volume

- [x] 15. Database Backup Service
  - [x] 15.1 Create `backup/backup.sh`: runs `pg_dump --format=custom`, compresses output, logs filename/size/timestamp on success, exits non-zero on failure, prunes files older than `$BACKUP_RETENTION_DAYS`
  - [x] 15.2 Add a `db-backup` service to `docker-compose.yml` using `postgres:16-alpine`, mounting `./backup/backup.sh` and a backup volume, running on a configurable schedule

- [ ] 16. Environment Configuration — `.env.example` and Validation
  - [ ] 16.1 Update `.env.example` to include all new variables (`DB_POOL_SIZE`, `DB_MAX_OVERFLOW`, `DB_POOL_RECYCLE`, `DB_POOL_TIMEOUT`, `HTTPS_BEHIND_PROXY`, `REDIS_CACHE_TTL`, `BACKUP_DEST_PATH`, `BACKUP_RETENTION_DAYS`, `METRICS_ENABLED`), grouped by service with descriptive comments
  - [-] 16.2 Add a `scripts/check_env_example.py` script that diffs `Settings` field names against `.env.example` keys and exits non-zero if any are missing

- [ ] 17. CI/CD Pipeline
  - [ ] 17.1 Add a `secret-scan` job to `.github/workflows/ci.yml` using `trufflesecurity/trufflehog` that runs before all other jobs
  - [ ] 17.2 Add a `docker-build` job that builds backend, worker, and frontend images using `docker/build-push-action`
  - [ ] 17.3 Add a `cve-scan` job using `aquasecurity/trivy-action` with `exit-code: 1` on `CRITICAL` severity findings
  - [ ] 17.4 Add a `push` job conditional on `github.ref == 'refs/heads/main'` and all prior jobs passing, that pushes tagged images to the configured container registry
  - [ ] 17.5 Add `actions/cache` steps for pip (`~/.cache/pip`) and npm (`~/.npm`) to the backend and frontend jobs
  - [ ] 17.6 Add an `env-check` step to the backend CI job that runs `scripts/check_env_example.py` and fails if any Settings fields are undocumented

- [ ] 18. Property-Based and Unit Tests
  - [ ] 18.1 Add `hypothesis` to `backend/requirements.txt`
  - [ ] 18.2 Create `backend/tests/test_production_readiness.py` with unit tests: `test_jwt_secret_guard`, `test_cors_wildcard_raises`, `test_json_log_fields`, `test_sensitive_field_redaction`, `test_rfc7807_shape`, `test_cache_key_user_scoping`, `test_backup_retention_deletes_old_files`
  - [ ] 18.3 Add property-based tests to `test_production_readiness.py` using `hypothesis` for: JSON log structure invariant (Property 5), sensitive field redaction (Property 6), rate limit 429+Retry-After (Property 7), cache key user-scoping (Property 8), RFC 7807 error shape (Property 11), backup retention (Property 12)
