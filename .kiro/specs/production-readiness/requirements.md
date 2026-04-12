# Requirements Document

## Introduction

ReconX Elite is a full-stack bug-bounty reconnaissance platform (FastAPI + Celery + PostgreSQL + Redis backend, React/Vite frontend, Docker Compose orchestration). This feature covers all changes required to make the platform safe, observable, and reliable for production deployment. The scope spans Docker/container hardening, security hardening, observability, performance, reliability, CI/CD pipeline maturity, environment configuration management, and frontend production serving.

---

## Glossary

- **Platform**: The complete ReconX Elite system including all Docker Compose services.
- **Backend**: The FastAPI/uvicorn service (`backend` container).
- **Worker**: The Celery task-processing service (`worker` container).
- **Frontend**: The React/Vite application served by nginx (`frontend` container).
- **Migrate_Service**: The one-shot Alembic migration container (`migrate`).
- **Reverse_Proxy**: The TLS-terminating nginx or Traefik instance placed in front of the Platform.
- **Secrets_Store**: The mechanism used to supply sensitive values to containers (Docker secrets, environment-specific `.env`, or an external vault).
- **Health_Endpoint**: The `/health` HTTP endpoint exposed by the Backend.
- **Observability_Stack**: The combination of structured logging, metrics collection, and alerting components.
- **CI_Pipeline**: The GitHub Actions workflow that validates, tests, and optionally publishes the Platform.
- **DB_Backup_Job**: The scheduled process that creates and verifies PostgreSQL backups.

---

## Requirements

### Requirement 1: Non-Root Container Execution

**User Story:** As a platform operator, I want all containers to run as non-root users, so that a container escape does not grant root access to the host.

#### Acceptance Criteria

1. THE Backend SHALL run as a non-root OS user with UID ≥ 1000 inside its container.
2. THE Worker SHALL run as a non-root OS user with UID ≥ 1000 inside its container.
3. THE Frontend SHALL run as a non-root OS user with UID ≥ 1000 inside its container.
4. THE Migrate_Service SHALL run as a non-root OS user with UID ≥ 1000 inside its container.
5. WHEN a container is started, THE Platform SHALL not grant the container the `CAP_SYS_ADMIN` Linux capability.

---

### Requirement 2: Container Healthchecks

**User Story:** As a platform operator, I want every long-running service to declare a Docker healthcheck, so that Docker Compose and orchestrators can detect and restart unhealthy containers automatically.

#### Acceptance Criteria

1. THE Backend container SHALL declare a Docker `HEALTHCHECK` that calls `GET /health` and succeeds within 5 seconds.
2. THE Worker container SHALL declare a Docker `HEALTHCHECK` that verifies the Celery process is responsive within 10 seconds.
3. THE Frontend container SHALL declare a Docker `HEALTHCHECK` that calls `GET /` on port 80 and succeeds within 5 seconds.
4. WHEN a service fails its healthcheck 3 consecutive times, THE Platform SHALL mark that service as `unhealthy`.
5. WHEN a dependent service is `unhealthy`, THE Platform SHALL not route traffic to it.

---

### Requirement 3: TLS / HTTPS Termination

**User Story:** As a platform operator, I want all external traffic to be served over HTTPS, so that data in transit is encrypted and clients are protected from interception.

#### Acceptance Criteria

1. THE Reverse_Proxy SHALL terminate TLS for all inbound HTTP connections on port 443.
2. THE Reverse_Proxy SHALL redirect all plain HTTP requests on port 80 to HTTPS with a 301 status code.
3. THE Reverse_Proxy SHALL present a TLS certificate with a validity period greater than 0 days at the time of each request.
4. THE Reverse_Proxy SHALL support TLS 1.2 and TLS 1.3 and SHALL reject connections using TLS 1.0 or TLS 1.1.
5. WHERE a self-signed certificate is used in non-production environments, THE Reverse_Proxy SHALL still enforce TLS termination.

---

### Requirement 4: Security Headers

**User Story:** As a platform operator, I want HTTP responses to include hardened security headers, so that browsers enforce content policies and mitigate common web attacks.

#### Acceptance Criteria

1. THE Backend SHALL include an `HTTP Strict-Transport-Security` header with `max-age` ≥ 31536000 on all HTTPS responses.
2. THE Frontend SHALL include a `Content-Security-Policy` header that restricts script sources to `'self'` on all HTML responses.
3. THE Backend SHALL include `X-Content-Type-Options: nosniff` on all responses.
4. THE Backend SHALL include `X-Frame-Options: DENY` on all responses.
5. THE Frontend nginx configuration SHALL include `Referrer-Policy: strict-origin-when-cross-origin` on all responses.
6. WHEN the `CORS_ALLOWED_ORIGINS` setting does not contain a wildcard (`*`), THE Backend SHALL enforce the configured origin allowlist on all cross-origin requests.

---

### Requirement 5: Secrets Management

**User Story:** As a platform operator, I want sensitive credentials to be supplied via a Secrets_Store rather than committed to source control, so that secrets are not exposed in the repository or image layers.

#### Acceptance Criteria

1. THE Platform SHALL not include a `.env` file containing production secrets in the Docker image layers.
2. THE Secrets_Store SHALL supply `JWT_SECRET_KEY`, `POSTGRES_PASSWORD`, and all third-party API tokens to containers at runtime.
3. WHEN the `JWT_SECRET_KEY` value equals `change-me-in-production`, THE Backend SHALL refuse to start and SHALL log a fatal error.
4. THE `.env.example` file SHALL document every required secret with a placeholder value and a comment describing its purpose.
5. THE CI_Pipeline SHALL scan committed files for secret patterns and SHALL fail the build if a secret is detected.

---

### Requirement 6: CORS Configuration

**User Story:** As a platform operator, I want CORS to be locked to known production origins, so that unauthorized domains cannot make credentialed API requests.

#### Acceptance Criteria

1. THE Backend SHALL read the allowed origins list exclusively from the `CORS_ALLOWED_ORIGINS` environment variable.
2. WHEN `CORS_ALLOWED_ORIGINS` contains `*`, THE Backend SHALL raise a `RuntimeError` at startup and SHALL not serve any requests.
3. WHEN a cross-origin request arrives from an origin not in the allowlist, THE Backend SHALL respond with HTTP 403.
4. THE `.env.example` SHALL set `CORS_ALLOWED_ORIGINS` to a non-wildcard placeholder value.

---

### Requirement 7: Structured Logging

**User Story:** As a platform operator, I want all services to emit structured JSON logs, so that log aggregation tools can parse, filter, and alert on log data reliably.

#### Acceptance Criteria

1. THE Backend SHALL emit all log records as JSON objects containing at minimum `timestamp`, `level`, `logger`, and `message` fields.
2. THE Worker SHALL emit all log records as JSON objects containing at minimum `timestamp`, `level`, `logger`, `task_name`, and `message` fields.
3. WHEN an unhandled exception occurs, THE Backend SHALL log the full stack trace as a single JSON log record.
4. THE Backend SHALL log each inbound HTTP request with `method`, `path`, `status_code`, and `duration_ms` fields.
5. THE Backend SHALL not log the values of `Authorization` headers or password fields in any log record.

---

### Requirement 8: Metrics and Monitoring

**User Story:** As a platform operator, I want the Platform to expose runtime metrics, so that I can monitor service health, throughput, and resource usage in a metrics dashboard.

#### Acceptance Criteria

1. THE Backend SHALL expose a `/metrics` endpoint that returns Prometheus-compatible metrics.
2. THE Backend metrics SHALL include HTTP request count, HTTP request duration histogram, and active database connection count.
3. THE Worker SHALL expose Celery task queue depth, task success count, and task failure count as Prometheus metrics.
4. WHEN a Celery task fails, THE Observability_Stack SHALL increment the task failure counter for that task name.
5. THE Platform SHALL include a `docker-compose.monitoring.yml` override file that starts a Prometheus and Grafana instance pre-configured to scrape the Backend and Worker metrics endpoints.

---

### Requirement 9: Alerting

**User Story:** As a platform operator, I want alerts to fire when critical thresholds are breached, so that I am notified of production incidents before users are significantly impacted.

#### Acceptance Criteria

1. THE Observability_Stack SHALL fire an alert when the Backend HTTP 5xx error rate exceeds 5% of requests over a 5-minute window.
2. THE Observability_Stack SHALL fire an alert when the Worker task failure rate exceeds 10 failures per minute over a 5-minute window.
3. THE Observability_Stack SHALL fire an alert when the PostgreSQL connection pool utilization exceeds 80% of `pool_size + max_overflow`.
4. THE Observability_Stack SHALL fire an alert when any container transitions to the `unhealthy` Docker health state.
5. WHERE an alerting webhook URL is configured, THE Observability_Stack SHALL deliver alert notifications to that webhook within 60 seconds of threshold breach.

---

### Requirement 10: Database Connection Pooling

**User Story:** As a platform operator, I want database connection pool parameters to be tunable via environment variables, so that I can right-size the pool for the production host without rebuilding the image.

#### Acceptance Criteria

1. THE Backend SHALL read `DB_POOL_SIZE`, `DB_MAX_OVERFLOW`, `DB_POOL_RECYCLE`, and `DB_POOL_TIMEOUT` from environment variables with documented defaults.
2. WHEN `DB_POOL_SIZE` is not set, THE Backend SHALL default to a pool size of 20.
3. THE Backend SHALL enable `pool_pre_ping` to validate connections before use.
4. WHEN the connection pool is exhausted, THE Backend SHALL return HTTP 503 to the caller within `DB_POOL_TIMEOUT` seconds rather than blocking indefinitely.

---

### Requirement 11: API Rate Limiting

**User Story:** As a platform operator, I want all API rate limits to be configurable via environment variables, so that I can tune limits for production traffic without code changes.

#### Acceptance Criteria

1. THE Backend SHALL apply per-user rate limits to all authenticated endpoints using the user ID as the rate-limit key.
2. THE Backend SHALL apply per-IP rate limits to all unauthenticated endpoints using the client IP as the rate-limit key.
3. WHEN a rate limit is exceeded, THE Backend SHALL respond with HTTP 429 and a `Retry-After` header indicating the number of seconds until the limit resets.
4. THE Backend SHALL read all rate limit values (`REGISTER_RATE_LIMIT`, `LOGIN_RATE_LIMIT`, `SCAN_RATE_LIMIT`, etc.) from environment variables.

---

### Requirement 12: Redis Caching

**User Story:** As a platform operator, I want frequently read, rarely changing data to be cached in Redis, so that repeated API calls do not generate unnecessary database load.

#### Acceptance Criteria

1. THE Backend SHALL cache responses for read-only list endpoints (e.g., target list, vulnerability list) in Redis with a TTL of 60 seconds.
2. WHEN a write operation modifies a cached resource, THE Backend SHALL invalidate the corresponding cache entry within 1 second of the write completing.
3. WHEN Redis is unavailable, THE Backend SHALL fall back to querying the database directly and SHALL log a warning.
4. THE Backend SHALL not cache responses that contain user-specific data without scoping the cache key to the authenticated user ID.

---

### Requirement 13: Graceful Shutdown

**User Story:** As a platform operator, I want services to shut down gracefully on SIGTERM, so that in-flight requests and tasks are completed before the process exits.

#### Acceptance Criteria

1. WHEN the Backend receives SIGTERM, THE Backend SHALL stop accepting new connections and SHALL complete all in-flight HTTP requests before exiting, within a 30-second timeout.
2. WHEN the Worker receives SIGTERM, THE Worker SHALL finish any currently executing Celery task before exiting, within a 300-second timeout.
3. WHEN the graceful shutdown timeout is exceeded, THE Backend SHALL exit with a non-zero status code and SHALL log the number of requests that were terminated.
4. THE docker-compose.yml SHALL set `stop_grace_period` to at least 35 seconds for the Backend and 310 seconds for the Worker.

---

### Requirement 14: Error Handling and Fault Isolation

**User Story:** As a platform operator, I want errors in one service or scan stage to be isolated, so that a failure does not cascade and bring down the entire Platform.

#### Acceptance Criteria

1. WHEN a Celery scan stage raises an unhandled exception, THE Worker SHALL mark the scan as `failed`, log the exception, and SHALL not crash the worker process.
2. WHEN an external tool (subfinder, httpx, nuclei, gau) exits with a non-zero code, THE Worker SHALL record the failure as a scan warning or error and SHALL continue processing remaining stages where possible.
3. WHEN the Backend cannot reach Redis, THE Backend SHALL continue serving non-cached endpoints and SHALL log the connectivity error.
4. WHEN the Backend cannot reach PostgreSQL, THE Backend SHALL return HTTP 503 and SHALL log the connectivity error.
5. THE Backend SHALL return RFC 7807 Problem Details JSON for all 4xx and 5xx error responses.

---

### Requirement 15: Database Backup and Recovery

**User Story:** As a platform operator, I want automated PostgreSQL backups, so that I can recover scan data after accidental deletion or infrastructure failure.

#### Acceptance Criteria

1. THE DB_Backup_Job SHALL create a compressed PostgreSQL dump of the `reconx` database on a configurable schedule (default: daily).
2. THE DB_Backup_Job SHALL store backup files in a configurable destination path or object storage bucket.
3. WHEN a backup completes successfully, THE DB_Backup_Job SHALL log the backup file name, size in bytes, and completion timestamp.
4. WHEN a backup fails, THE DB_Backup_Job SHALL log the error and SHALL exit with a non-zero status code so that the scheduler can detect the failure.
5. THE DB_Backup_Job SHALL retain backups for a configurable number of days (default: 7) and SHALL delete backups older than the retention period.

---

### Requirement 16: CI/CD Pipeline

**User Story:** As a developer, I want a complete CI/CD pipeline, so that every pull request is automatically validated and production deployments are gated on passing tests.

#### Acceptance Criteria

1. THE CI_Pipeline SHALL run backend unit tests on every push to `main` and on every pull request targeting `main`.
2. THE CI_Pipeline SHALL run frontend lint, test, and build steps on every push to `main` and on every pull request targeting `main`.
3. THE CI_Pipeline SHALL build the backend and worker Docker images and SHALL fail the build if the image build fails.
4. THE CI_Pipeline SHALL scan Docker images for known CVEs using a container scanning tool and SHALL fail the build if a critical-severity CVE is found.
5. WHEN all CI checks pass on a push to `main`, THE CI_Pipeline SHALL push tagged Docker images to a configured container registry.
6. THE CI_Pipeline SHALL cache pip and npm dependencies between runs to complete within 10 minutes for a clean build.
7. THE CI_Pipeline SHALL run the secret-scanning check before any other step and SHALL fail immediately if a secret pattern is detected.

---

### Requirement 17: Environment Configuration Management

**User Story:** As a developer, I want a single authoritative reference for all environment variables, so that new deployments can be configured correctly without reading source code.

#### Acceptance Criteria

1. THE `.env.example` file SHALL contain every environment variable consumed by the Platform, grouped by service, with a comment describing each variable's purpose and acceptable values.
2. WHEN a required environment variable is missing at startup, THE Backend SHALL log a descriptive error naming the missing variable and SHALL exit with a non-zero status code.
3. THE Platform SHALL support a `docker-compose.override.yml` pattern for local development overrides without modifying the base `docker-compose.yml`.
4. THE CI_Pipeline SHALL validate that every variable declared in `Settings` has a corresponding entry in `.env.example`.

---

### Requirement 18: Frontend Production Build and Serving

**User Story:** As a platform operator, I want the frontend to be built for production and served securely by nginx, so that users receive optimized assets and the serving layer is hardened.

#### Acceptance Criteria

1. THE Frontend SHALL be built using `npm run build` producing minified, content-hashed static assets in the `dist/` directory.
2. THE Frontend nginx configuration SHALL set `Cache-Control: public, max-age=31536000, immutable` for all hashed static asset paths (e.g., `/assets/*`).
3. THE Frontend nginx configuration SHALL set `Cache-Control: no-cache` for `index.html` to ensure clients always fetch the latest entry point.
4. THE Frontend nginx configuration SHALL include `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and `Content-Security-Policy` headers on all responses.
5. THE Frontend nginx configuration SHALL enable gzip compression for `text/html`, `text/css`, `application/javascript`, and `application/json` MIME types.
6. WHEN a request path does not match a static file, THE Frontend nginx configuration SHALL serve `index.html` to support client-side routing.
7. THE Frontend container SHALL not expose the nginx version string in HTTP response headers.

---

### Requirement 19: Worker Dockerfile Hardening

**User Story:** As a platform operator, I want the worker container to be minimal and hardened, so that the attack surface of the container running external recon tools is reduced.

#### Acceptance Criteria

1. THE Worker Dockerfile SHALL use a multi-stage build to separate the tool-download stage from the final runtime image.
2. THE Worker Dockerfile SHALL not include build tools (curl, unzip) in the final runtime image layer.
3. THE Worker SHALL run as a non-root user in the final image.
4. THE Worker Dockerfile SHALL pin all external tool versions (subfinder, httpx, nuclei, gau) to specific release tags.
5. WHEN a tool binary download fails during image build, THE Worker Dockerfile build SHALL fail with a non-zero exit code.

---

### Requirement 20: Migration Service Reliability

**User Story:** As a platform operator, I want database migrations to run reliably as a one-shot service before the application starts, so that schema changes are applied atomically and the application never starts against a stale schema.

#### Acceptance Criteria

1. THE Migrate_Service SHALL run `alembic upgrade head` and SHALL exit with code 0 on success.
2. WHEN `alembic upgrade head` fails, THE Migrate_Service SHALL exit with a non-zero code and SHALL log the Alembic error output.
3. THE Backend and Worker services SHALL declare `depends_on: migrate: condition: service_completed_successfully` in `docker-compose.yml`.
4. THE Migrate_Service SHALL not be restarted automatically (`restart: "no"`).
5. WHEN the Migrate_Service exits with a non-zero code, THE Platform SHALL not start the Backend or Worker services.
