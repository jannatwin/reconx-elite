# AGENTS.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project overview

ReconX Elite is a full-stack bug-bounty reconnaissance platform. Users register targets (domains), trigger scans, and get back subdomains, live hosts, endpoints, vulnerabilities, JavaScript intelligence, and ranked attack paths. The stack is FastAPI + Celery + PostgreSQL + Redis (backend/worker) and React/Vite (frontend), all orchestrated via Docker Compose.

## Commands

### Docker (full stack)

```bash
cp .env.example .env          # first-time setup
docker compose up --build     # build and start all services
docker compose down           # stop
```

### Backend (local dev)

From the `backend/` directory:

```bash
python -m venv .venv
.venv\Scripts\activate        # Windows
pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --reload
```

Run the Celery worker in a second shell (same venv):

```bash
celery -A app.tasks.celery_app.celery_app worker --loglevel=info
```

Database migrations:

```bash
alembic upgrade head                          # apply all migrations
alembic revision --autogenerate -m "message"  # generate a new migration
alembic downgrade -1                          # roll back one step
```

### Frontend (local dev)

From the `frontend/` directory:

```bash
npm install
npm run dev      # dev server on :5173
npm run build    # production build
```

### Tests

Backend unit tests (stdlib `unittest`, no database required):

```bash
# Run all tests
python -m unittest discover -s tests

# Run a single test file
python -m unittest tests.test_scan_parsers

# Run a single test method
python -m unittest tests.test_scan_parsers.ScanParserTests.test_parse_nuclei_output_adds_source_and_confidence
```

Tests live in `backend/tests/` and must add `backend/` to `sys.path` themselves (see existing test files for the pattern).

## Architecture

### Service topology

```
frontend (React/Vite, nginx in Docker)  :5173
  └─> backend (FastAPI, uvicorn)        :8000
        ├─> PostgreSQL                  :5432
        ├─> Redis (broker + result)     :6379
        └─> Celery worker
              └─> subfinder / httpx / gau / nuclei (CLI tools)
```

Both `backend` and `worker` Docker images share the same Python source (`backend/app`). The worker image also installs the four recon CLI tools at pinned versions (see `worker/Dockerfile`). The backend Dockerfile does **not** include the CLI tools—it only serves the API.

### Scan pipeline (Celery chain)

Scans are the core feature. Triggering a scan (`POST /scan/{target_id}`) creates a `Scan` row and enqueues a Celery chain:

```
scan_stage_subfinder → scan_stage_httpx → scan_stage_gau → scan_stage_nuclei
```

Each stage is a separate Celery task. State is forwarded between tasks as a plain dict (`{"scan_id": ..., "subdomains": [...], "live_hosts": [...], "nuclei_targets": [...]}`). The final nuclei stage also runs header analysis, heuristic correlation, attack path ranking, payload opportunity detection, and scan-diff + notification generation.

Scan progress is tracked in `Scan.metadata_json` with fields `stage`, `stage_index`, `stage_total`, `progress_percent`, `warnings`, and `errors`. Core stage failures (subfinder/httpx/gau/nuclei) are hard failures that mark the scan `failed`. Enrichment, JS analysis, and header checks are soft-fail (warnings only).

### Backend structure

- `app/core/config.py` — `Settings` via `pydantic-settings`, reads from `.env`. All tunable behaviour (rate limits, scan caps, JWT config, CORS) is here.
- `app/core/database.py` — lazy SQLAlchemy engine + session factory. Engine is created on first use to avoid import-time DB connections. Use `get_db()` (FastAPI dep) or `get_sessionmaker()()` (Celery tasks).
- `app/core/middleware.py` — `AuthGuardMiddleware` protects routes under `/targets`, `/scan`, `/scans`, `/bookmarks`, `/notifications`, `/reports`, `/schedules`, `/vulnerabilities`. It also sets `request.state.rate_limit_key` (user ID if authenticated, IP otherwise). `RequestLoggingMiddleware` logs every request.
- `app/core/deps.py` — `get_current_user` FastAPI dependency (validates access JWT, returns `User`). `require_admin` builds on top of it.
- `app/core/security.py` — `create_access_token`, `create_refresh_token`, `decode_token`, `hash_password`, `verify_password`. Refresh tokens are stored in the DB (`RefreshToken` model) and rotated on every use.
- `app/routers/` — one file per resource. All routers import the shared `limiter` from `auth.py` to apply rate limits. Audit events are logged via `app/services/audit.py` (`log_audit_event`).
- `app/services/intelligence.py` — the largest and most complex service. Handles: URL normalization and deduplication (`normalize_endpoint_url`, `normalize_and_dedupe_urls`), endpoint scoring and tagging, subdomain enrichment (`build_subdomain_record`), JavaScript asset fetching + endpoint extraction + secret detection, heuristic vulnerability synthesis (`synthesize_heuristic_findings`), and attack path ranking (`rank_attack_paths`).
- `app/services/scan_runner.py` — thin wrappers around the four CLI tools, calling `execute_with_retry` from `tool_executor.py`.
- `app/services/tool_executor.py` — `execute_with_retry` runs a subprocess, captures stdout/stderr, retries up to `max_retries` times, returns a `ToolExecutionResult` dataclass.
- `app/services/domain.py` — `normalize_domain` validates and normalises target domain strings (lowercase, strip scheme, no forbidden chars).
- `app/tasks/scan_tasks.py` — all Celery task logic. Helper functions (`_load_scan`, `_set_stage`, `_append_warning`, `_append_error`, `_fail_scan`, `_log_step`, `_upsert_endpoints`) keep each stage handler focused. `check_scheduled_scans` is a periodic beat task.

### Data model relationships

`Target` (owner_id → User) → `Scan` (many) → `Subdomain`, `Endpoint`, `Vulnerability`, `JavaScriptAsset`, `AttackPath`, `PayloadOpportunity`, `ScanLog`, `ScanDiff`

`Endpoint` → `PayloadOpportunity` (many)

`User` → `Notification`, `Bookmark`, `ScheduledScan`, `AuditLog`

Cascade deletes are set on all scan children (`cascade="all, delete-orphan"`).

### Frontend structure

- `src/api/client.js` — Axios instance with two interceptors: (1) injects `Authorization: Bearer <token>` on every request, (2) on 401 automatically calls `/auth/refresh` (deduplicating concurrent refreshes via a shared `refreshPromise`), retries the original request, or calls `logout()` on failure.
- `src/context/AuthContext.jsx` — stores `{ accessToken, refreshToken }` in `localStorage` under `reconx_auth`. Provides `login`, `logout`, `refreshTokens`, and `isAuthenticated`.
- `src/App.jsx` — React Router routes: `/login` (public), `/` (DashboardPage, protected), `/targets/:targetId` (TargetPage, protected).
- Pages import from `src/api/client.js` directly; there is no separate API layer module.

### Auth flow

1. `POST /auth/register` or `POST /auth/login` → returns `{ access_token, refresh_token }`.
2. Access token is short-lived (default 120 min), refresh token is long-lived (default 7 days), stored in DB.
3. On 401, the frontend automatically calls `POST /auth/refresh` with the stored refresh token; the old refresh token is revoked and a new pair is issued.
4. `AuthGuardMiddleware` enforces auth at the middleware level for all protected prefixes before route handlers run.

### Environment variables

All env vars are declared in `backend/app/core/config.py` (`Settings` class). The root `.env.example` is the authoritative reference. Notable non-obvious vars:
- `BACKEND_CALLBACK_URL` — base URL of the backend, used when generating SSRF callback payloads (not in `.env.example` but present in `Settings`).
- `NUCLEI_TEMPLATES` — optional path to a local nuclei templates directory; if empty, nuclei uses its default templates.
- `TAKEOVER_CNAME_INDICATORS` — comma-separated CNAME suffixes used to flag subdomain takeover candidates.
- `SCAN_THROTTLE_SECONDS` — per-user cooldown between scan triggers (default 20s).
- `SCAN_NUCLEI_TARGET_CAP` / `SCAN_HEADER_PROBE_CAP` — hard limits on how many URLs are passed to nuclei / header probing.
