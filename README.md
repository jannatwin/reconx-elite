# ReconX

<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
ReconX is a full-stack bug bounty reconnaissance and security testing dashboard for a single target domain per project entry. It combines FastAPI, Celery, Redis, PostgreSQL, and React into one containerized monorepo.

## Monorepo Structure

```text
reconx/
├── backend/
├── frontend/
├── worker/
├── docker-compose.yml
└── README.md
=======
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
ReconX is a full-stack bug bounty reconnaissance and security testing dashboard for a **single target domain per project entry**. It combines FastAPI, Celery, Redis, PostgreSQL, and React to run recon/security pipelines asynchronously and display results in a clean UI.

## Architecture

```text
frontend (React/Vite) -> backend (FastAPI) -> PostgreSQL
                                   |
                                   -> Redis broker -> worker (Celery + CLI tools)
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
```

## Features

<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
- JWT auth (`register` / `login`)
- Target management (add/list/view)
- Async scan execution with Celery
- CLI tool integration (`subfinder`, `httpx`, `gau`, `nuclei`)
- Structured scan results in PostgreSQL
- React dashboard with polling scan status
- Input validation + domain ownership guardrails
- Basic rate limiting on API routes

## Prerequisites

### Local (non-Docker)

- Python 3.11+
- Node.js 20+
- PostgreSQL 15+
- Redis 7+
- Security tooling in PATH:
  - `subfinder`
  - `httpx`
  - `gau`
  - `nuclei`

### Docker

- Docker Desktop (or Docker Engine + Compose)
- For full scanning support, install tools in backend and worker images (already defined in Dockerfiles).

## Environment Variables

Copy and adjust:

```bash
cp backend/.env.example backend/.env
```

Important variables:

- `DATABASE_URL`
- `REDIS_URL`
- `JWT_SECRET_KEY`
- `ACCESS_TOKEN_EXPIRE_MINUTES`
- `SCAN_ALLOWED_SCHEMES`

## Running with Docker

```bash
docker-compose up --build
```

Services:

- Backend API: `http://localhost:8000`
- Frontend: `http://localhost:5173`
- PostgreSQL: `localhost:5432`
- Redis: `localhost:6379`

## API Endpoints

Auth:

- `POST /auth/register`
- `POST /auth/login`

Targets:

- `POST /targets`
- `GET /targets`
- `GET /targets/{id}`

Scans:

- `POST /scan/{target_id}`

Health:

- `GET /health`

Interactive docs:

- `http://localhost:8000/docs`

## CLI Tool Integration Notes

ReconX uses Python `subprocess` to call the CLI binaries directly. No scan results are mocked.

- `subfinder` discovers subdomains
- `httpx` identifies live hosts
- `gau` collects known URLs
- `nuclei` checks vulnerabilities via templates

If any tool is missing, the scan records a warning/error in the scan metadata.

## Security Notes

- Scans are only run against domains explicitly added by authenticated users.
- Domain input is validated using strict hostname checks.
- API includes rate limiting middleware.
- Frontend includes an explicit legal disclaimer to authorize testing only owned/approved assets.

## Development

Backend:

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Worker:

```bash
cd worker
pip install -r requirements.txt
celery -A app.tasks.celery_app.celery_app worker --loglevel=info
```

Frontend:

```bash
cd frontend
npm install
npm run dev
```
=======
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
- JWT authentication (`register/login`)
- Target management (add/list/detail)
- Async scan execution (Celery)
- Recon integrations:
  - `subfinder` (subdomain enumeration)
  - `httpx` (live host detection)
  - `gau` (URL collection)
  - `nuclei` (template-based findings)
- Basic status tracking (`pending/running/completed/failed`)
- Polling-based real-time scan updates in frontend
- Security controls:
  - Domain normalization/validation
  - Scan only for previously added targets
  - In-memory API rate limiting middleware
  - UI disclaimer

## Project structure

```text
/reconx
├── backend/
├── frontend/
├── worker/
├── docker-compose.yml
└── README.md
```

## API Endpoints

- `POST /auth/register`
- `POST /auth/login`
- `POST /targets`
- `GET /targets`
- `GET /targets/{id}`
- `POST /scan/{target_id}`
- `GET /health`

> Authenticated routes require `Authorization: Bearer <token>`.

## Local run with Docker

### 1) Prerequisites
- Docker
- Docker Compose

### 2) Start stack

```bash
docker-compose up --build
```

Services:
- Frontend: http://localhost:5173
- Backend API docs: http://localhost:8000/docs
- PostgreSQL: localhost:5432
- Redis: localhost:6379

## Required recon tools

The worker container installs tools automatically at build time using `go install`:
- `subfinder`
- `httpx`
- `nuclei`
- `gau`

If running worker outside Docker, install them manually and ensure they are in `$PATH`.

## Environment variables

Used by backend and worker:

- `DATABASE_URL` (default `postgresql+psycopg2://reconx:reconx@db:5432/reconx`)
- `REDIS_URL` (default `redis://redis:6379/0`)
- `SECRET_KEY`
- `ALGORITHM` (optional, default `HS256`)
- `ACCESS_TOKEN_EXPIRE_MINUTES` (optional)

## Notes

- This project creates DB tables at API startup using SQLAlchemy metadata (`create_all`) for fast local onboarding.
- For production, add migrations via Alembic and harden CORS/rate-limiting with distributed storage.
- Always run scans only with explicit authorization.
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
