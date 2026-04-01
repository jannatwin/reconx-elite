# ReconX

ReconX is a full-stack bug bounty reconnaissance and security testing dashboard for a single target domain per project entry. It combines FastAPI, Celery, Redis, PostgreSQL, and React into one containerized monorepo.

## Monorepo Structure

```text
reconx/
├── backend/
├── frontend/
├── worker/
├── docker-compose.yml
└── README.md
```

## Features

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
