# ReconX Elite - Advanced Bug Bounty Platform

ReconX Elite is a **professional-grade, multi-model AI-powered bug bounty reconnaissance platform** built around a wildcard domain assessment workflow. It provides a complete solution for security researchers, covering everything from initial reconnaissance to automated vulnerability analysis and professional report generation.

The platform combines a full reconnaissance pipeline, automated vulnerability testing workflow, and a task-routed multi-model AI layer. Every phase is coordinated by an orchestrator agent that routes work to the best-fit model based on capability, reasoning depth, context window, and speed.

## 🚀 Advanced Bug Bounty Assistant

ReconX Elite is a **complete bug bounty assistant** with cutting-edge capabilities:

### 🎯 **Core Advanced Features**

- **🔍 Exploit Validation Engine** - Request replay and confirmation logic
- **🌐 Out-of-Band Interaction Tracking** - SSRF and blind XSS detection via interactsh
- **🧪 Manual Testing Suite** - Payload injection and request replay
- **🧠 Intelligence Learning System** - Pattern extraction and effectiveness tracking
- **📝 Custom Nuclei Template Engine** - Database-stored user templates
- **🛡️ AI Security Hardening** - Input sanitization and data masking
- **📄 Elite Report Generation** - CVSS/CWE/OWASP mapping
- **📊 Centralized Logging** - System validation and monitoring
- **🕵️ Advanced Recon Pipeline** - Stealth scanning, parameter discovery, content fuzzing

### 🔐 **Security-First Architecture**

- **Multi-model AI layer** with task-specific model assignments
- **Input sanitization** against prompt injection attacks
- **Data masking** for sensitive information protection
- **Rate limiting** and safety controls for all AI features
- **Structured JSON output** enforcement and validation

## 🧠 Multi-Model AI Orchestration

ReconX Elite uses a sophisticated multi-model architecture where each task is routed to the most capable model based on context length, reasoning requirements, and speed.

| Model | Assigned Role |
| :--- | :--- |
| **Nemotron 3 Nano** | Orchestrator routing agent |
| **Llama 3.3 70B** | Primary analysis, IDOR test generation, severity rating |
| **Nemotron 3 Super** | Deep chain reasoning, JWT attack analysis, SSRF escalation |
| **Qwen3 Coder 480B** | Code generation, payload creation, JS analysis |
| **GLM 4.5 Air** | Fast subdomain and host triage classification |
| **Gemma 4 26B A4B** | Structured JSON extraction from raw tool output |
| **Gemma 4 31B** | Misconfiguration and HTTP header analysis |
| **MiniMax M2.5** | Long-context JavaScript file analysis (Large context window) |
| **gpt-oss-120b** | High/Critical severity reports and executive summaries |
| **gpt-oss-20b** | Low/Medium severity report drafting |

### Orchestration Workflow

The orchestration layer follows a ten-phase decision workflow that covers the full bug bounty lifecycle from initialization through continuous monitoring. The Nemotron 3 Nano orchestrator applies escalation logic, hard-stop conditions, and model handoff rules so each task is sent to the most appropriate model at the right phase of the pipeline.

## 🕵️ Reconnaissance Pipeline

The recon pipeline covers a comprehensive suite of tools and techniques:

1. **Subdomain Enumeration**: `subfinder`, `sublist3r`, `findomain`, `crt.sh`, `massdns`, and `gobuster`. Results are deduplicated into `all_subs.txt`.
2. **Live Host Detection**: `httpx` and `httprobe`.
3. **Port Scanning**: `nmap` and `masscan`.
4. **Visual Recon**: `gowitness` for automated screenshots.
5. **URL Collection**: `gau`, `waybackurls`, `katana`, and `hakrawler`.
6. **Parameter Extraction**: All URLs with parameters are extracted into `params.txt`.
7. **JS Analysis**: Automated downloading and secret detection using `SecretFinder`, `LinkFinder`, `trufflehog`, and custom grep patterns.

## 🛡️ Vulnerability Testing Pipeline

The automated testing pipeline includes:

- **Subdomain Takeover**: `subjack` and `nuclei`.
- **Injection Attacks**: XSS (`kxss`, `dalfox`), SQL Injection (`sqlmap`, `ghauri`), and SSRF (`interactsh`).
- **Configuration Audits**: CORS misconfigurations, cloud bucket exposures (`aws-cli`, `cloud_enum`).
- **Information Leakage**: Sensitive file exposure and security header analysis.
- **Nuclei Scanning**: Full template scanning with custom and community templates.

## 🖥️ Dashboard Experience

The frontend dashboard is a dark-themed interface built to make long-running recon and testing workflows easy to monitor. It includes:

- **Pipeline Progress Tracking**: A visual progress bar for the end-to-end workflow.
- **Live Agent Log**: Streaming activity updates from the active orchestration and scanning stages.
- **Findings Management**: Severity-badged finding cards and summary views.
- **Model Activity Grid**: Real-time visibility into which AI model is currently active and what role it is performing.
- **Severity Stats**: Statistical cards for Low, Medium, High, and Critical findings.

## Architecture

```text
frontend (React/Vite, nginx in Docker)  :5173
  └─> backend (FastAPI, uvicorn)        :8000
        ├─> PostgreSQL                  :5432
        ├─> Redis (broker + result)     :6379
        └─> Celery worker
              ├─> subfinder / httpx / gau / nuclei (CLI tools)
              ├─> Exploit Validator Service
              ├─> Out-of-Band Interaction Service
              ├─> Manual Testing Service
              ├─> Intelligence Learning Service
              ├─> Custom Template Engine
              └─> AI Orchestrator (Multi-Model Integration)
```

## 🎯 Advanced Capabilities

### 🔍 **Exploit Validation & Confirmation**

- **Request replay** with payload injection
- **Automatic vulnerability confirmation** (XSS, SQLi, SSRF)
- **Confidence scoring** and detailed logging
- **Full request/response capture** with timing analysis

### 🌐 **Out-of-Band Interaction Tracking**

- **Unique callback URL generation** per user
- **SSRF and blind XSS payload management**
- **Real-time interaction recording** and analysis
- **IP geolocation and confidence assessment**

### 🧪 **Professional Manual Testing**

- **Custom HTTP request sending** with full control
- **Payload template library** (XSS, SQLi, SSRF, Path Traversal, etc.)
- **Response comparison** and differential analysis
- **Request history** and testing workflow management

### 🧠 **Intelligence Learning System**

- **Pattern extraction** from successful findings
- **Payload effectiveness tracking** and optimization
- **High-value endpoint identification**
- **Similar findings recommendations**
- **User-specific learning insights**

### 📝 **Custom Nuclei Template Engine**

- **Database-stored templates** with version control
- **Template validation** and syntax checking
- **Public template sharing** and community features
- **Template execution** with result tracking
- **Usage statistics** and success metrics

### 📄 **Elite Report Generation**

- **HackerOne-quality reports** with professional formatting
- **CVSS scoring** and vulnerability classification
- **CWE mapping** and OWASP Top 10 integration
- **Bounty estimation** based on market rates
- **AI-assisted writing** with human validation

### 🛡️ **Enterprise Security**

- **Comprehensive input validation** and sanitization
- **Sensitive data masking** and privacy protection
- **Rate limiting** and abuse prevention
- **Audit logging** and compliance features
- **Role-based access control** and permissions

### 📊 **System Monitoring & Validation**

- **Centralized logging** with structured output
- **Health checks** and system validation
- **Performance metrics** and monitoring
- **Error tracking** and alerting
- **Admin dashboard** for system management

### 🕵️ **Advanced Reconnaissance Pipeline**

- **Stealth Scanning Engine** - Rate limiting, jitter, user agent rotation
- **Parameter Discovery** - Automated parameter detection with confidence scoring
- **Content Fuzzing** - FFUF-style directory and endpoint fuzzing
- **Smart Wordlists** - Categorized wordlists with success tracking
- **Adaptive Intelligence** - Learning-based scan optimization
- **Performance Controls** - Timeout management and request limiting

## Repository layout

```text
.
├── backend/
│   ├── alembic/
│   ├── app/
│   └── requirements.txt
├── frontend/
│   ├── src/
│   └── Dockerfile
├── worker/
├── docker-compose.yml
└── .env.example
```

## Required tools

ReconX Elite expects these CLI tools inside the backend and worker runtime:

- `subfinder`
- `httpx`
- `gau`
- `nuclei`

The provided Dockerfiles install pinned versions of all four tools.

## Environment setup

**⚠️ SECURITY WARNING**: Never commit API keys or secrets to version control!

### Prerequisites

- Docker and Docker Compose
- Python 3.8+ (for local dev without Docker)
- Git

### Step 1: Configure environment

```bash
git clone <repository-url>
cd reconx-elite
cp .env.example .env
```

Edit `.env` with your settings. For AI features, set `GEMINI_API_KEY`. Optional: `CALLBACK_URL` (or equivalent) for out-of-band callbacks as documented in `.env.example`.

### Step 2: Gemini API key (AI features)

1. Visit [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Create an API key
3. Add it to `.env` as `GEMINI_API_KEY=...`

### Step 3: Start services (Docker)

```bash
docker compose up --build
```

Compose runs migrations via the `migrate` service before the API and worker start (see `docker-compose.yml`).

### Step 4: Quick checks

```bash
curl http://localhost:8000/health
curl http://localhost:8000/system/health
```

Open [http://localhost:8000/docs](http://localhost:8000/docs) for interactive API documentation.

## 🌐 Access Points

After setup, access the platform at:

- **Frontend**: http://localhost:5173
- **Backend API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs
- **API liveness**: http://localhost:8000/health
- **System health (JSON)**: http://localhost:8000/system/health
- **Admin system validation** (admin JWT required): http://localhost:8000/system/validation/admin

## Local backend workflow

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --reload
```

Run the worker in a second shell:

```bash
cd backend
.venv\Scripts\activate
celery -A app.tasks.celery_app.celery_app worker --loglevel=info
```

Frontend:

```bash
cd frontend
npm install
npm run dev
```

## Docker usage

```bash
# Set up environment variables first (see above)
cp .env.example .env
# Edit .env with your settings including GEMINI_API_KEY

# Build and start all services
docker compose up --build
```

Expected services:

- Backend API: [http://localhost:8000](http://localhost:8000)
- Frontend: [http://localhost:5173](http://localhost:5173)
- PostgreSQL: `localhost:5432`
- Redis: `localhost:6379`

Migrations are applied by the dedicated `migrate` service; the API and worker wait for it to finish successfully.

## 🔍 AI Features Usage

### Automatic Report Generation

AI reports are **automatically generated** for:

- High severity vulnerabilities
- Critical severity vulnerabilities
- Maximum 5 reports per scan (to manage API usage)

### Privacy Controls

Each target has an `enable_ai_processing` flag:

- `True` (default): AI analysis enabled
- `False`: AI processing disabled for privacy

### Report Content

Generated reports include:

- **Title & Summary**: Clear vulnerability overview
- **Technical Details**: Reproduction steps and proof of concept
- **Impact Analysis**: Business impact assessment
- **Remediation**: Technical fix recommendations
- **CVSS Score**: Estimated severity scoring
- **CWE Mapping**: Common Weakness Enumeration references
- **OWASP Top 10**: Category classification
- **Bounty Estimate**: Realistic payout range

### Safety Limits

- Rate limited: 10 AI requests per minute
- Input length capped: 10,000 characters
- Confidence scoring: Low/Medium/High
- All reports marked as "AI-assisted - manual validation required"

## API routes

Auth:

- `POST /auth/register`
- `POST /auth/login`
- `POST /auth/refresh`

Targets:

- `POST /targets`
- `GET /targets`
- `GET /targets/{id}`
- `PUT /targets/{id}`

Scans:

- `POST /scan/{target_id}`
- `POST /scan/{target_id}/config`
- `GET /scans/{scan_id}`

Bookmarks / notes / schedules:

- `GET /bookmarks`
- `POST /bookmarks`
- `DELETE /bookmarks/{id}`
- `PUT /vulnerabilities/{id}`
- `GET /schedules`
- `POST /schedules`
- `PUT /schedules/{id}`
- `DELETE /schedules/{id}`

Reports and notifications:

- `GET /notifications`
- `PUT /notifications/{id}/read`
- `GET /reports/{target_id}/json`
- `GET /reports/{target_id}/pdf`

Health:

- `GET /health`

Advanced Reconnaissance:

- `POST /advanced-recon/stealth-config/{target_id}` - Create stealth configuration
- `GET /advanced-recon/stealth-config/{target_id}` - Get stealth configuration
- `POST /advanced-recon/parameter-discovery` - Start parameter discovery
- `POST /advanced-recon/content-fuzzing` - Start content fuzzing
- `GET /advanced-recon/parameters/{target_id}` - Get discovered parameters
- `GET /advanced-recon/fuzzed-endpoints/{target_id}` - Get fuzzed endpoints
- `POST /advanced-recon/wordlists` - Create smart wordlist
- `GET /advanced-recon/wordlists` - Get wordlists
- `GET /advanced-recon/scan-modes` - Get available scan modes

Interactive OpenAPI docs are available at [http://localhost:8000/docs](http://localhost:8000/docs).

## Testing

Backend unit checks:

```bash
cd backend
python -m unittest discover -s tests
```

From the repository root you can also run:

```bash
python run_backend_tests.py
```

Recommended smoke checks after startup:

- Register, login, and refresh a user session.
- Create a target and verify `GET /targets`.
- Trigger default and configured scans.
- Poll `GET /scans/{scan_id}` until completion.
- Check for AI-generated reports on high/critical findings.
- Verify bookmarks, notes, schedules, reports, and notifications.
- Test advanced reconnaissance features:
  - Configure stealth settings for a target
  - Run parameter discovery on endpoints
  - Execute content fuzzing with different wordlists
  - Review discovered parameters and fuzzed endpoints

## 🔧 Troubleshooting

### AI Features Not Working

1. **Check API Key**: Ensure `GEMINI_API_KEY` is set in `.env`
2. **Check Logs**: Look for AI-related errors in backend logs
3. **Rate Limits**: AI features are rate-limited to prevent abuse

### Database Migration Issues

```bash
# Manually run migrations if needed
cd backend
alembic upgrade head
```

## Legal notice

Use ReconX Elite only against domains, subdomains, applications, and infrastructure you own or are explicitly authorized to assess. Running recon or vulnerability tooling without permission can violate law, platform policy, or contractual scope.
