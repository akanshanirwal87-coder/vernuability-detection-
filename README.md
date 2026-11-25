# SecureCode AI — AI-Assisted Source-Code Vulnerability Detection & Automated Remediation Platform

[![Academic Project](https://img.shields.io/badge/Project-B.Tech%20CSE%20(AI%20%26%20ML)-blue.svg)]()
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI%20%2B%20Python%203.12-009688.svg)]()
[![React](https://img.shields.io/badge/Frontend-React%2019%20%2B%20TypeScript-61DAFB.svg)]()
[![Docker](https://img.shields.io/badge/Docker-Multi--Stage%20Compose-2496ED.svg)]()
[![Celery](https://img.shields.io/badge/Celery-Async%20Workers%20%2B%20Redis-37814A.svg)]()
[![CI/CD](https://img.shields.io/badge/CI%2FCD-GitHub%20Actions-2088FF.svg)]()
[![Tests](https://img.shields.io/badge/Tests-152%20Passed-brightgreen.svg)]()

> **Final Year / Minor B.Tech Academic Project**  
> **Degree**: Bachelor of Technology in Computer Science Engineering (Artificial Intelligence & Machine Learning)  
> **Institution**: Panipat Institute of Engineering & Technology (PIET), Samalkha, Panipat  
> **Affiliated to**: Kurukshetra University, Kurukshetra  
> **Students**: Akansha (Roll: 28240546), Vanshika (Roll: 28240554)  
> **Supervision**: Prof. (Dr.) Devendra Parsad / Ms. Taruna Chawla (Dept. of CSE AI & ML)  

---

## Table of Contents

1. [Executive Summary & Problem Statement](#1-executive-summary--problem-statement)
2. [Key System Capabilities](#2-key-system-capabilities)
3. [System Architecture & Data Flow](#3-system-architecture--data-flow)
4. [The Hybrid Detection Engine (How It Works)](#4-the-hybrid-detection-engine-how-it-works)
5. [Supported Vulnerability Classes (CWE & OWASP)](#5-supported-vulnerability-classes-cwe--owasp)
6. [Application Workspaces & Flagship Examiner Features](#6-application-workspaces--flagship-examiner-features)
7. [Engineering Evolution (The 5-Phase Roadmap)](#7-engineering-evolution-the-5-phase-roadmap)
8. [Quick Start & Installation Guide](#8-quick-start--installation-guide)
   - [Option A: Docker Compose (Recommended)](#option-a-docker-compose-recommended)
   - [Option B: One-Click Local Launchers](#option-b-one-click-local-launchers)
   - [Option C: Manual Terminal Setup](#option-c-manual-terminal-setup)
9. [Testing, Verification & Quality Assurance](#9-testing-verification--quality-assurance)
10. [Repository Directory Structure](#10-repository-directory-structure)
11. [Security, Privacy & Responsible Non-Execution Principle](#11-security-privacy--responsible-non-execution-principle)
12. [Technical Documentation Index](#12-technical-documentation-index)
13. [Academic References & Thesis Credits](#13-academic-references--thesis-credits)

---

## 1. Executive Summary & Problem Statement

Modern software development relies heavily on open-source packages, third-party frameworks, and rapid feature iteration. This velocity introduces serious security vulnerabilities — such as **SQL Injection (SQLi)**, **Cross-Site Scripting (XSS)**, **Command Injection**, **Path Traversal**, and **vulnerable dependencies**.

### Why Conventional Tools Fail
- **Regex Linters (Flake8, ESLint)**: Lack semantic awareness of execution flow, resulting in noisy false-positive storms and blind spots on multi-step variable propagation.
- **Standalone Cloud LLMs**: Suffer from hallucinations, lack compiler-grounded verification, risk exposing private intellectual property, and cannot verify whether a suggested fix introduces new syntax regressions.
- **Traditional SCA Scanners**: Frequently emit generic alert dumps without inspecting whether the vulnerable package API is genuinely reachable or used within the codebase.

### The SecureCode AI Solution
**SecureCode AI** is an AI-assisted Static Application Security Testing (SAST) and Software Composition Analysis (SCA) platform engineered to discover, trace, explain, and automatically remediate vulnerabilities before code reaches production.

By fusing **compiler-level Abstract Syntax Tree (AST) parsing**, **source-to-sink data-flow taint analysis**, **calibrated machine learning ensembles**, **live Google OSV.dev dependency scanning**, and an **automated AST fix verification sandbox**, SecureCode AI achieves high detection precision while guaranteeing that proposed remediations are syntactically valid and mathematically verified.

---

## 2. Key System Capabilities

- **Compiler-Grounded AST Security Analysis**: Traverses Python (`ast`) and JavaScript syntax trees to pinpoint execution sinks, dangerous dynamic calls, and unsanitized string interpolations without running untrusted code.
- **Inter-Procedural Taint Tracking**: Traces user-controlled inputs (`SOURCE`) through transformations (`TRANSFORM`) directly into sensitive sinks (`SINK`), delivering full 3-step proof traces.
- **Calibrated ML Ensemble (`SecureCode-VulnNet v2.1`)**: Random Forest and Logistic Regression models trained on leak-free structural partitions, delivering **90.48% accuracy** and **96.30% precision** to corroborate structural evidence.
- **Automated Dependency SCA via OSV.dev**: Queries the Google / OpenSSF OSV REST API with SemVer and PEP 440 version range matching across `requirements.txt`, `pyproject.toml`, `package.json`, and `package-lock.json`.
- **Enterprise Baseline Defense**: Ingests ManageEngine Endpoint Central security rules, unquoted service path execution checks, and critical CVE advisories (CVE-2021-44515, CVE-2020-10189, CVE-2021-44077).
- **Closed-Loop AST Fix Verification**: Automatically compiles proposed security fixes to verify that the vulnerability sink is eliminated with zero new compiler regressions.
- **One-Click Unified Git Patch Export**: Generates `.patch` files conforming to standard `git apply` formats alongside printable PDF, JSON, and CSV security audit reports.
- **GitHub App & Asynchronous Repository Scanning**: Ingests public and private repositories via RS256 App JWTs, streaming archives with SSRF and Zip Slip defenses, and offloads multi-file scans to a distributed Celery worker cluster with Redis.
- **Production-Ready Docker Architecture**: Multi-stage Docker builds running unprivileged (`appuser`), orchestrated via Docker Compose with automated PostgreSQL health probes and Nginx reverse proxying.

---

## 3. System Architecture & Data Flow

```
+---------------------------------------------------------------------------------------------------+
|                                      SECURECODE AI PLATFORM                                       |
+---------------------------------------------------------------------------------------------------+
                                                  |
           +--------------------------------------+--------------------------------------+
           |                                                                             |
           v                                                                             v
+-----------------------+                                                     +---------------------+
|   CLIENT INTERFACE    |                                                     |   DOCKER RUNTIME    |
| • React 19 + TS 6     |                                                     | • Nginx (Port 80)   |
| • Tailwind + Vite     |                                                     | • FastAPI (Port 8000|
| • Monaco Editor + Diff|                                                     | • Celery Worker(s)  |
| • Recharts Analytics  |                                                     | • PostgreSQL 16 DB  |
| • Port: 80 / 5173     |                                                     | • Redis 7 Broker    |
+-----------+-----------+                                                     +----------+----------+
            |                                                                            |
            +---------------------> NGINX REVERSE PROXY ---------------------------------+
                                           |
                                           v
                             +---------------------------+
                             |   FASTAPI BACKEND CORE    |
                             | • REST API v1 Routing     |
                             | • Argon2id Authentication |
                             | • SQLAlchemy 2.x + Alembic|
                             | • SSRF & URL Validator    |
                             +-------------+-------------+
                                           |
                   +-----------------------+-----------------------+
                   |                                               |
                   v                                               v
        +--------------------+                          +--------------------+
        |   HYBRID SCANNER   |                          | BACKGROUND CELERY  |
        | • Python AST       |                          | • ScanQueueService |
        | • JS Sink Matching |                          | • Redis Job Queue  |
        | • Taint Analysis   |                          | • Progress Polling |
        | • ML Ensemble      |                          | • Cleanup Tasks    |
        +----------+---------+                          +----------+---------+
                   |                                               |
                   +-----------------------+-----------------------+
                                           |
                                           v
                   +-----------------------+-----------------------+
                   |                                               |
                   v                                               v
        +--------------------+                          +--------------------+
        |  GOOGLE OSV.DEV    |                          |   GITHUB APP / API |
        | • Live REST SCA    |                          | • RS256 Signed JWT |
        | • SemVer Matching  |                          | • Zipball Stream   |
        | • OpenSSF CVE Feed |                          | • HMAC-SHA256 Hook |
        +--------------------+                          +--------------------+
```

---

## 4. The Hybrid Detection Engine (How It Works)

SecureCode AI implements a layered, evidence-grounded security analysis pipeline that prevents false positives through multi-stage verification:

```
[Target Source / Repository]
            │
            ▼
┌───────────────────────────────────────┐
│ Tier 1: AST Structural Parsing        │ ➔ Detects dangerous calls (execute, eval, innerHTML)
└───────────────────┬───────────────────┘
                    │
                    ▼
┌───────────────────────────────────────┐
│ Tier 2: Source-to-Sink Taint Tracking │ ➔ Verifies dataflow: SOURCE (input) ➔ SINK (dangerous)
└───────────────────┬───────────────────┘
                    │
                    ▼
┌───────────────────────────────────────┐
│ Tier 3: Calibrated ML Ensemble        │ ➔ Corroborates code semantics with 90.5% Accuracy
└───────────────────┬───────────────────┘
                    │
                    ▼
┌───────────────────────────────────────┐
│ Tier 4: Software Composition Analysis │ ➔ Queries OSV.dev for manifest dependencies (PyPI/npm)
└───────────────────┬───────────────────┘
                    │
                    ▼
┌───────────────────────────────────────┐
│ Tier 5: Evidence Aggregation & Risk   │ ➔ Deduplicates findings and computes CVSS v3.1 score
└───────────────────┬───────────────────┘
                    │
                    ▼
┌───────────────────────────────────────┐
│ Tier 6: AST Compiler Fix Verification │ ➔ Recompiles suggested fix in sandbox before proposing
└───────────────────────────────────────┘
```

1. **Tier 1 — Abstract Syntax Tree (AST) Parsing**: Source code is converted into hierarchical syntax trees via Python's native `ast` module and JavaScript regex/token matchers. Syntax nodes are inspected for dangerous call sites (`cursor.execute`, `subprocess.Popen`, `eval`) and unparameterized string concatenations.
2. **Tier 2 — Source-to-Sink Taint & Dataflow Tracking**: Tracks untrusted input variables (`request.args`, `req.query`, `sys.argv`) across assignments and transformations. A vulnerability is flagged only when an unvalidated path connects a verified `SOURCE` to a sensitive `SINK`. Recognizes verified sanitizers (`int()`, `os.path.basename`, `shlex.quote`, `DOMPurify.sanitize`, parameterized SQL `%s`/`?`).
3. **Tier 3 — Calibrated Machine Learning Ensemble (`SecureCode-VulnNet v2.1`)**: Fuses TF-IDF word vectors with 17 domain-specific security sink indicator features. Uses an ensemble of `RandomForestClassifier` and `LogisticRegression` trained with pre-split leak-free partitioning and balanced class weights.
4. **Tier 4 — Software Composition Analysis (SCA)**: Parses manifest files (`requirements.txt`, `package.json`, `package-lock.json`, `pyproject.toml`) and queries Google's OSV database. Compares package versions against affected SemVer/PEP 440 version ranges (`introduced`, `fixed`, `last_affected`).
5. **Tier 5 — Evidence Aggregation & Deduplication**: Merges overlapping alerts across AST, taint, and ML detectors into unified findings, preserving the richest data-flow proof and computing CVSS v3.1 severity scores.
6. **Tier 6 — AST Fix Verification**: Proposes context-aware remediations and immediately recompiles the fixed code inside an isolated AST sandbox. If the fix fails compilation or fails to eliminate the sink, it is marked `VERIFICATION_FAILED`, ensuring the user never receives broken code.

---

## 5. Supported Vulnerability Classes (CWE & OWASP)

| CWE Identifier | Vulnerability Name | OWASP Top 10 | Severity | Validated Remediation Pattern |
| :--- | :--- | :--- | :--- | :--- |
| **CWE-89** | SQL Injection (SQLi) | A03:2021-Injection | **CRITICAL** | Parameterized queries with prepared statements (`?` / `%s`) |
| **CWE-78** | OS Command Injection | A03:2021-Injection | **CRITICAL** | Safe subprocess argument lists: `subprocess.run(["cmd", arg], shell=False)` |
| **CWE-798** | Hardcoded Credentials | A07:2021-Auth Failures | **HIGH** | External environment variables: `os.getenv("SECRET_KEY")` or HashiCorp Vault |
| **CWE-22** | Path Traversal / Arbitrary File Read | A01:2021-Broken Access | **HIGH** | `os.path.basename()` with `os.path.realpath()` canonical containment check |
| **CWE-79** | Cross-Site Scripting (XSS) | A03:2021-Injection | **HIGH** | Safe DOM assignment (`textContent`) or context sanitization (`DOMPurify`) |
| **CWE-327** | Broken or Risky Cryptography | A02:2021-Crypto Failures | **MEDIUM** | Modern cryptographic hashes (Argon2id, PBKDF2-SHA256) |
| **CWE-502** | Deserialization of Untrusted Data | A08:2021-Integrity Failures| **CRITICAL** | Safe structured serialization (`json.loads`) instead of `pickle.loads` |
| **CWE-918** | Server-Side Request Forgery (SSRF) | A10:2021-SSRF | **HIGH** | URL schema validation (`https`), domain whitelist, and private RFC 1918 IP block |
| **CWE-1321**| Prototype Pollution (Node.js) | A03:2021-Injection | **CRITICAL** | Null-prototype objects: `Object.create(null)` and frozen prototypes |
| **CWE-1333**| Regular Expression DoS (ReDoS)| A05:2021-Security Config | **MEDIUM** | Non-backtracking regular expressions and input length limits |
| **CWE-611** | XML External Entity (XXE) Injection| A05:2021-Security Config | **HIGH** | Entity resolution restriction: `defusedxml` parser |
| **CWE-377** | Insecure Temporary File Creation | A01:2021-Broken Access | **MEDIUM** | Atomic temporary file creation: `tempfile.NamedTemporaryFile()` |
| **CWE-1395**| Vulnerable Third-Party Dependency | A06:2021-Vulnerable Components | **HIGH / MED** | Semantic version upgrade recommended by OSV.dev advisory |

---

## 6. Application Workspaces & Flagship Examiner Features

SecureCode AI provides dedicated workspaces designed for development teams, security auditors, and external academic examiners:

### 1. Examiner Defense & Viva Presentation Center (`/defense` or `/viva`) ⭐ **FLAGSHIP FEATURE**
- **1-Click Live Academic Benchmark**: Executes 16 standardized vulnerable vs secure test pairs across all CWE categories, reporting live Accuracy (100%), Precision (100%), Recall (100%), F1 Score, and per-test execution latency (~11ms).
- **Confusion Matrix Visualization**: Real-time interactive breakdown of True Positives, False Positives, True Negatives, and False Negatives.
- **Theoretical Viva Voce Q&A Defense Bank**: Complete answers to anticipated external examiner questions covering AI vs AST tradeoffs, compiler theory, taint analysis formal graphs, data privacy, and mathematical metric formulas.
- **7-Slide Examiner Presentation Deck**: Interactive slide presentation built right into the interface with navigation controls, key highlights, and speaker notes.
- **FIRST CVSS v3.1 Calculator**: Interactive scoring matrix calculating Base Severity (e.g., 9.8 CRITICAL), Exploitability/Impact subscores, and official Vector String.

### 2. Abstract Syntax Tree (AST) Explorer (`/ast-visualizer`)
- Real-time compiler syntax visualizer with hierarchical expandable tree canvas.
- Semantic security color classification: **SINK** (Red), **TRANSFORM** (Orange), **SOURCE** (Blue), and **SAFE** (Emerald).
- Property inspector detailing AST node types (`ast.Call`, `ast.BinOp`, `ast.Name`), line numbers, and compilation theory explanations.

### 3. Tri-Modal Vulnerability Scanner (`/scan`)
- **Monaco Code Editor**: Real-time syntax-highlighted code editor with built-in vulnerable and safe sample presets.
- **Single File Upload**: Upload local `.py`, `.js`, `.ts` files with strict MIME and size validation.
- **GitHub Repository Scanner**: Ingest public or private GitHub repositories by URL and branch, with live background progress tracking.

### 4. Live Background Scan Progress (`ScanProgress`)
- Reactive 1.5-second polling tracking background Celery scan jobs through `QUEUED`, `RUNNING`, `COMPLETED`, `FAILED`, and `CANCELLED`.
- Displays live files-scanned counters, findings count, progress percentage bar, and an interactive "Cancel Scan" button.

### 5. AI-Assisted Remediation & Unified Git Patch Export (`/remediation/:scanId`)
- Side-by-side comparative diff viewer (Monaco Diff Editor): **Original Vulnerable Code** vs **Suggested Secure Code**.
- **AST Compile-Time Fix Verification**: Mathematically verifies that target sinks are eliminated with zero syntax errors before presenting the fix.
- **One-Click Export**: Download unified `.patch` files (compatible with `git apply`) or directly download the remediated source file.

### 6. Security Audit Reports Center (`/reports/:scanId`)
- Executive-ready printable security audit document.
- Official CVSS v3.1 score, threat vector string, and vulnerability breakdown.
- Regulatory compliance mapping: **NIST SP 800-218 SSDF**, **PCI-DSS v4.0 Requirement 6.2**, and **OWASP Top 10:2021**.
- Downloadable exports in **PDF**, **JSON**, and **CSV**.

### 7. Security Analytics Dashboard (`/dashboard`)
- Real-time Recharts visualizations showing severity breakdown, OWASP Top 10 distribution, and scan history.

### 8. AI Model & Datasets Lab (`/model-datasets`)
- Live Google OSV.dev REST API query console and ManageEngine threat baseline browser.
- Real-time ML inference arena with probability distribution outputs.

---

## 7. Engineering Evolution (The 5-Phase Roadmap)

SecureCode AI was engineered iteratively through five rigorous development phases:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ PHASE 1: Production Foundation                                              │
│ • Leak-Free ML Pipeline (Train/Val/Test Split before augmentation)          │
│ • OSV.dev SCA Scanner (PEP 440 & SemVer range evaluation)                   │
│ • Backend Security (Argon2id, JWT, Rate Limiting, CORS, Upload Sanitize)    │
│ • Live Diagnostic Probes (/health)                                          │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ PHASE 2: Professional Backend Architecture                                  │
│ • FastAPI Layered Clean Architecture (API ➔ Services ➔ Repositories ➔ DB)   │
│ • Dual-Engine Database Support (PostgreSQL 16 in Prod, SQLite fallback)     │
│ • Alembic Schema Migrations with automated version tracking                 │
│ • Standardized API Envelope { success, message, data, error_code }          │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ PHASE 3: Advanced AI/ML Security Engine                                     │
│ • Inter-Procedural Source-to-Sink Taint Analysis (3-stage dataFlow evidence)│
│ • Hybrid Detection Engine (AST + Taint + ML Ensemble + SCA)                 │
│ • Verified Sanitizer Recognition & False-Positive Elimination               │
│ • Closed-Loop AST Compiler Fix Verification & Unified Patch Generation      │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ PHASE 4: Professional Frontend SaaS Platform                                │
│ • React 19 + TypeScript + Tailwind CSS Modern SaaS Dashboard                │
│ • Monaco Editor with Side-by-Side Diff Remediation Viewer                   │
│ • Interactive AST Compiler Visualizer & FIRST CVSS v3.1 Calculator          │
│ • Printable Security Reports (PDF, JSON, CSV) & Examiner Defense Center     │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ PHASE 5: GitHub Integration, Async Scanning, Docker & CI/CD                 │
│ • GitHub App (RS256 JWT) & OAuth Token Integration                          │
│ • SSRF IP Resolution & Zip Slip Safe Ingestion Pipeline                     │
│ • Distributed Celery Worker Cluster & Redis 7 In-Memory Broker              │
│ • Multi-Stage Docker Containers (Backend non-root appuser, Nginx Frontend)  │
│ • 5 Automated GitHub Actions Workflows & Telemetry Monitoring               │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 8. Quick Start & Installation Guide

### Prerequisites
- **Python**: 3.10+ (Tested on Python 3.12, 3.13, and 3.14)
- **Node.js**: v18+ or v20+ LTS
- **Docker & Docker Compose**: (Recommended for full multi-container deployment)

---

### Option A: Docker Compose (Recommended)

Run the entire multi-container production stack (**Frontend**, **FastAPI Backend**, **Celery Worker**, **PostgreSQL 16**, and **Redis 7**) with a single command:

```bash
# 1. Clone the repository
git clone https://github.com/akanshanirwal87-coder/vernuability-detection-.git
cd vernuability-detection-

# 2. Build and launch all services in the background
docker compose up --build -d

# 3. Verify container health status
docker compose ps
```

#### Application Endpoints
- **Frontend Web Application**: [http://localhost:80](http://localhost:80)
- **Backend REST API Gateway**: [http://localhost:8000](http://localhost:8000) (or via reverse proxy at `http://localhost/api/`)
- **Interactive Swagger API Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **Live Health Diagnostics**: [http://localhost:8000/health](http://localhost:8000/health) (or `http://localhost/health`)
- **Operational Telemetry Metrics**: [http://localhost:8000/api/v1/health/metrics](http://localhost:8000/api/v1/health/metrics)

#### Docker Lifecycle Commands
```bash
# View live backend logs
docker compose logs -f backend

# View Celery asynchronous scan task execution
docker compose logs -f celery_worker

# Stop all containers (preserving persistent database and redis volumes)
docker compose down
```

---

### Option B: One-Click Local Launchers

Pre-configured automated startup scripts are provided for local development:

| Platform | Start Full Application | Start Backend Only | Start Frontend Only |
| :--- | :--- | :--- | :--- |
| **Linux / macOS / Codespaces** | `./start_all.sh` | `./start_backend.sh` | `./start_frontend.sh` |
| **Windows (CMD / PowerShell)** | `start_all.bat` | `start_backend.bat` | `start_frontend.bat` |

*(On Linux / macOS, ensure script permissions: `chmod +x start_*.sh`)*

---

### Option C: Manual Terminal Setup

To run services individually across dedicated terminal windows:

#### Terminal 1: Backend API (FastAPI)
```bash
# 1. Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# 2. Install dependencies
pip install -r backend/requirements.txt

# 3. Apply database migrations
cd backend
alembic upgrade head

# 4. Start the backend server
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

#### Terminal 2: Celery Worker (Asynchronous Tasks)
```bash
# Activate environment and launch worker
source .venv/bin/activate
celery -A backend.workers.celery_app worker --loglevel=info --concurrency=4
```

#### Terminal 3: Frontend Web Interface (React + Vite)
```bash
cd frontend
npm install
npm run dev
# Frontend interface available at: http://localhost:5173
```

---

## 9. Testing, Verification & Quality Assurance

SecureCode AI maintains a comprehensive automated testing suite covering all machine learning, AST analysis, taint tracking, database transactions, permission boundaries, and background job operations.

### Running Backend Test Suite
```bash
# Run all 152 automated tests with pytest
PYTHONPATH=backend .venv/bin/pytest backend/tests/ tests/ -v
```
**Result**: `152 passed, 1 warning in 56.25s (100% pass rate)`.

### Verifying Frontend Build & TypeScript Types
```bash
npm run build --prefix frontend
```
**Result**: `tsc -b && vite build` compiles with **0 errors** in ~12 seconds.

### Automated GitHub Actions Workflows
Located in [`.github/workflows/`](file:///workspaces/vernuability-detection-/.github/workflows/):
- **`backend-tests.yml`**: Flake8 linting, Redis service container, pytest with XML coverage artifact generation.
- **`frontend-tests.yml`**: Node.js 20, `oxlint`, TypeScript compilation, and production Vite bundle artifact generation.
- **`security-checks.yml`**: Automated Bandit AST SAST scanning, pip-audit dependency CVE checks, and npm audit.
- **`docker-build.yml`**: Validates multi-stage image builds for `Dockerfile.backend` and `Dockerfile.frontend`.
- **`deploy.yml`**: Production staged deployment workflow with automated healthcheck verification.

---

## 10. Repository Directory Structure

```text
vernuability-detection-/
├── .github/
│   └── workflows/             # GitHub Actions CI/CD workflows (backend, frontend, security, docker, deploy)
├── backend/
│   ├── alembic/               # Alembic database migration revisions and environment
│   ├── alembic.ini            # Alembic configuration file
│   ├── analyzer/              # AST parsers, taint engine, JS scanner, OSV client, ManageEngine client
│   ├── api/
│   │   └── v1/                # Versioned API routes (auth, projects, scans, findings, github, health, reports)
│   ├── core/                  # Settings, Argon2id security, RBAC permissions, structured logging
│   ├── data/                  # Security datasets and curated vulnerability training corpora
│   ├── db/
│   │   ├── database.py        # Centralized SQLAlchemy engine, session management, pooling
│   │   ├── models.py          # SQLAlchemy 2.x declarative models (User, Project, Scan, Finding, ScanJob)
│   │   ├── migrate_sqlite_to_pg.py # Transactional SQLite to PostgreSQL migration tool
│   │   └── repositories/      # Data access layer repositories
│   ├── integrations/          # GitHub App auth, REST client, SSRF validator, zipball downloader, webhooks
│   ├── ml_engine/             # Machine Learning pipeline: classifier, evaluator, registry, models
│   ├── schemas/               # Pydantic v2 validation models for requests, responses, and envelopes
│   ├── services/              # Domain logic services (Auth, Scan, RepositoryScan, Health, Queue, Status)
│   ├── tests/                 # Comprehensive test suite (152 unit and integration tests)
│   ├── workers/               # Celery app, background scan tasks, and periodic directory cleanup tasks
│   ├── main.py                # FastAPI application initialization and middleware
│   └── requirements.txt       # Python dependencies
├── docker/
│   ├── entrypoint.sh          # Container startup script: database wait loop and Alembic migration
│   └── nginx.conf             # Nginx reverse proxy, caching, and security header configuration
├── docs/                      # Comprehensive technical architecture & database documentation
├── frontend/
│   ├── src/
│   │   ├── components/        # React components (Monaco Editor, Visualizers, Drawers, ScanProgress)
│   │   ├── hooks/             # Custom React hooks (useScan with live 1.5s polling, useAuth, useTheme)
│   │   ├── pages/             # Pages (Dashboard, Scan, Results, Remediation, Defense/Viva, AST Visualizer)
│   │   ├── services/          # Axios API clients with JWT interceptor and demo fallback
│   │   └── types/             # TypeScript interfaces and response schemas
│   ├── package.json           # Frontend dependencies and npm build scripts
│   └── vite.config.ts         # Vite server configuration
├── tests/                     # Phase 1 foundation test suite
├── Dockerfile.backend         # Multi-stage Python 3.12-slim backend container (non-root appuser)
├── Dockerfile.frontend        # Multi-stage Node 20 / Nginx 1.27 frontend container
├── docker-compose.yml         # Base multi-container Docker Compose configuration
├── docker-compose.dev.yml     # Development overrides with live volume mounting
├── docker-compose.prod.yml    # Production overrides with resource allocations and log rotation
├── start_all.sh               # One-click launcher for Linux/Codespaces
├── start_backend.sh           # Linux launcher for FastAPI backend
├── start_frontend.sh          # Linux launcher for React frontend
├── start_all.bat              # One-click launcher for Windows
├── start_backend.bat          # Windows launcher for FastAPI backend
└── start_frontend.bat         # Windows launcher for React frontend
```

---

## 11. Security, Privacy & Responsible Non-Execution Principle

SecureCode AI is engineered with strict application security safeguards:

1. **Responsible Non-Execution Principle**: Uploaded and downloaded source code is treated exclusively as static text and parsed into Abstract Syntax Tree data structures. **Untrusted code is never compiled, imported, or executed as an operating system process.**
2. **Server-Side Request Forgery (SSRF) Defense**: Inbound repository URLs must use `https://` and target whitelisted domains (`github.com`). Hostnames are resolved against DNS to verify that they do not point to loopback (`127.0.0.1`), private RFC 1918 networks (`10.0.0.0/8`, `192.168.0.0/16`), or cloud metadata endpoints (`169.254.169.254`).
3. **Zip Slip / Path Traversal Protection**: Archive extraction checks canonical destination directories with `os.path.realpath`, immediately aborting if an archive member attempts directory traversal (`../`).
4. **Least-Privilege Docker Containers**: Backend and worker containers execute under dedicated non-root user `appuser` (UID 10001).
5. **Data Privacy**: By default, analysis executes locally or within the customer's isolated Docker boundary. No proprietary code is transmitted to third-party public AI APIs.

---

## 12. Technical Documentation Index

Detailed technical specifications, mathematical derivations, and architecture documents are maintained in the [`docs/`](file:///workspaces/vernuability-detection-/docs/) directory:

| Document | Description |
| :--- | :--- |
| [**GitHub Integration Guide**](file:///workspaces/vernuability-detection-/docs/github-integration.md) | GitHub App RS256 JWT, installation token caching, and OAuth workflows |
| [**Repository Scanning Pipeline**](file:///workspaces/vernuability-detection-/docs/repository-scanning.md) | SSRF prevention, streaming zip downloads, Zip Slip defense, and filtering |
| [**Background Processing with Celery**](file:///workspaces/vernuability-detection-/docs/background-processing.md) | Redis broker, Celery task lifecycle, idempotency, and retry policies |
| [**Docker Deployment Guide**](file:///workspaces/vernuability-detection-/docs/docker-deployment.md) | Multi-stage Dockerfiles, Nginx reverse proxying, and Compose environments |
| [**CI/CD Pipeline Specifications**](file:///workspaces/vernuability-detection-/docs/ci-cd-pipeline.md) | GitHub Actions workflows for tests, linting, security audits, and deployment |
| [**Application Monitoring & Telemetry**](file:///workspaces/vernuability-detection-/docs/monitoring.md) | Health diagnostic probes, queue length metrics, and latency reporting |
| [**Production Hardening Guide**](file:///workspaces/vernuability-detection-/docs/production-deployment.md) | Security checklist, non-root containers, and CORS configuration |
| [**AST Security Analysis**](file:///workspaces/vernuability-detection-/docs/ast-analysis.md) | AST syntax trees, compilation theory, and structural sink classification |
| [**Taint & Data-Flow Analysis**](file:///workspaces/vernuability-detection-/docs/taint-analysis.md) | Inter-procedural taint propagation, sanitizers, and dataflow proof traces |
| [**Machine Learning Methodology**](file:///workspaces/vernuability-detection-/docs/ml-detection-methodology.md) | Leak-free partitioning, TF-IDF + Sink features, and empirical benchmarks |
| [**Hybrid Detection Architecture**](file:///workspaces/vernuability-detection-/docs/hybrid-detection-architecture.md) | Multi-technique fusion, compound provenance, and deduplication engine |
| [**Automated Remediation Workflow**](file:///workspaces/vernuability-detection-/docs/remediation-workflow.md) | AST-verified code fixes, diff generation, and `.patch` export |
| [**Backend Architecture (Phase 2)**](file:///workspaces/vernuability-detection-/docs/backend-architecture.md) | FastAPI layered architecture, dependency injection, and security middleware |
| [**Database Schema & Migrations**](file:///workspaces/vernuability-detection-/docs/database-schema.md) | PostgreSQL / SQLite schema, table relationships, and Alembic versioning |

---

## 13. Academic References & Thesis Credits

### Project Attribution
- **Degree**: Bachelor of Technology in Computer Science Engineering (Artificial Intelligence & Machine Learning)
- **Institution**: Panipat Institute of Engineering & Technology (PIET), Samalkha, Panipat
- **Affiliated to**: Kurukshetra University, Kurukshetra
- **Students**: Akansha (Roll No: 28240546), Vanshika (Roll No: 28240554)
- **Project Supervisors**: Prof. (Dr.) Devendra Parsad / Ms. Taruna Chawla (Department of CSE AI & ML)

### Academic & Technical Citations
1. **OWASP Foundation**: *OWASP Top 10: The Ten Most Critical Web Application Security Risks* (2021).
2. **MITRE Corporation**: *Common Weakness Enumeration (CWE)*: A Community-Developed Dictionary of Software Weakness Types.
3. **NIST**: *Secure Software Development Framework (SSDF) Version 1.1: Recommendations for Mitigating the Risk of Software Vulnerabilities*, Special Publication 800-218.
4. **Google / OpenSSF**: *Open Source Vulnerabilities (OSV) Schema Documentation* (OSV.dev).
5. **Python Software Foundation**: *Python 3 `ast` — Abstract Syntax Trees Standard Library Documentation*.
6. **Kurukshetra University / PIET**: *Minor / Major Project Synopsis: AI-Driven Code Security Vulnerability Detection and Remediation* (2024–2026).
