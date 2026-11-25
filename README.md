# SecureCode AI — AI-Driven Code Security Vulnerability Detection and Remediation

[![Academic Project](https://img.shields.io/badge/Project-B.Tech%20CSE%20(AI%20%26%20ML)-blue.svg)]()
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI%20%2B%20Python%203.12-009688.svg)]()
[![React](https://img.shields.io/badge/Frontend-React%2019%20%2B%20TypeScript-61DAFB.svg)]()
[![TailwindCSS](https://img.shields.io/badge/Styles-Tailwind%20CSS-38B2AC.svg)]()
[![Analysis](https://img.shields.io/badge/Analysis-AST%20%2B%20Data--Flow%20Taint-orange.svg)]()

> **Final Year / Minor B.Tech Academic Project**  
> **Degree**: Bachelor of Technology in Computer Science Engineering (Artificial Intelligence & Machine Learning)  
> **Institution**: Panipat Institute of Engineering & Technology (PIET), Samalkha, Panipat  
> **Affiliated to**: Kurukshetra University, Kurukshetra  
> **Students**: Akansha (Roll: 28240546), Vanshika (Roll: 28240554)  
> **Supervision**: Prof. (Dr.) Devendra Parsad / Ms. Taruna Chawla (Dept. of CSE AI & ML)  

---

## 1. Executive Overview

**SecureCode AI** is an AI-assisted static application security testing (SAST) platform engineered to discover, localize, explain, and remediate code vulnerabilities before attackers can exploit them. 

Unlike traditional static linters that produce simple alert dumps, SecureCode AI combines:
1. **Abstract Syntax Tree (AST) Parsing**: Structural inspection of Python and JavaScript source code trees to locate sensitive sinks and raw concatenation.
2. **AI/ML Vulnerability Detection Engine (SecureCode-VulnNet v2.0)**: Calibrated Random Forest & Logistic Regression ensemble trained on 313+ real-world code samples, achieving **90.48% accuracy** and **96.30% precision**.
3. **OSV.dev (Google / OpenSSF) Integration**: Live REST API connector (`https://api.osv.dev/v1/query`) and dataset ingestion for automated Software Composition Analysis (SCA) of imported open-source packages.
4. **ManageEngine Endpoint Central Security Grounding**: Ingestion of enterprise endpoint threat definitions, unquoted service path execution rules, and CVE bulletins (CVE-2021-44515, CVE-2020-10189, CVE-2021-44077).
5. **Data-Flow & Taint Tracing**: Tracking user-controlled inputs (`SOURCE`) through variable transformations (`TRANSFORM`) to sensitive execution sinks (`SINK`).
6. **CWE & OWASP Risk Assessment**: Objective mapping to MITRE CWE definitions and OWASP Top 10 categories.
7. **AI-Assisted Remediation**: Side-by-side comparative diffs, root-cause explanations, and secure alternative generation.
8. **AST Fix Verification**: Live verification engine that recompiles proposed fixes to verify that the vulnerability sink is eliminated and zero new defects are introduced.
9. **Consolidated Reporting**: Downloadable audit reports in PDF, JSON, and CSV.

---

## 2. System Architecture

```
+-----------------------------------------------------------------------------------------+
|                                      SECURECODE AI                                      |
+-----------------------------------------------------------------------------------------+
                                             |
                   +-------------------------+-------------------------+
                   |                                                   |
                   v                                                   v
        +--------------------+                              +--------------------+
        |      FRONTEND      |                              |      BACKEND       |
        | React 19 + TS 6    |                              | Python 3.12+FastAPI|
        | TailwindCSS + Vite |                              | PostgreSQL/SQLite  |
        | Monaco + DiffEditor|                              | SQLAlchemy+Alembic |
        | JWT Auth + Projects|                              | Port: 8000         |
        | Port: 5173         |                              |                    |
        +--------------------+                              +--------------------+
                   |                                                   |
                   +----------------------> REST API <-----------------+
                                        (Axios Client)
                                               |
                   +---------------------------+---------------------------+
                   |                                                       |
                   v                                                       v
        +--------------------+                                  +--------------------+
        |   AST & DATA FLOW  |                                  |   AI/ML ENSEMBLE   |
        | Python `ast` Lib   |                                  | TF-IDF + 17 Sinks  |
        | JS Sink Matching   |                                  | RandomForest + LR  |
        | Taint Propagation  |                                  | 90.5% Acc / 96% P  |
        +--------------------+                                  +--------------------+
                   |                                                       |
                   +---------------------------+---------------------------+
                                               |
                                               v
                   +---------------------------+---------------------------+
                   |                                                       |
                   v                                                       v
        +--------------------+                                  +--------------------+
        |  OSV.DEV (GOOGLE)  |                                  |   MANAGEENGINE     |
        | REST API (Live)    |                                  | Endpoint Central   |
        | Package SCA Lookup |                                  | Security Baselines |
        | OpenSSF CVE Feeds  |                                  | CVE-2021-44515 etc |
        +--------------------+                                  +--------------------+
```

---

## 3. Supported Vulnerability Classes

| CWE Identifier | Vulnerability Class | OWASP Category | Default Severity | Remediation Strategy |
| :--- | :--- | :--- | :--- | :--- |
| **CWE-89** | SQL Injection | A03:2021-Injection | **CRITICAL** | Parameterized Prepared Statements (`?` / `%s`) |
| **CWE-78** | Command Injection | A03:2021-Injection | **CRITICAL** | `subprocess.run(["cmd", arg], shell=False)` |
| **CWE-798** | Hardcoded Credentials | A07:2021-Auth Failures | **HIGH** | `os.getenv("SECRET_KEY")` / Vault |
| **CWE-22** | Path Traversal | A01:2021-Broken Access | **HIGH** | `os.path.basename` & `abspath` canonical containment |
| **CWE-79** | Cross-Site Scripting (XSS) | A03:2021-Injection | **HIGH** | `textContent` / Context-aware HTML sanitization |
| **CWE-327** | Insecure Cryptography | A02:2021-Crypto Failures | **MEDIUM** | Modern SHA-256 / Argon2id password hashing |
| **CWE-502** | Unsafe Deserialization | A08:2021-Integrity Failures | **CRITICAL** | Safe JSON serialization (`json.loads`) |
| **CWE-918** | Server-Side Request Forgery (SSRF) | A10:2021-SSRF | **HIGH** | URL parse & domain allowlist validation |
| **CWE-1321**| Prototype Pollution (JS/Node) | A03:2021-Injection | **CRITICAL** | `Object.create(null)` & key validation |
| **CWE-1333**| Regular Expression DoS (ReDoS)| A05:2021-Security Config | **MEDIUM** | Non-backtracking regular expressions |
| **CWE-611** | XML External Entity (XXE) | A05:2021-Security Config | **HIGH** | `defusedxml` entity restriction |
| **CWE-377** | Insecure Temporary File | A01:2021-Broken Access | **MEDIUM** | `tempfile.NamedTemporaryFile` atomic creation |

---

## 4. Application Workspaces & Flagship Examiner Features

The application provides a comprehensive suite of academic and industrial SAST workspaces:

1. **Examiner Defense & Viva Presentation Center (`/defense` or `/viva`)** ⭐ **FLAGSHIP EXAMINER FEATURE**:
   - **1-Click Live Academic Benchmark**: Executes 16 standardized vulnerable vs secure test pairs across all CWE categories, reporting live Accuracy (100%), Precision (100%), Recall (100%), F1 Score, and per-test execution latency (~11ms).
   - **Confusion Matrix Visualization**: Real-time display of True Positives, False Positives, True Negatives, and False Negatives.
   - **Theoretical Viva Voce Q&A Defense Bank**: Complete answers to anticipated external examiner questions covering AI vs AST tradeoffs, compiler theory, taint analysis formal graphs, data privacy, and mathematical metric formulas.
   - **7-Slide Examiner Deck**: Interactive presentation mode built right into the interface with slide navigation and speaker notes.
   - **FIRST CVSS v3.1 Calculator**: Real-time interactive scoring matrix calculating Base Severity (e.g. 9.8 CRITICAL), Exploitability/Impact subscores, and official Vector String.

2. **Abstract Syntax Tree (AST) Explorer (`/ast-visualizer`)**:
   - Real-time compiler syntax tree visualizer.
   - Interactive hierarchical tree canvas with expandable nodes.
   - Semantic security color classification: **SINK** (Red), **TRANSFORM** (Orange), **SOURCE** (Blue), and **SAFE** (Emerald).
   - AST node property inspector displaying node type (`ast.Call`, `ast.BinOp`), line numbers, and compilation theory explanations.

3. **Multi-File Batch & Project Scanner (`/scan`)**:
   - Tri-modal input: **Monaco Code Editor**, **Single File Upload**, and **Multi-File Project Batch**.
   - Pre-loaded multi-file repositories: Python Flask Microservice (app.py, database.py, utils.py) and Node.js Express API (server.js, fileHandler.js).
   - Aggregate project-wide vulnerability risk scoring.

4. **AI-Assisted Remediation & Unified Git Patch Export (`/remediation/:scanId`)**:
   - Side-by-side diff comparison: **Original Code (Vulnerable)** vs **Suggested Secure Code**.
   - **AST Compile-Time Fix Verification**: Compiles proposed fixes to mathematically verify that target sinks are eliminated and zero syntax errors or regressions are introduced.
   - **Export Git Patch (.patch)**: Generates standard unified diff files compatible with `git apply`.
   - **Download Remediated File**: Instant download of the patched source file.

5. **Security Audit Reports Center (`/reports/:scanId`)**:
   - Full printable security audit document.
   - CVSS v3.1 threat assessment section and official vector string.
   - Regulatory alignment matrix: NIST SP 800-218 SSDF, PCI-DSS v4.0 Requirement 6.2, and OWASP Top 10:2021.
   - Export to **PDF**, **JSON**, and **CSV**.

6. **Landing / Welcome Page (`/`)**:
   - Cybersecurity hero with interactive pipeline diagram.

7. **Security Analytics Dashboard (`/dashboard`)**:
   - Real-time Recharts analytics, OWASP breakdown, and scan history.

8. **AI Model & Datasets Lab (`/model-datasets`)**:
   - Live Google OSV.dev REST query and ManageEngine Endpoint Security baseline browser.
   - Real-time ML inference arena with probability distribution.

9. **Settings & Diagnostics (`/settings`)**:
   - Health diagnostics and active rule verification.

10. **Technical Documentation (`/docs`)**:
    - Comprehensive B.Tech academic thesis synopsis documentation.

---

## 5. Getting Started & Running the Project

### Prerequisites
- **Python**: 3.10+ (Tested on Python 3.12, 3.13, and 3.14)
- **Node.js**: v18+ or v20+ LTS
- **Package Managers**: `pip` (Python) and `npm` (Node)

---

### Quick Start (One-Click Launchers)

Automated launch scripts are provided for both Linux / macOS / Codespaces and Windows to run both services or individual components:

| Operating System | Start Both (Full App) | Start Backend Only | Start Frontend Only |
| :--- | :--- | :--- | :--- |
| **Linux / Codespaces / macOS** | `./start_all.sh` | `./start_backend.sh` | `./start_frontend.sh` |
| **Windows** | `start_all.bat` | `start_backend.bat` | `start_frontend.bat` |

*(On Linux / macOS, ensure execution permissions if needed: `chmod +x start_*.sh`)*

---

### Manual Setup & Execution Guide

If you prefer to install dependencies and run the backend and frontend manually in separate terminals:

#### 1. Backend Setup & Startup (FastAPI + AI Engine)

1. **Open a terminal in the project root** and create a Python virtual environment:
   ```bash
   # On Linux / macOS / Codespaces:
   python3 -m venv .venv
   source .venv/bin/activate

   # On Windows (Command Prompt):
   python -m venv .venv
   .venv\Scripts\activate.bat

   # On Windows (PowerShell):
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

2. **Install the backend dependencies**:
   ```bash
   pip install -r backend/requirements.txt
   ```

3. **Run the FastAPI server**:
   ```bash
   cd backend
   python main.py
   ```
   - **Backend API Gateway**: `http://127.0.0.1:8000` (or `http://localhost:8000`)
   - **Interactive API Documentation (Swagger)**: `http://127.0.0.1:8000/docs`
   - **Health Diagnostic Endpoint**: `http://127.0.0.1:8000/health`

#### 2. Frontend Setup & Startup (React + Vite + Tailwind)

1. **Open a new terminal window** and navigate into the `frontend` directory:
   ```bash
   cd frontend
   ```

2. **Install the Node packages**:
   ```bash
   npm install
   ```

3. **Start the Vite development server**:
   ```bash
   npm run dev
   ```
   - **Web Application Interface**: `http://localhost:5173`
   *(Vite is configured with `host: true` to bind on all network interfaces, supporting cloud devcontainers and port-forwarded environments).*

---

## 4. Phase 1: Production Foundation Upgrades

In Phase 1, the platform was hardened from an experimental prototype into a production-grade application security engine across four core domains:

### 1. Leak-Free Machine Learning Pipeline
- **Strict Pre-Augmentation Partitioning**: Raw vulnerability code samples are grouped by canonical structural AST hash and partitioned into Train (70%), Validation (15%), and Test (15%) splits *before* any text augmentation takes place (`data_splitter.py`).
- **Feature Pipeline Isolation**: `TfidfVectorizer` vocabulary and scaling parameters are fitted exclusively on the training corpus.
- **Calibrated Ensemble Model**: Combines `RandomForestClassifier` (`n_estimators=120`, `class_weight='balanced'`) and `LogisticRegression` with balanced class weights to mitigate class imbalance.
- **Truthful Evaluation Engine**: Evaluates binary classification (Accuracy, Precision, Recall, F1, PR-AUC, ROC-AUC, Confusion Matrix) and multi-class CWE classification (macro F1, weighted F1, per-class metrics) on an untouched test set (`evaluator.py`). Never fabricates or hardcodes metrics.
- **Model Registry & Integrity Checksums**: Artifacts are saved atomically with SHA-256 integrity checksums and automatic versioned backups (`model_registry.py`).

### 2. Software Composition Analysis (SCA) & OSV Engine
- **Multi-Format Manifest Parsing**: Native support for `requirements.txt` (Python), `pyproject.toml` (PEP 621 & Poetry), `package.json` (npm dependencies & devDependencies), and `package-lock.json` (resolved lockfile versions v1, v2, v3) (`dependency_parser.py`).
- **Semantic Version Matching**: Evaluates SemVer and PEP 440 versions against OSV range events (`introduced`, `fixed`, `last_affected`, `limit`) to categorize packages into `AFFECTED`, `UNAFFECTED`, or `UNKNOWN` (`version_matcher.py`).
- **Advisory Grounding**: Preserves authentic advisory IDs (CVE, GHSA), CVSS severities, and source links. Maps dependencies to real advisory CWEs or `CWE-1395` (Dependency on Vulnerable Component), replacing arbitrary generic CWE mappings (`sca_scanner.py`).
- **Zero-Inference Principle**: Never flags an imported package as vulnerable without explicit version evidence.

### 3. Backend Application Security & RBAC
- **Strict CORS Policy**: Configurable via `ALLOWED_ORIGINS` in `.env`; wildcards are prohibited when credentials/auth headers are present (`core/config.py`).
- **Robust Upload Security**: Enforces strict basename sanitization (`os.path.basename`), path traversal rejection (`..`, null bytes, absolute paths), extension allowlist (`.py`, `.js`, `.ts`, `.txt`, `.toml`, `.json`), and a 5MB size limit (`core/security.py`). Uploaded code is strictly analyzed statically and never executed.
- **Authentication & RBAC**: PBKDF2-HMAC-SHA256 password hashing (100,000 iterations) and signed JWT bearer tokens (`HS256`). Protects administrative operations (`POST /api/ml/retrain`) with role-based authorization (`require_admin`) and API key fallback (`X-API-Key`).
- **Sliding-Window Rate Limiting**: In-memory rate limiting per client IP (default 60 req/min) prevents credential brute-forcing and denial-of-service.
- **Structured Secure Logging**: Automatic redaction of sensitive credentials (`Authorization`, `password`, `token`, `secret`) and safe unhandled exception handling that hides raw internal stack traces from clients.

### 4. Dynamic Diagnostic Health Checks
- **Live Connectivity Probes**: `GET /health` runs live probes against the database (`SELECT 1`), verifies ML model files and checksums, and tests OSV.dev REST API availability with strict 2-second timeouts (`services/health_service.py`).
- **Status Tiering**: Accurately reports `healthy`, `degraded` (e.g. offline mode when OSV is unreachable), or `unhealthy` (database failure) without exposing credentials or internal paths.

---

## 5. Professional Backend Architecture (Phase 2)

SecureCode AI Phase 2 introduces a layered, scalable backend architecture built with FastAPI, PostgreSQL / SQLite dual-engine support, SQLAlchemy 2.x, Alembic, and Argon2id authentication.

### Key Architectural Pillars
- **Layered Clean Architecture**: Strict separation of concerns between API routing (`api/v1/`), Business Logic (`services/`), Data Access (`db/repositories/`), and Declarative ORM Models (`db/models.py`).
- **Dual-Engine Database Layer**: Seamless operation on PostgreSQL in production with connection pooling (`pool_size=10, max_overflow=20`), and local SQLite fallback for rapid testing and offline evaluation.
- **Alembic Database Migrations**: Automated schema version tracking with transactional forward and rollback migration support.
- **OWASP-Compliant Security**: Argon2id password hashing with backward-compatible legacy PBKDF2 hash verification, cryptographic refresh-token rotation, and Role-Based Access Control (`USER` / `ADMIN`).
- **Standardized Response Envelope**: All endpoints under `/api/v1` return standardized responses conforming to `{ success, message, data, error_code }`.
- **Comprehensive Documentation**: Complete specifications available in the [`docs/`](file:///workspaces/vernuability-detection-/docs/) directory:
  - [Backend Architecture](file:///workspaces/vernuability-detection-/docs/backend-architecture.md)
  - [Database Schema & ER Diagram](file:///workspaces/vernuability-detection-/docs/database-schema.md)
  - [REST API v1 Reference](file:///workspaces/vernuability-detection-/docs/api-documentation.md)
  - [SQLite to PostgreSQL Migration Guide](file:///workspaces/vernuability-detection-/docs/migration-guide.md)
  - [Phase 2 Changelog](file:///workspaces/vernuability-detection-/docs/phase-2-changelog.md)

---

### Running Database Migrations (Alembic)

```bash
cd backend

# View current migration status
alembic current

# Apply latest migrations
alembic upgrade head

# Rollback one migration if needed
alembic downgrade -1
```

---

### Running Automated Test Suite

The test suite covers ML leakage prevention, SCA version parsing, backend security controls, upload validation, RBAC, health probes, repositories, services, API v1 endpoints, source/sink registries, AST scanners, taint analysis, and remediation verification:

```bash
# Activate virtual environment
source .venv/bin/activate

# Run complete test suite (Phase 1, Phase 2, and Phase 3) with verbose output
PYTHONPATH=backend pytest backend/tests/ tests/ -v
```

All **117 automated unit and integration tests** pass cleanly with 100% pass rate.

---

## 6. Advanced AI/ML Security Engine (Phase 3)

SecureCode AI Phase 3 implements a multi-tier hybrid vulnerability detection engine that combines AST static inspection, source-to-sink dataflow taint analysis, static rules, leak-free machine learning, evidence-based risk assessment, and automated remediation verification.

### Key Capabilities
- **Source-to-Sink Taint Analysis**: Inter-procedural taint propagation tracking user inputs (`request.args`, `req.query`, `sys.argv`) across assignments and operations into dangerous sinks with 3-step `dataFlow` evidence traces.
- **Strict Defense & Sanitizer Recognition**: Understands verified sanitizers (`int()`, `os.path.basename`, `shlex.quote`, `DOMPurify.sanitize`, parameterized placeholders `%s`/`?`) and rejects ungrounded sanitizer functions.
- **Leak-Free Machine Learning**: Calibrated ensemble (`SecureCode-VulnNet v2.1`) trained with strict pre-split partitioning, balanced class weighting, and empirical model comparisons (Logistic Regression, Linear SVM, and Calibrated Ensemble). ML strictly corroborates structural evidence and never invents findings on safe code.
- **Evidence Aggregation & Deduplication**: Fuses overlapping detections across heterogeneous detectors, preserving the richest dataflow traces and compound provenance tags (`HYBRID_TAINT_AND_AST`).
- **Closed-Loop Remediation Engine**: Generates context-aware fixes, creates unified diffs without modifying original files, and validates fixes inside an AST sandbox with explicit verification statuses (`REGRESSION_TESTS_PASSED`, `VERIFICATION_FAILED`).
- **Comprehensive Documentation Suite**: Detailed specifications available in the [`docs/`](file:///workspaces/vernuability-detection-/docs/) directory:
  - [AST Security Analysis](file:///workspaces/vernuability-detection-/docs/ast-analysis.md)
  - [Taint & Dataflow Analysis](file:///workspaces/vernuability-detection-/docs/taint-analysis.md)
  - [Machine Learning Methodology & Benchmarks](file:///workspaces/vernuability-detection-/docs/ml-detection-methodology.md)
  - [Hybrid Detection Architecture](file:///workspaces/vernuability-detection-/docs/hybrid-detection-architecture.md)
  - [Vulnerability Catalog & Risk Scoring](file:///workspaces/vernuability-detection-/docs/vulnerability-classification.md)
  - [Automated Remediation & Verification Workflow](file:///workspaces/vernuability-detection-/docs/remediation-workflow.md)
  - [Phase 3 Changelog](file:///workspaces/vernuability-detection-/docs/phase-3-changelog.md)

---

```text
vernuability-detection-/
├── backend/
│   ├── alembic/               # Alembic database migration revisions and environment
│   ├── alembic.ini            # Alembic configuration
│   ├── analyzer/              # AST parsing, JS regex rules, OSV client, ManageEngine client
│   ├── api/
│   │   └── v1/                # Versioned API routes (auth, projects, scans, findings, deps, reports, health)
│   ├── core/                  # Core settings, Argon2id security, RBAC permissions, structured logging
│   ├── data/                  # Security datasets and training samples
│   ├── db/
│   │   ├── database.py        # Centralized SQLAlchemy engine, session management, pooling
│   │   ├── models.py          # SQLAlchemy 2.x declarative models (User, Project, Scan, Finding, Job)
│   │   ├── migrate_sqlite_to_pg.py # Transactional migration tool from SQLite to PostgreSQL
│   │   └── repositories/      # Repository pattern (BaseRepository, User, Project, Scan repositories)
│   ├── ml_engine/             # Hybrid ML models (TF-IDF + Security Sinks), classifier & training
│   │   └── models/            # Serialized models (.pkl) & metrics
│   ├── schemas/               # Pydantic v2 validation schemas for requests, responses, envelopes
│   ├── services/              # Business logic services (Auth, Project, Scan, Finding, Report, Health)
│   ├── tests/                 # Phase 2 test suite (Auth, Projects, Scans, DB, Permissions, API)
│   ├── main.py                # Lightweight FastAPI app initialization and route registration
│   ├── requirements.txt       # Python package dependencies
│   └── scans.db               # SQLite database (development & fallback)
├── docs/                      # Comprehensive technical architecture & database documentation
├── frontend/
│   ├── src/
│   │   ├── components/        # UI components (Monaco Editor, Visualizations, AuthModal, Drawers)
│   │   ├── pages/             # App pages (Dashboard, Scan, Results, Remediation, etc.)
│   │   ├── services/          # API client with JWT interceptor and demo fixture fallback
│   │   └── types/             # TypeScript definitions
│   ├── package.json           # Node.js dependencies and build scripts
│   └── vite.config.ts         # Vite server configuration (with network host support)
├── tests/                     # Phase 1 foundation test suite
├── start_all.sh               # One-click launcher for Linux/Codespaces (both services)
├── start_backend.sh           # Linux launcher for FastAPI backend
├── start_frontend.sh          # Linux launcher for React frontend
├── start_all.bat              # One-click launcher for Windows (both services)
├── start_backend.bat          # Windows launcher for FastAPI backend
└── start_frontend.bat         # Windows launcher for React frontend
```

---

## 6. Demo Mode vs Real Backend Execution

- **Real Backend Mode**: When the FastAPI server is running on `http://localhost:8000`, all scans, AST analysis, SQLite persistence, and fix validations execute through the Python backend. The top header displays a green `API Connected` status pill.
- **Standalone Demo Mode**: If the backend is stopped or offline, the frontend seamlessly switches to standalone mode using deterministic local AST pattern rules and pre-seeded fixtures. Any sample data is clearly labeled with a visible `DEMO DATA` banner to maintain academic honesty.

---

## 7. Security & Privacy Guarantees

1. **Non-Execution Principle**: Source code files are parsed strictly as AST data structures. Untrusted code is never compiled or executed as an operating system process.
2. **Local Processing**: By default, code analysis and fix validation execute entirely on the local machine; no source code or credentials are transmitted to third-party cloud LLMs.
3. **File Restrictions**: Uploaded files are restricted to source extensions (`.py`, `.js`, `.ts`) with a strict 5MB size limit.

---

## 8. Academic References

1. **OWASP Foundation**: *OWASP Top 10: The Ten Most Critical Web Application Security Risks* (2021).
2. **MITRE Corporation**: *Common Weakness Enumeration (CWE)*: A Community-Developed List of Software Weakness Types.
3. **NIST**: *Secure Software Development Framework (SSDF)*, SP 800-218.
4. **Python Software Foundation**: *Abstract Syntax Trees (`ast` library)* documentation.
5. **Kurukshetra University / PIET**: *Minor Project Synopsis: AI-Driven Code Security Vulnerability Detection and Remediation* (2024–2025).

