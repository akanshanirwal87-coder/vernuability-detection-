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
        | React + TypeScript |                              |  Python + FastAPI  |
        | Tailwind CSS + Vite|                              |  SQLite Storage    |
        | Monaco Editor      |                              |  Port: 8000        |
        | Model/Dataset Lab  |                              |                    |
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

### Project Structure Overview

```text
vernuability-detection-/
├── backend/
│   ├── analyzer/              # AST parsing, JS regex rules, OSV client, ManageEngine client
│   ├── data/                  # Security datasets and training samples
│   ├── ml_engine/             # Hybrid ML models (TF-IDF + Security Sinks), classifier & training
│   │   └── models/            # Serialized models (.pkl) & metrics
│   ├── main.py                # FastAPI REST API endpoints
│   ├── models.py              # Pydantic request & response data schemas
│   ├── storage.py             # SQLite scan history and persistence
│   ├── requirements.txt       # Python package dependencies
│   └── scans.db               # SQLite database
├── frontend/
│   ├── src/
│   │   ├── components/        # UI components (Monaco Editor, Visualizations, Drawers)
│   │   ├── pages/             # App pages (Dashboard, Scan, Results, Remediation, etc.)
│   │   ├── services/          # API client and demo fixture fallback
│   │   └── types/             # TypeScript definitions
│   ├── package.json           # Node.js dependencies and build scripts
│   └── vite.config.ts         # Vite server configuration (with network host support)
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

