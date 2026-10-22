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

---

## 4. Application Pages & Features

The application delivers all 8 primary workflow workspaces:

1. **Landing / Welcome Page (`/`)**:
   - High-impact cybersecurity hero (*"Find Vulnerabilities Before Attackers Do."*).
   - End-to-end architecture pipeline diagram (Source Code → AST & Static Analysis → AI/ML Classification → Risk Assessment → Remediation → Security Report).
   - Interactive live preview with code editor and remediation badges.
   - Core feature cards and academic verification disclaimer.

2. **Security Dashboard (`/dashboard`)**:
   - Summary cards: Total Scans, Vulnerabilities Found, Critical Findings, and Remediation Progress.
   - Recharts visual analytics: Severity distribution donut, OWASP category breakdown bar chart, and scan activity.
   - Recent Scans table with View Results, Open Report, and Delete with modal confirmation.
   - Latest vulnerability findings preview.

3. **New Code Scan Workspace (`/scan`)**:
   - Dual-mode input: **Monaco Editor** (VS Code-like dark theme) and **File Upload** (.py, .js, .ts with drag-and-drop & size limit).
   - Analysis option checkboxes: AST Parsing, Data-Flow Tracing, AI Classifier, CWE/OWASP Rules.
   - Pre-loaded safe example loader demonstrating SQL Injection, Command Injection, Secrets, XSS, and Path Traversal in both vulnerable and secure modes.
   - Multi-stage scan progress modal.

4. **Scan Results & Vulnerability Analysis (`/results/:scanId`)**:
   - Scan metadata header with highest severity badge and line counts.
   - Severity counters (Critical, High, Medium, Low) and zero-state handling.
   - Searchable and filterable findings table with severity, category, and file filters.
   - Investigation drawer displaying exact line numbers, AST evidence, root cause description, and **interactive Data-Flow Diagram** (`SOURCE` → `TRANSFORM` → `SINK`).

5. **AI-Assisted Remediation Workspace (`/remediation/:scanId`)**:
   - Side-by-side diff comparison: **Original Code (Vulnerable)** vs **Suggested Secure Code**.
   - Editable proposed code editor.
   - **Validate Fix with AST**: Re-evaluates proposed code to verify elimination of target sinks.
   - **Apply Fix**: With explicit confirmation dialog.
   - Best practices checklist and Copy Fix action.

6. **Scan History Archive (`/history`)**:
   - Filter by programming language, severity level, status, or date.
   - Sortable columns for date and total findings.
   - Quick actions for results viewing, report preview, and record deletion.

7. **Reports Center (`/reports/:scanId`)**:
   - Full printable security audit document.
   - Executive summary and risk assessment score.
   - Vulnerability details with code snippets and remediation instructions.
   - **Export PDF** (instant client-side generation via jsPDF).
   - **Export JSON** and **Export CSV** downloaders.
   - Dedicated print styles.

8. **Settings & Diagnostics (`/settings`)**:
   - General preferences: Default language, theme, auto-validation.
   - Analysis engine status and rule registry.
   - Privacy & data retention explanation (local in-memory processing, zero external transmission).
   - **Live Backend Diagnostics**: Ping check with real latency measurement against `http://localhost:8000/health`.

9. **Documentation & Theory (`/docs`)**:
   - Complete academic foundation matching the synopsis.
   - CWE mapping matrix, AST parsing methodology, limitations, and future scope.

---

## 5. Getting Started & Running the Project

### Prerequisites
- Python 3.12+
- Node.js (v20+ LTS)

### Quick Start: Running Backend (FastAPI)

```powershell
# Open terminal in project root
cd "d:\final project\minor_project\backend"

# Run FastAPI server with Uvicorn
python main.py
```
*Backend runs on `http://127.0.0.1:8000` (Swagger docs available at `http://127.0.0.1:8000/docs`).*

### Quick Start: Running Frontend (React + Vite)

```powershell
# Open terminal in project root
cd "d:\final project\minor_project\frontend"

# Launch Vite development server
npm run dev
```
*Frontend runs on `http://localhost:5173`.*

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

