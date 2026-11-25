# SecureCode AI — Professional Backend Architecture (Phase 2)

## 1. Architectural Overview

SecureCode AI Phase 2 introduces a layered, modular clean architecture adhering to separation of concerns, dependency injection, and scalable enterprise design patterns.

```
+-----------------------------------------------------------------------------------+
|                                 CLIENT APPLICATIONS                               |
|        React 19 Frontend  |  CI/CD Automated Pipelines  |  REST API Clients       |
+-----------------------------------------------------------------------------------+
                                          |
                                    HTTPS / JSON
                                          v
+-----------------------------------------------------------------------------------+
|                                FASTAPI API LAYER                                  |
|  - CORS Middleware (Environment-configured trusted origins)                       |
|  - In-Memory Sliding-Window Rate Limiting (60 req/min/IP)                         |
|  - Centralized Exception Handlers (AppException, RequestValidationError)          |
|  - Unified Response Envelope: { success, message, data, error_code }              |
|                                                                                   |
|  /api/v1 Routers:                                                                 |
|    ├── /auth         (Register, Login, Refresh, Logout, Me)                       |
|    ├── /projects     (Project CRUD, Isolation, Pagination, Search)                |
|    ├── /scans        (Static AST, AI/ML, SCA, File Uploads)                       |
|    ├── /findings     (Vulnerability findings, Remediation status)                 |
|    ├── /dependencies (SCA manifest parsing, OSV.dev lookup)                       |
|    ├── /reports      (Executive summaries, risk scoring)                          |
|    └── /health       (Live DB, ML model, OSV diagnostic probes)                   |
+-----------------------------------------------------------------------------------+
                                          |
                                 Dependency Injection
                                          v
+-----------------------------------------------------------------------------------+
|                                  SERVICES LAYER                                   |
|  - AuthService         : Argon2id hashing, JWT access/refresh token rotation       |
|  - ProjectService     : Multi-tenant project workspace management & isolation     |
|  - ScanService        : Orchestrates AST, ML ensemble, OSV SCA, and ME baselines  |
|  - FindingService     : Findings pagination, CWE filtering, status tracking       |
|  - RemediationService : AST sandbox compilation and fix verification engine       |
|  - ReportService      : Mathematical risk score calculation & audit reporting     |
|  - HealthService      : Live connectivity diagnostic probes                       |
+-----------------------------------------------------------------------------------+
                                          |
                                     Transactions
                                          v
+-----------------------------------------------------------------------------------+
|                           REPOSITORY & DATA ACCESS LAYER                          |
|  - BaseRepository[T]  : Generic CRUD, pagination, filtering, ordering             |
|  - UserRepository     : User account persistence, token rotation & revocation     |
|  - ProjectRepository  : User-isolated project retrieval and search queries        |
|  - ScanRepository     : Scan records, batch findings insertion, status updates   |
+-----------------------------------------------------------------------------------+
                                          |
                                   SQLAlchemy 2.x
                                          v
+-----------------------------------------------------------------------------------+
|                             DATABASE STORAGE & MIGRATIONS                         |
|  - PostgreSQL (Production with Connection Pooling) / SQLite (Dev & Tests)         |
|  - Alembic Migration Engine with Rollback Support                                 |
|  - Tables: users, refresh_tokens, projects, scans, findings, scan_jobs            |
+-----------------------------------------------------------------------------------+
```

---

## 2. Component Responsibilities

### Core Layer (`backend/core/`)
- **`config.py`**: Central typed settings class parsing `.env` with fallback defaults for PostgreSQL/SQLite URLs, JWT secrets, upload restrictions, and token lifespans.
- **`security.py`**: OWASP-compliant Argon2id password hashing (`time_cost=2`, `memory_cost=65536`, `parallelism=1`), legacy PBKDF2 hash verification for zero-downtime user upgrades, JWT signing (`HS256`), and high-entropy cryptographic refresh token generation.
- **`permissions.py`**: FastAPI dependency injection for current authenticated user extraction (`get_current_user`), optional authentication (`get_current_user_optional`), role-based authorization (`require_admin`), and sliding-window rate limiting.
- **`exceptions.py`**: Standardized application exception hierarchy mapping business exceptions to HTTP status codes (`EntityNotFoundException` $\to$ 404, `AuthenticationException` $\to$ 401, `AuthorizationException` $\to$ 403, `ConflictException` $\to$ 409, `ValidationException` $\to$ 422).
- **`logging.py`**: Structured JSON logging with automatic redaction of sensitive credentials (`Authorization`, `password`, `token`, `secret`).

### API v1 Layer (`backend/api/v1/`)
- Translates HTTP requests to validated Pydantic models.
- Enforces authentication and authorization dependencies before invoking services.
- Wraps successful output in standardized `ApiResponse[T]` envelopes and catches domain exceptions.

### Services Layer (`backend/services/`)
- Implements pure business logic independent of HTTP protocols.
- Enforces cross-user isolation and ownership verification.
- Coordinates external connectors (Google OSV.dev REST API, ManageEngine baseline knowledge base) and local AI/ML inference.

### Repositories Layer (`backend/db/repositories/`)
- Encapsulates raw database queries and mutations using SQLAlchemy 2.x `select()` and `update()` constructs.
- Handles pagination, column-based sorting, ILIKE search filters, and transaction commits/rollbacks.

---

## 3. Security Architecture & Controls

1. **Password Security**:
   - Modern accounts are hashed using **Argon2id**.
   - Verifier transparently verifies legacy PBKDF2-HMAC-SHA256 hashes, allowing seamless migration without forced password resets.
2. **JWT & Refresh Token Rotation**:
   - Short-lived Access Tokens (30 minutes) prevent prolonged token compromise.
   - Refresh Tokens are high-entropy (48 bytes URL-safe) strings. The database stores strictly a SHA-256 hash of the token (`refresh_tokens.token_hash`).
   - Every refresh operation rotates the token: the consumed token is revoked, and a fresh refresh token is issued.
   - Logout immediately revokes the active token in the database.
3. **User Isolation**:
   - Never trusts client-supplied `user_id` in request payloads. All ownership and filtering operations derive user identity strictly from the validated JWT claims.
   - Non-admin users are strictly restricted to their own projects, scans, and findings.
4. **Code Execution Protection**:
   - Uploaded and submitted source codes are analyzed strictly via Abstract Syntax Tree (AST) compilation and lexical token extraction. Source code is never executed as an operating system process.
