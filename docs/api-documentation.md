# SecureCode AI — REST API v1 Reference

All modern Phase 2 endpoints are hosted under `/api/v1/` and return a standardized JSON response envelope.

---

## 1. Standard Response Envelope

Every endpoint under `/api/v1` returns responses conforming to the `ApiResponse[T]` schema:

```json
{
  "success": true,
  "message": "Operation completed successfully",
  "data": { ... },
  "error_code": null
}
```

In the event of an error (4xx or 5xx), the payload retains the same structure:

```json
{
  "success": false,
  "message": "Detailed description of the error",
  "data": null,
  "error_code": "ENTITY_NOT_FOUND"
}
```

### Standard Error Codes
| Error Code | HTTP Status | Description |
| :--- | :--- | :--- |
| `VALIDATION_ERROR` | 422 | Request body or query parameters failed Pydantic schema validation. |
| `UNAUTHENTICATED` | 401 | Missing, malformed, or expired Bearer token. |
| `FORBIDDEN` | 403 | Insufficient role permissions (e.g., non-admin calling retrain). |
| `NOT_FOUND` | 404 | Target entity (project, scan, finding) does not exist. |
| `CONFLICT` | 409 | Unique constraint conflict (e.g., duplicate email address). |
| `RATE_LIMIT_EXCEEDED` | 429 | Sliding-window client rate limit exceeded (>60 req/min). |
| `INTERNAL_ERROR` | 500 | Unhandled internal server exception. |

---

## 2. Authentication Endpoints (`/api/v1/auth`)

### 2.1 Register User
- **Method**: `POST`
- **Path**: `/api/v1/auth/register`
- **Auth**: None
- **Request Body**:
  ```json
  {
    "email": "analyst@securecode.local",
    "password": "SecurePassword123!",
    "full_name": "Security Analyst"
  }
  ```
- **Response** (201 Created):
  ```json
  {
    "success": true,
    "message": "User registered successfully",
    "data": {
      "id": 1,
      "email": "analyst@securecode.local",
      "full_name": "Security Analyst",
      "role": "USER",
      "is_active": true,
      "created_at": "2026-11-25T17:00:00Z"
    },
    "error_code": null
  }
  ```

### 2.2 Login (Token Pair Issuance)
- **Method**: `POST`
- **Path**: `/api/v1/auth/login`
- **Auth**: None
- **Request Body**:
  ```json
  {
    "email": "analyst@securecode.local",
    "password": "SecurePassword123!"
  }
  ```
- **Response** (200 OK):
  ```json
  {
    "success": true,
    "message": "Login successful",
    "data": {
      "access_token": "eyJhbGciOi...",
      "refresh_token": "a8f3c...",
      "token_type": "bearer",
      "expires_in": 1800,
      "user": {
        "id": 1,
        "email": "analyst@securecode.local",
        "full_name": "Security Analyst",
        "role": "USER"
      }
    },
    "error_code": null
  }
  ```

### 2.3 Rotate Refresh Token
- **Method**: `POST`
- **Path**: `/api/v1/auth/refresh`
- **Auth**: None
- **Request Body**:
  ```json
  {
    "refresh_token": "a8f3c..."
  }
  ```
- **Response** (200 OK):
  Returns a brand new access token and a freshly rotated refresh token. The prior refresh token is immediately revoked.

### 2.4 Logout
- **Method**: `POST`
- **Path**: `/api/v1/auth/logout`
- **Auth**: Bearer Token
- **Request Body**:
  ```json
  {
    "refresh_token": "a8f3c..."
  }
  ```
- **Response** (200 OK):
  ```json
  {
    "success": true,
    "message": "Logged out successfully",
    "data": null,
    "error_code": null
  }
  ```

### 2.5 Get Current Profile
- **Method**: `GET`
- **Path**: `/api/v1/auth/me`
- **Auth**: Bearer Token
- **Response** (200 OK):
  Returns current user profile information.

---

## 3. Project Management Endpoints (`/api/v1/projects`)

All project endpoints require `Authorization: Bearer <token>`. Users are isolated strictly to their own projects.

| Method | Path | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/projects` | List projects with pagination (`page`, `page_size`, `search`, `order_by`, `direction`). |
| `POST` | `/api/v1/projects` | Create a new project workspace (`name`, `description`, `repository_url`). |
| `GET` | `/api/v1/projects/{id}` | Retrieve project details by ID (enforces ownership). |
| `PUT` | `/api/v1/projects/{id}` | Update project details (`name`, `description`, `repository_url`). |
| `DELETE` | `/api/v1/projects/{id}` | Delete project workspace and cascade-delete all associated scans. |

---

## 4. Scan Execution & Management (`/api/v1/scans`)

### 4.1 Trigger Direct Code Scan
- **Method**: `POST`
- **Path**: `/api/v1/scans`
- **Auth**: Optional (Supports guest and authenticated users)
- **Request Body**:
  ```json
  {
    "code": "import sqlite3\ndef fetch(uid): return db.execute('SELECT * FROM users WHERE id=' + uid)",
    "language": "python",
    "filename": "database_handler.py",
    "project_id": null
  }
  ```
- **Response** (201 Created):
  ```json
  {
    "success": true,
    "message": "Scan completed with 1 vulnerabilities detected",
    "data": {
      "scan_id": 42,
      "target_name": "database_handler.py",
      "language": "python",
      "status": "completed",
      "risk_score": 85.0,
      "total_findings": 1,
      "findings": [
        {
          "id": 105,
          "cwe": "CWE-89",
          "severity": "CRITICAL",
          "confidence": 0.95,
          "start_line": 2,
          "end_line": 2,
          "description": "SQL Injection vulnerability via raw string concatenation",
          "remediation_status": "OPEN"
        }
      ]
    },
    "error_code": null
  }
  ```

### 4.2 Upload File for Scan
- **Method**: `POST`
- **Path**: `/api/v1/scans/upload`
- **Auth**: Optional
- **Form Data**: `file` (Multipart, max 5MB, `.py`, `.js`, `.ts`, `.txt`, `.json`, `.toml`)

### 4.3 List Historical Scans
- **Method**: `GET`
- **Path**: `/api/v1/scans?project_id=1&page=1&page_size=20`

### 4.4 Validate Remediation Fix
- **Method**: `POST`
- **Path**: `/api/v1/scans/validate-fix`
- **Request Body**:
  ```json
  {
    "original_code": "cursor.execute('SELECT * FROM users WHERE id=' + uid)",
    "fixed_code": "cursor.execute('SELECT * FROM users WHERE id = %s', (uid,))",
    "vulnerability_type": "CWE-89"
  }
  ```
- **Response** (200 OK):
  ```json
  {
    "success": true,
    "message": "Remediation fix validated successfully",
    "data": {
      "is_valid": true,
      "syntax_valid": true,
      "vulnerability_fixed": true,
      "new_vulnerabilities": [],
      "message": "Sink eliminated successfully"
    },
    "error_code": null
  }
  ```

---

## 5. Vulnerability Findings (`/api/v1/findings`)

### 5.1 Update Finding Status
- **Method**: `PATCH`
- **Path**: `/api/v1/findings/{id}`
- **Auth**: Bearer Token
- **Request Body**:
  ```json
  {
    "remediation_status": "RESOLVED"
  }
  ```
  *(Permitted values: `OPEN`, `RESOLVED`, `FALSE_POSITIVE`)*

---

## 6. Software Composition Analysis (SCA) (`/api/v1/dependencies`)

### 6.1 Scan Manifest File
- **Method**: `POST`
- **Path**: `/api/v1/dependencies/scan`
- **Request Body**:
  ```json
  {
    "filename": "requirements.txt",
    "content": "requests==2.25.1\nflask==1.1.2\nurllib3==1.26.4"
  }
  ```
- **Response** (200 OK):
  Returns exact resolved package versions cross-referenced against OSV.dev advisories.

### 6.2 Query Single Dependency
- **Method**: `POST`
- **Path**: `/api/v1/dependencies/query`
- **Request Body**:
  ```json
  {
    "package": "requests",
    "version": "2.25.1",
    "ecosystem": "PyPI"
  }
  ```

---

## 7. Executive Audit Reports (`/api/v1/reports`)

- **Method**: `GET`
- **Path**: `/api/v1/reports/{scan_id}`
- **Response** (200 OK):
  Provides consolidated executive audit report including overall mathematical risk score, severity distributions, CWE classification counts, and compliance summaries.

---

## 8. Health & Diagnostics (`/api/v1/health`)

- **Method**: `GET`
- **Path**: `/api/v1/health`
- **Auth**: None
- **Response** (200 OK):
  ```json
  {
    "success": true,
    "message": "System status: healthy",
    "data": {
      "status": "healthy",
      "timestamp": "2026-11-25T17:15:00Z",
      "checks": {
        "database": { "status": "healthy", "latency_ms": 1.2 },
        "ml_model": { "status": "healthy", "model_version": "2.0.0" },
        "osv_api": { "status": "healthy", "reachable": true }
      }
    },
    "error_code": null
  }
  ```

---

## 9. Example cURL Workflows

### Register & Login Flow:
```bash
# 1. Register new analyst
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"analyst@example.com","password":"SecretPassword123!","full_name":"Lead Analyst"}'

# 2. Login to retrieve tokens
LOGIN_RESP=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"analyst@example.com","password":"SecretPassword123!"}')

ACCESS_TOKEN=$(echo $LOGIN_RESP | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)
echo "JWT Token: $ACCESS_TOKEN"

# 3. Create a Project workspace
curl -X POST http://localhost:8000/api/v1/projects \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -d '{"name":"Backend Core API","description":"Critical backend payment services"}'
```
