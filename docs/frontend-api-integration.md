# SecureCode AI — Frontend API Integration Guide

## 1. API Client Configuration

Centralized in `frontend/src/services/api.ts`:
- Base URL configured from environment: `import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'`
- Automatic Bearer token attachment via Axios request interceptors.
- Automatic JWT refresh token rotation on HTTP 401 via `POST /api/v1/auth/refresh`.

---

## 2. Integrated API Contracts

### Authentication (`/api/v1/auth`)
- `POST /api/v1/auth/login`: `{ email, password }` $\to$ Returns `access_token`, `refresh_token`, and `UserProfile`.
- `POST /api/v1/auth/register`: `{ name, email, password }` $\to$ Registers user and logs in.
- `POST /api/v1/auth/refresh`: `{ refresh_token }` $\to$ Rotates refresh token and issues new access token.
- `GET /api/v1/auth/me`: Returns current authenticated user profile.
- `POST /api/v1/auth/logout`: Revokes stored tokens.

### Project Management (`/api/v1/projects`)
- `GET /api/v1/projects`: Lists paginated projects with `skip`, `limit`, `search`, `sort_by`.
- `POST /api/v1/projects`: `{ name, description, repository_url, language, default_branch }`.
- `GET /api/v1/projects/{id}`: Returns detailed project info and scan statistics.
- `PUT /api/v1/projects/{id}`: Updates project metadata.
- `DELETE /api/v1/projects/{id}`: Removes project record.

### Code Scanning (`/api/v1/scans`)
- `POST /api/v1/scans`: Initiates SAST and AI vulnerability scan on source code string.
- `POST /api/v1/scans/upload`: Multipart upload with path traversal and size checks.
- `GET /api/v1/scans`: Lists scan audit runs with project and status filters.
- `GET /api/v1/scans/{id}`: Retrieves complete scan report with findings, AST summary, and AI metadata.
- `POST /api/v1/scans/{id}/validate-fix`: Recompiles proposed code in AST sandbox to verify fix.
- `DELETE /api/v1/scans/{id}`: Deletes scan record.

### Findings Management (`/api/v1/findings`)
- `PUT /api/v1/findings/{id}`: Updates status (`OPEN`, `RESOLVED`, `FALSE_POSITIVE`) and explanation.

### Reports (`/api/v1/reports`)
- `GET /api/v1/reports/{scan_id}`: Compiles executive security audit report with aggregated risk score and hardening recommendations.
