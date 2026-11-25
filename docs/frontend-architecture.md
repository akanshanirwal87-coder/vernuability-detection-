# SecureCode AI — Frontend Architecture Specification

## 1. Architectural Overview

SecureCode AI’s frontend is a modern, responsive Single Page Application (SPA) built on **React 19**, **TypeScript 6**, **Vite 5**, and **Tailwind CSS 3.4**. It provides an enterprise-grade cybersecurity dashboard and code remediation studio that interfaces with the FastAPI backend architecture.

```
frontend/src/
│
├── App.tsx                          # Root router and context provider tree
├── index.css                        # Design system tokens and tailwind base styles
│
├── context/
│   └── AuthContext.tsx              # Reactive JWT session, user roles, token rotation
│
├── hooks/
│   ├── useAuth.ts                   # AuthContext consumer hook
│   ├── useProjects.ts               # Project CRUD and repository hook
│   ├── useScan.ts                   # SAST scan execution and file upload hook
│   └── useFindings.ts               # Finding filtering, sorting, and status updating hook
│
├── services/
│   ├── api.ts                       # Axios instance with auto-refresh token queue
│   ├── apiClient.ts                 # Backward-compatible API wrapper
│   ├── authService.ts               # Login, register, logout, token refresh
│   ├── projectService.ts            # Project management endpoints (/api/v1/projects)
│   ├── scanService.ts               # Scan execution, uploads, and fix validation (/api/v1/scans)
│   ├── findingService.ts            # Finding status transitions (/api/v1/findings)
│   └── reportService.ts             # PDF/CSV/JSON generators and audit summaries
│
├── components/
│   ├── layout/                      # Persistent sidebar, breadcrumb header, AppShell
│   ├── common/                      # ErrorBoundary, Modal, Loader skeletons, SeverityBadge
│   ├── dashboard/                   # SecurityOverview, SeverityChart, ScanActivity, RecentScans
│   ├── scanner/                     # Monaco CodeEditor, FileUploader, ScanProgress
│   ├── findings/                    # FindingCard, FindingFilters, FindingDetails (Taint Tracing)
│   ├── remediation/                 # Monaco CodeDiff, FixExplanation, VerificationStatus
│   └── reports/                     # ReportSummary (risk gauge), ReportExport (PDF/CSV/JSON)
│
├── pages/
│   ├── LandingPage.tsx              # SaaS welcome page with interactive analysis preview
│   ├── Login.tsx                    # Dedicated JWT authentication page
│   ├── Register.tsx                 # Account registration page
│   ├── DashboardPage.tsx            # Live security metrics and vulnerability analytics
│   ├── Projects.tsx                 # Project management workspace
│   ├── ProjectDetails.tsx           # Single project audit history
│   ├── NewScanPage.tsx              # Monaco scanner with single-file and batch modes
│   ├── ScanResultsPage.tsx          # Vulnerability inspection and multi-facet filtering
│   ├── RemediationPage.tsx          # AST-validated diff workspace and patch download
│   ├── ScanHistoryPage.tsx          # Historical audit archive
│   └── ReportsPage.tsx              # Executive security audit reports
│
└── types/
    ├── auth.ts                      # UserProfile, AuthTokens, ApiResponse<T>
    ├── project.ts                   # Project, ProjectCreateInput, PaginatedProjects
    ├── scan.ts                      # ScanResult, VulnerabilityFinding, DataFlowStep
    ├── finding.ts                   # FindingStatus, FindingFilterOptions
    └── remediation.ts               # FixValidationRequest, FixValidationResponse
```

---

## 2. State Management & Data Flow

1. **Authentication State**: Managed centrally by `AuthContext`. On application boot, it checks stored JWT tokens and calls `/api/v1/auth/me`. When an access token expires (HTTP 401), `api.ts` transparently issues a refresh token request to `/api/v1/auth/refresh` without user disruption.
2. **Scan Telemetry**: Initiated via `useScan`. Direct source code scans call `POST /api/v1/scans`; drag-and-drop file uploads call `POST /api/v1/scans/upload` via `multipart/form-data`.
3. **Findings State**: Handled by `useFindings` which provides client-side multi-facet filtering (CWE, severity, file, keyword search) and communicates status transitions (OPEN, RESOLVED, FALSE_POSITIVE) via `PUT /api/v1/findings/{id}`.
4. **Remediation Verification**: Recompiled on the backend via `POST /api/v1/scans/{scan_id}/validate-fix` ensuring 3-stage validation (`SYNTAX_VALID`, `SECURITY_CHECK_PASSED`, `REGRESSION_TESTS_PASSED`).

---

## 3. Resilience & Error Boundaries

- **`ErrorBoundary`**: Wraps the top-level application and individual major views to catch render errors gracefully without crashing the whole application.
- **Loading Skeletons**: Standardized `CardSkeleton` and `TableSkeleton` prevent content layout shifts during network requests.
- **Offline / Local Fallback**: In the rare event of backend network partition, the client includes deterministic AST pattern parsing so examiner demonstrations can proceed uninterrupted.
