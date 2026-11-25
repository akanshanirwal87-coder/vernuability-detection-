# SecureCode AI — Frontend Testing & Quality Verification

## 1. Automated Verification Commands

### TypeScript Compilation & Production Build
```bash
npm run build --prefix frontend
```
Runs:
1. `tsc -b`: Strict TypeScript compiler check across all modules, interfaces, and JSX components.
2. `vite build`: Minification, tree-shaking, Rollup bundling, and chunk compression.

### Oxlint Quality Linting
```bash
npm run lint --prefix frontend
```

---

## 2. Integration Test Checklist

| Area | Feature | Test Verification |
|---|---|---|
| **Authentication** | Login Flow | User logs in with `admin@securecode.ai`; access token stored; navbar displays profile. |
| **Authentication** | Token Refresh | Expired 401 triggers `/api/v1/auth/refresh`; user continues without re-login. |
| **Routing** | Protected Routes | Unauthenticated user navigating to `/dashboard` is redirected to `/login`. |
| **Dashboard** | Zero Dummy Data | Clean empty state when no scans exist; real metrics computed from backend scans. |
| **Projects** | Project Creation | New project registered via modal; listed in project grid with repository links. |
| **Scanner** | Monaco Editor | Code editor renders with Python/JS syntax; line numbers and character counts accurate. |
| **Scanner** | File Upload | Drag-and-drop `.py` file reads content into editor and executes backend scan. |
| **Vulnerabilities** | Taint Flow Trace | Multi-step taint trace displays Source $\to$ Transform $\to$ Sink with line numbers. |
| **Remediation** | Monaco Diff | `<DiffEditor />` shows side-by-side colorized deletions and additions. |
| **Remediation** | Fix Validation | "Validate Fix" button verifies absence of target sink in AST sandbox. |
| **Remediation** | Patch Download | "Download .patch" exports valid unified diff for `git apply`. |
| **Reports** | Export Formats | PDF generation via `jsPDF`, CSV export, and JSON export all function. |
