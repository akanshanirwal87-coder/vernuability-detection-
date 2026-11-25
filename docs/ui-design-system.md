# SecureCode AI — UI Design System & Component Library

## 1. Visual Theme & Color Palette

SecureCode AI employs a modern, dark-first cybersecurity aesthetic optimized for code review, data visualization, and reduced eye strain during security audits.

| Token | Hex Code | Purpose |
|---|---|---|
| Background | `#0B1020` | Root application background |
| Surface / Cards | `#111827` | Elevated card surfaces, modals, and toolbars |
| Border | `#1E293B` | Subtle panel boundaries and dividers |
| Primary Indigo | `#6366F1` | Primary CTA buttons, active tabs, brand accents |
| Accent Cyan | `#06B6D4` | AST node highlights, confidence scores, technical metrics |
| Purple Accent | `#A855F7` | AI/ML intelligence badges, OSV.dev connectors |

---

## 2. Vulnerability Severity Color Tokens

Severity tokens adhere to CVSS 3.1 impact guidelines and MITRE CWE classifications:

| Severity | Badge Background | Text Color | Border Color | Priority |
|---|---|---|---|---|
| **CRITICAL** | `bg-red-500/10` | `text-red-400` | `border-red-500/30` | 1 |
| **HIGH** | `bg-amber-500/10` | `text-amber-400` | `border-amber-500/30` | 2 |
| **MEDIUM** | `bg-yellow-500/10` | `text-yellow-400` | `border-yellow-500/30` | 3 |
| **LOW** | `bg-blue-500/10` | `text-blue-400` | `border-blue-500/30` | 4 |
| **INFO** | `bg-slate-500/10` | `text-slate-400` | `border-slate-500/30` | 5 |

---

## 3. Typography & Code Display

- **Heading Font**: `Inter, system-ui, sans-serif`
- **Monospace Font**: `JetBrains Mono, Fira Code, monospace`
- **Editor Theme**: Monaco `vs-dark` with custom line-height and bracket pair colorization.

---

## 4. Reusable Component Catalog

1. **`SecurityOverview`**: Key metric cards with live counters and animated pulse indicators for critical risks.
2. **`SeverityChart`**: Responsive Recharts bar chart displaying vulnerability counts by severity.
3. **`ScanActivity`**: Recharts area chart showing audit execution velocity over time.
4. **`RecentScans`**: Paginated table of recent audits with direct view, remediation, and report links.
5. **`CodeEditor`**: Monaco Editor configured for Python, JavaScript, and TypeScript with line counts and syntax highlighting.
6. **`FileUploader`**: Drag-and-drop zone with client validation for file size and supported extensions.
7. **`ScanProgress`**: Multi-stage progress indicator with step-by-step state markers.
8. **`FindingCard`**: Vulnerability summary card with CWE tag, severity badge, and confidence percentage.
9. **`CodeDiff`**: Monaco `<DiffEditor />` showing unified side-by-side comparison between vulnerable code and proposed fix.
10. **`Modal`**: Accessible dialog wrapper with keyboard Escape listener and backdrop blur.
