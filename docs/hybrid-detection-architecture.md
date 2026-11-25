# SecureCode AI — Hybrid Vulnerability Detection Architecture

## 1. Overview

SecureCode AI Phase 3 introduces a multi-tier hybrid detection engine that merges deterministic static analysis with probabilistic AI modeling to maximize detection recall while suppressing false positives.

```
                  +-------------------------------------------------+
                  |                 TARGET SOURCE CODE              |
                  +-------------------------------------------------+
                                           │
         ┌───────────────────┬─────────────┴───────┬───────────────────┐
         ▼                   ▼                     ▼                   ▼
+─────────────────+ +─────────────────+ +─────────────────+ +─────────────────+
|   AST Scanner   | |  Taint Analyzer | |   Rule Engine   | |   ML Classifier |
| (Syntax & Sinks)| | (Source-to-Sink)| | (Hardcoded Secs)| | (TF-IDF + Sinks)|
+─────────────────+ +─────────────────+ +─────────────────+ +─────────────────+
         │                   │                     │                   │
         └───────────────────┼─────────────────────┴───────────────────┘
                             ▼
              +─────────────────────────────+
              |      FindingAggregator      |
              | (Normalization to Standard) |
              +─────────────────────────────+
                             │
                             ▼
              +─────────────────────────────+
              |     FindingDeduplicator     |
              | (Line overlap & CWE match)  |
              +─────────────────────────────+
                             │
                             ▼
              +─────────────────────────────+
              |      ConfidenceEngine       |
              | (Calibrated Non-Inflating)  |
              +─────────────────────────────+
                             │
                             ▼
              +─────────────────────────────+
              |    Severity & Risk Engine   |
              | (Evidence-based 0-100 score)|
              +─────────────────────────────+
                             │
                             ▼
              +─────────────────────────────+
              |    FINAL CONSOLIDATED SCAN   |
              |           FINDINGS          |
              +─────────────────────────────+
```

---

## 2. Evidence Aggregation & Deduplication

### 2.1 Aggregation
The `FindingAggregator` ingests raw detections from all scanners, normalizing fields into canonical representations:
- Normalizes CWE identifiers (e.g. `89` $\to$ `CWE-89`).
- Assigns corresponding OWASP Top 10 (2021) categories.
- Extracts line numbers and maps evidence snippets.
- Tags initial detection provenance (`AST`, `TAINT_ANALYSIS`, `STATIC_RULES`, `ML_MODEL`, `SCA`).

### 2.2 Deduplication & Fusion
When two or more detection techniques detect an issue at the same code location (overlapping lines and compatible weakness category):
- Detections are fused into a single unified record.
- The richest dataflow trace (e.g. full 3-step taint flow) is preserved.
- `detectionMethods` accumulates all contributing detectors (e.g. `["AST", "TAINT_ANALYSIS", "ML_MODEL"]`).
- `detectionSource` is upgraded to compound provenance:
  - `HYBRID_TAINT_AND_AST`
  - `HYBRID_AST_AND_ML`
  - `HYBRID_MULTI_DETECTOR`

---

## 3. Calibrated Confidence Scoring

To prevent artificial confidence inflation when multiple detectors analyze the same underlying syntax:
- Full source-to-sink dataflow paths with verified entry points: **0.95 to 0.98**.
- AST sink matches with dynamic strings: **0.90 to 0.94**.
- Multi-engine corroboration: Calibrated boost (+0.02, capped at 0.99).
- Standalone ML predictions without structural AST confirmation: Bounded at **0.85 max**.
- Confidence rationale is recorded with every finding explaining why the score was assigned.
