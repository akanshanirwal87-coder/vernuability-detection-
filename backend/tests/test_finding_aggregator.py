"""Unit tests for FindingAggregator and FindingDeduplicator in SecureCode AI."""

from analyzer.finding_aggregator import FindingAggregator
from analyzer.finding_deduplicator import FindingDeduplicator


def test_finding_aggregator_normalization():
    raw_findings = [
        {
            "id": "raw-1",
            "cwe": "89",
            "severity": "critical",
            "startLine": "10",
            "endLine": "12",
            "confidence": "0.95",
        }
    ]
    norm = FindingAggregator.aggregate(
        ast_findings=raw_findings,
        taint_findings=[],
        rule_findings=[],
        ml_findings=[],
    )
    assert len(norm) == 1
    f = norm[0]
    assert f["cwe"] == "CWE-89"
    assert f["severity"] == "CRITICAL"
    assert f["startLine"] == 10
    assert f["endLine"] == 12
    assert f["confidence"] == 0.95
    assert f["owaspCategory"] == "A03:2021-Injection"


def test_finding_deduplication_same_line_and_cwe():
    # Finding 1 from AST
    f1 = {
        "id": "fnd-ast-1",
        "file": "main.py",
        "startLine": 15,
        "endLine": 15,
        "cwe": "CWE-89",
        "category": "SQL_INJECTION",
        "severity": "CRITICAL",
        "confidence": 0.90,
        "detectionSource": "AST",
        "detectionMethods": ["AST"],
    }
    # Finding 2 from Taint Analysis (with dataflow)
    f2 = {
        "id": "fnd-taint-1",
        "file": "main.py",
        "startLine": 12,
        "endLine": 15,
        "cwe": "CWE-89",
        "category": "SQL_INJECTION",
        "severity": "CRITICAL",
        "confidence": 0.96,
        "detectionSource": "TAINT_ANALYSIS",
        "detectionMethods": ["TAINT_ANALYSIS"],
        "dataFlow": [
            {"step": 1, "type": "SOURCE", "line": 12},
            {"step": 2, "type": "SINK", "line": 15},
        ],
    }

    deduped = FindingDeduplicator.deduplicate([f1, f2])

    # Must be consolidated into exactly ONE finding!
    assert len(deduped) == 1
    merged = deduped[0]
    assert "AST" in merged["detectionMethods"]
    assert "TAINT_ANALYSIS" in merged["detectionMethods"]
    assert merged["detectionSource"] == "HYBRID_TAINT_AND_AST"
    assert merged["dataFlow"] is not None
    assert merged["confidence"] >= 0.96


def test_distinct_findings_not_merged():
    f1 = {"id": "1", "file": "main.py", "startLine": 5, "endLine": 5, "cwe": "CWE-89"}
    f2 = {"id": "2", "file": "main.py", "startLine": 50, "endLine": 50, "cwe": "CWE-78"}

    deduped = FindingDeduplicator.deduplicate([f1, f2])
    assert len(deduped) == 2
