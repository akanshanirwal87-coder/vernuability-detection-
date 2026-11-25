"""Unit tests for SeverityEngine and RiskAssessment in SecureCode AI."""

from analyzer.severity_engine import SeverityEngine
from analyzer.risk_assessment import RiskAssessment


def test_severity_normalization():
    assert SeverityEngine.normalize_severity("critical") == "CRITICAL"
    assert SeverityEngine.normalize_severity("HIGH") == "HIGH"
    assert SeverityEngine.normalize_severity("info") == "INFORMATIONAL"
    assert SeverityEngine.normalize_severity("unknown") == "LOW"


def test_severity_evaluation():
    # Confirmed direct taint path
    sev = SeverityEngine.evaluate_severity("CWE-89", detection_method="TAINT_ANALYSIS", has_direct_source=True)
    assert sev == "CRITICAL"

    # Low confidence heuristic without sink
    sev_low = SeverityEngine.evaluate_severity("CWE-89", detection_method="ML_MODEL", confidence=0.5)
    assert sev_low == "HIGH"


def test_highest_severity():
    findings = [
        {"severity": "LOW"},
        {"severity": "HIGH"},
        {"severity": "MEDIUM"},
    ]
    assert SeverityEngine.calculate_highest_severity(findings) == "HIGH"

    findings_crit = findings + [{"severity": "CRITICAL"}]
    assert SeverityEngine.calculate_highest_severity(findings_crit) == "CRITICAL"


def test_risk_assessment_calculation():
    findings = [
        {"severity": "CRITICAL", "confidence": 0.95, "cwe": "CWE-89", "title": "SQLi"},
        {"severity": "HIGH", "confidence": 0.90, "cwe": "CWE-78", "title": "Cmd Injection"},
    ]
    report = RiskAssessment.evaluate_risk(findings)
    assert report.overall_score > 60.0
    assert report.risk_level in ("CRITICAL", "HIGH")
    assert report.score_type == "INTERNAL_RISK_ESTIMATE"
    assert "CVSS" in report.disclaimer
    assert len(report.reasoning) == 2


def test_empty_findings_risk():
    report = RiskAssessment.evaluate_risk([])
    assert report.overall_score == 0.0
    assert report.risk_level == "CLEAN"
