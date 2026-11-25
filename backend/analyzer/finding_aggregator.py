"""
Finding Aggregator for SecureCode AI.
Collects, normalizes, and groups findings from heterogeneous detection engines:
- Static AST Analysis
- Source-to-Sink Taint Analysis
- Static Rule Engine
- AI/ML Feature Ensemble Classifier
- Dependency SCA (OSV.dev)
"""

from typing import List, Dict, Any
from .cwe_mapper import CWEMapper
from .owasp_mapper import OWASPMapper
from .severity_engine import SeverityEngine


class FindingAggregator:
    """Normalizes raw finding dictionaries from different detection sources into a uniform schema."""

    @classmethod
    def normalize_finding(cls, finding: Dict[str, Any], default_source: str = "AST") -> Dict[str, Any]:
        """Ensures a finding conforms to the canonical SecureCode finding schema."""
        norm = dict(finding)

        # Ensure identification
        norm["detectionSource"] = norm.get("detectionSource", default_source)
        if "detectionMethods" not in norm:
            norm["detectionMethods"] = [norm["detectionSource"]]

        # Normalize CWE
        raw_cwe = norm.get("cwe", "CWE-OTHER")
        norm_cwe = CWEMapper.normalize_cwe(raw_cwe)
        norm["cwe"] = norm_cwe

        # Normalize OWASP
        if not norm.get("owaspCategory") or norm.get("owaspCategory") == "Code Quality":
            norm["owaspCategory"] = OWASPMapper.map_cwe_to_owasp(norm_cwe)

        # Normalize Severity
        raw_sev = norm.get("severity", "LOW")
        norm["severity"] = SeverityEngine.normalize_severity(raw_sev)

        # Ensure numeric lines
        norm["startLine"] = int(norm.get("startLine", 1))
        norm["endLine"] = int(norm.get("endLine", norm["startLine"]))

        # Ensure confidence float
        norm["confidence"] = round(float(norm.get("confidence", 0.85)), 2)

        # Ensure lists
        norm["bestPractices"] = list(norm.get("bestPractices", []))
        norm["references"] = list(norm.get("references", []))

        return norm

    @classmethod
    def aggregate(
        cls,
        ast_findings: List[Dict[str, Any]],
        taint_findings: List[Dict[str, Any]],
        rule_findings: List[Dict[str, Any]],
        ml_findings: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Aggregates all findings into a normalized collection."""
        aggregated: List[Dict[str, Any]] = []

        for f in taint_findings:
            aggregated.append(cls.normalize_finding(f, default_source="TAINT_ANALYSIS"))

        for f in ast_findings:
            aggregated.append(cls.normalize_finding(f, default_source="AST"))

        for f in rule_findings:
            aggregated.append(cls.normalize_finding(f, default_source="STATIC_RULES"))

        for f in ml_findings:
            aggregated.append(cls.normalize_finding(f, default_source="ML_MODEL"))

        return aggregated
