"""
Severity Engine for SecureCode AI.
Calculates and normalizes severity classifications across findings.
Severity levels: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL.
"""

from typing import Dict, Any, List, Optional
from .cwe_mapper import CWEMapper


class SeverityEngine:
    """Computes finding severity based on CWE baseline, exploitability, and confidence."""

    SEVERITY_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]

    @classmethod
    def normalize_severity(cls, severity: str) -> str:
        """Ensures severity is one of the valid enum values."""
        upper = severity.strip().upper()
        if upper in cls.SEVERITY_LEVELS:
            return upper
        if upper in ("INFO", "NOTE"):
            return "INFORMATIONAL"
        return "LOW"

    @classmethod
    def evaluate_severity(
        cls,
        cwe: str,
        detection_method: str = "AST",
        confidence: float = 0.9,
        has_direct_source: bool = False,
    ) -> str:
        """
        Determines the appropriate severity rating:
        - Uses catalog default severity as baseline.
        - Increases or decreases based on exploitability context.
        """
        defn = CWEMapper.get_definition(cwe)
        base_sev = defn.default_severity if defn else "MEDIUM"

        # If confirmed via source-to-sink taint analysis with direct user entry point
        if has_direct_source and detection_method == "TAINT_ANALYSIS":
            if base_sev in ("CRITICAL", "HIGH"):
                return base_sev  # Retains maximum criticality

        # If low confidence pattern match without dataflow confirmation
        if confidence < 0.65 and base_sev == "CRITICAL":
            return "HIGH"

        return cls.normalize_severity(base_sev)

    @classmethod
    def calculate_highest_severity(cls, findings: List[Dict[str, Any]]) -> str:
        """Returns the highest severity among a collection of findings."""
        if not findings:
            return "LOW"
        severities = [f.get("severity", "LOW").upper() for f in findings]
        for level in cls.SEVERITY_LEVELS:
            if level in severities:
                return level
        return "LOW"
