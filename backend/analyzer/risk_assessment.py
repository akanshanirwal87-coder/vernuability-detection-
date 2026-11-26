"""
Risk Assessment Engine for SecureCode AI.
Calculates mathematical risk scores (0.0 to 100.0) from vulnerability findings.
Clearly labels results as an Internal Risk Estimate and avoids fabricating official CVSS vectors.
Stores explicit reasoning for each score calculation.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any


@dataclass
class RiskReport:
    overall_score: float  # 0.0 to 100.0
    risk_level: str       # "CRITICAL", "HIGH", "MEDIUM", "LOW", "CLEAN"
    score_type: str       # "INTERNAL_RISK_ESTIMATE"
    disclaimer: str
    findings_count: int
    severity_breakdown: Dict[str, int]
    reasoning: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "overallScore": round(self.overall_score, 1),
            "riskLevel": self.risk_level,
            "scoreType": self.score_type,
            "disclaimer": self.disclaimer,
            "findingsCount": self.findings_count,
            "severityBreakdown": self.severity_breakdown,
            "reasoning": self.reasoning,
        }


class RiskAssessment:
    """Calculates weighted risk based on finding severities, confidences, and exploitability."""

    SEVERITY_WEIGHTS = {
        "CRITICAL": 30.0,
        "HIGH": 18.0,
        "MEDIUM": 8.0,
        "LOW": 3.0,
        "INFORMATIONAL": 0.5,
    }

    @classmethod
    def evaluate_risk(cls, findings: List[Dict[str, Any]]) -> RiskReport:
        if not findings:
            return RiskReport(
                overall_score=0.0,
                risk_level="CLEAN",
                score_type="INTERNAL_RISK_ESTIMATE",
                disclaimer="Internal Risk Score: Derived from verified static AST, taint, and dependency findings. Not an official CVSS vector.",
                findings_count=0,
                severity_breakdown={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0},
                reasoning=["No security findings identified in analyzed codebase."],
            )

        breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0}
        raw_score = 0.0
        reasoning = []

        for f in findings:
            sev = f.get("severity", "LOW").upper()
            if sev not in breakdown:
                sev = "LOW"
            breakdown[sev] += 1

            conf = float(f.get("confidence", 0.8))
            weight = cls.SEVERITY_WEIGHTS.get(sev, 3.0)
            finding_impact = weight * conf
            raw_score += finding_impact

            cwe = f.get("cwe", "CWE-OTHER")
            title = f.get("title", "Weakness")
            det = f.get("detectionSource", "STATIC")
            reasoning.append(
                f"[{sev}] {title} ({cwe}) detected via {det} (confidence {conf:.2f}) contributes +{finding_impact:.1f} risk."
            )

        # Scale score using non-linear asymptotic saturation:
        # Score = 100 * (1 - e^(-raw_score / 30))
        # Guarantees 0 <= score <= 100 while scoring confirmed CRITICAL sinks >= 60.
        import math
        normalized_score = min(100.0, max(0.0, 100.0 * (1.0 - math.exp(-raw_score / 30.0))))

        # Determine qualitative level
        if breakdown["CRITICAL"] > 0 or normalized_score >= 80.0:
            level = "CRITICAL"
        elif breakdown["HIGH"] > 0 or normalized_score >= 60.0:
            level = "HIGH"
        elif breakdown["MEDIUM"] > 0 or normalized_score >= 35.0:
            level = "MEDIUM"
        else:
            level = "LOW"

        return RiskReport(
            overall_score=normalized_score,
            risk_level=level,
            score_type="INTERNAL_RISK_ESTIMATE",
            disclaimer="Internal Risk Score: Derived from verified static AST, taint, and dependency findings. Not an official CVSS vector.",
            findings_count=len(findings),
            severity_breakdown=breakdown,
            reasoning=reasoning,
        )
