"""
Taint State definitions for SecureCode AI.
Encapsulates taint statuses, variable tracking state, and source-to-sink dataflow steps.
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


class TaintStatus(str, Enum):
    UNTAINTED = "UNTAINTED"
    TAINTED = "TAINTED"
    SANITIZED = "SANITIZED"


@dataclass
class TaintVariable:
    name: str
    status: TaintStatus
    source_identifier: Optional[str] = None
    source_line: int = 0
    source_snippet: str = ""
    sanitizer_name: Optional[str] = None
    sanitizer_line: int = 0
    transform_chain: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class DataFlowStep:
    step: int
    label: str
    code_snippet: str
    line: int
    type: str  # "SOURCE", "TRANSFORM", "SINK"
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step": self.step,
            "label": self.label,
            "codeSnippet": self.code_snippet,
            "line": self.line,
            "type": self.type,
            "description": self.description,
        }


@dataclass
class TaintFinding:
    id: str
    title: str
    category: str
    severity: str
    cwe: str
    owasp: str
    file: str
    start_line: int
    end_line: int
    confidence: float
    description: str
    evidence: str
    source_location: str
    sink_location: str
    data_flow: List[DataFlowStep]
    vulnerable_code: str
    remediation_code: str
    remediation_explanation: str
    best_practices: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "cwe": self.cwe,
            "owaspCategory": self.owasp,
            "file": self.file,
            "startLine": self.start_line,
            "endLine": self.end_line,
            "confidence": self.confidence,
            "description": self.description,
            "evidence": self.evidence,
            "impact": f"Untrusted data from {self.source_location} reaches critical sink at {self.sink_location} without sanitization.",
            "dataFlow": [step.to_dict() for step in self.data_flow],
            "vulnerableCode": self.vulnerable_code,
            "remediationCode": self.remediation_code,
            "remediationExplanation": self.remediation_explanation,
            "bestPractices": self.best_practices,
            "references": self.references,
            "remediationStatus": "OPEN",
            "validationStatus": "NOT_VALIDATED",
            "detectionSource": "TAINT_ANALYSIS",
        }
