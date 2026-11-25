from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    scan_id: str
    title: str
    category: str
    severity: str
    cwe: Optional[str] = None
    owasp_category: Optional[str] = None
    file_path: str
    start_line: int
    end_line: int
    confidence: float
    description: Optional[str] = None
    evidence: Optional[str] = None
    impact: Optional[str] = None
    vulnerable_code: Optional[str] = None
    remediation_code: Optional[str] = None
    remediation_explanation: Optional[str] = None
    remediation_status: str = "OPEN"
    detection_source: str = "AST"
    cve: Optional[str] = None
    data_flow: Optional[List[Dict[str, Any]]] = None
    best_practices: Optional[List[str]] = None
    references: Optional[List[str]] = None
    created_at: datetime


class FindingUpdate(BaseModel):
    remediation_status: str = Field(..., pattern="^(OPEN|IN_REVIEW|RESOLVED|FALSE_POSITIVE)$")
    remediation_explanation: Optional[str] = None
