from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


class ScanOptions(BaseModel):
    enableAiClassifier: bool = True
    enableRuleMatching: bool = True
    deepAnalysis: bool = False


class ScanCreate(BaseModel):
    projectName: Optional[str] = Field("Direct Analysis", max_length=150)
    fileName: Optional[str] = Field("source_code", max_length=255)
    language: str = Field(..., min_length=2, max_length=50)
    sourceCode: str = Field(..., min_length=1)
    projectId: Optional[str] = None
    options: Optional[ScanOptions] = Field(default_factory=ScanOptions)


class BatchFileItem(BaseModel):
    fileName: str
    language: str
    sourceCode: str


class MultiFileScanRequest(BaseModel):
    projectName: str = Field(..., min_length=1, max_length=150)
    projectId: Optional[str] = None
    files: List[BatchFileItem]
    options: Optional[ScanOptions] = Field(default_factory=ScanOptions)


class FixValidationRequest(BaseModel):
    findingId: str
    proposedCode: str


class FixValidationResponse(BaseModel):
    findingId: str
    status: str
    passed: bool
    message: str
    verifiedAt: str
    remainingFindingsCount: int


class ScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: Optional[str]
    user_id: Optional[str]
    project_name: str
    file_name: str
    language: str
    status: str
    risk_score: int
    highest_severity: str
    duration_ms: int
    lines_analyzed: int
    findings_count: Dict[str, Any]
    ast_summary: Optional[Dict[str, Any]] = None
    ml_analysis: Optional[Dict[str, Any]] = None
    started_at: datetime
    completed_at: Optional[datetime] = None
    created_at: datetime
