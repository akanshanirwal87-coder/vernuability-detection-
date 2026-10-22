from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class ScanOptions(BaseModel):
    enableAstAnalysis: bool = True
    enableDataFlow: bool = True
    enableAiClassifier: bool = True
    enableRuleMatching: bool = True

class ScanCreateRequest(BaseModel):
    projectName: str
    language: str # 'python' | 'javascript' | 'typescript'
    sourceCode: str
    fileName: Optional[str] = "input_code.py"
    options: ScanOptions = Field(default_factory=ScanOptions)

class DataFlowStepModel(BaseModel):
    step: int
    label: str
    codeSnippet: str
    line: int
    type: str # 'SOURCE' | 'TRANSFORM' | 'SINK'
    description: str

class FindingModel(BaseModel):
    id: str
    scanId: str
    title: str
    category: str
    severity: str # 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
    cwe: str
    owaspCategory: str
    file: str
    startLine: int
    endLine: int
    confidence: float
    description: str
    evidence: str
    impact: str
    dataFlow: Optional[List[DataFlowStepModel]] = None
    vulnerableCode: str
    remediationCode: str
    remediationExplanation: str
    bestPractices: List[str]
    references: List[str]
    remediationStatus: str = "OPEN" # 'OPEN' | 'REMEDIATED' | 'IGNORED'
    validationStatus: str = "NOT_VALIDATED"
    validationNotes: Optional[str] = None
    detectionSource: Optional[str] = "AST" # 'AST' | 'ML_MODEL' | 'OSV_DATABASE' | 'MANAGEENGINE_BASELINE'
    cve: Optional[str] = None

class AstSummaryModel(BaseModel):
    nodesCount: int
    functionsFound: int
    importsFound: List[str]
    sinksIdentified: int

class FindingsCountModel(BaseModel):
    critical: int
    high: int
    medium: int
    low: int
    total: int

class ScanResponseModel(BaseModel):
    id: str
    projectName: str
    fileName: str
    language: str
    createdAt: str
    completedAt: Optional[str]
    status: str
    durationMs: int
    linesAnalyzed: int
    sourceCode: str
    highestSeverity: str
    findingsCount: FindingsCountModel
    findings: List[FindingModel]
    astSummary: Optional[AstSummaryModel] = None
    mlAnalysis: Optional[Dict[str, Any]] = None
    osvFindings: Optional[List[Dict[str, Any]]] = None
    manageEngineRules: Optional[List[Dict[str, Any]]] = None
    isDemo: bool = False

class FixValidationRequest(BaseModel):
    findingId: str
    proposedCode: str

class FixValidationResponse(BaseModel):
    findingId: str
    status: str # 'VALIDATION_PASSED' | 'VALIDATION_FAILED'
    passed: bool
    message: str
    verifiedAt: str
    remainingFindingsCount: int

class OsvQueryRequest(BaseModel):
    packageName: str
    ecosystem: Optional[str] = "PyPI"
    version: Optional[str] = None
