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

class AstParseRequest(BaseModel):
    sourceCode: str
    language: str = "python"
    fileName: Optional[str] = "main.py"

class AstNodeModel(BaseModel):
    name: str
    type: str
    role: str # 'SAFE' | 'SOURCE' | 'TRANSFORM' | 'SINK'
    description: str
    lineno: Optional[int] = None
    colOffset: Optional[int] = None
    children: Optional[List[Dict[str, Any]]] = None

class BenchmarkItemResult(BaseModel):
    name: str
    category: str
    cwe: str
    isVulnerable: bool
    predictedVulnerable: bool
    passed: bool
    latencyMs: float
    detectionSource: str

class BenchmarkRunResponse(BaseModel):
    totalTests: int
    truePositives: int
    falsePositives: int
    trueNegatives: int
    falseNegatives: int
    accuracy: float
    precision: float
    recall: float
    f1Score: float
    averageLatencyMs: float
    testedAt: str
    results: List[BenchmarkItemResult]

class CvssCalculateRequest(BaseModel):
    attackVector: str = "N"
    attackComplexity: str = "L"
    privilegesRequired: str = "N"
    userInteraction: str = "N"
    scope: str = "U"
    confidentiality: str = "H"
    integrity: str = "H"
    availability: str = "H"

class CvssCalculateResponse(BaseModel):
    baseScore: float
    severity: str
    vectorString: str
    exploitabilityScore: float
    impactScore: float

class MultiFileItem(BaseModel):
    fileName: str
    sourceCode: str
    language: Optional[str] = "python"

class MultiFileScanRequest(BaseModel):
    projectName: str
    files: List[MultiFileItem]
    options: Optional[ScanOptions] = Field(default_factory=ScanOptions)

