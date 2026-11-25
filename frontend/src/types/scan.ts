export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type ScanStatus = 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED';

export type ValidationStatus = 
  | 'NOT_VALIDATED' 
  | 'VALIDATION_RUNNING' 
  | 'VALIDATION_PASSED' 
  | 'VALIDATION_FAILED' 
  | 'VALIDATION_UNAVAILABLE';

export type VulnerabilityCategory =
  | 'SQL_INJECTION'
  | 'CROSS_SITE_SCRIPTING'
  | 'HARDCODED_CREDENTIALS'
  | 'COMMAND_INJECTION'
  | 'PATH_TRAVERSAL'
  | 'INSECURE_CRYPTOGRAPHY'
  | 'UNSAFE_DESERIALIZATION';

export interface DataFlowStep {
  step: number;
  label: string;
  codeSnippet: string;
  line: number;
  type: 'SOURCE' | 'TRANSFORM' | 'SINK';
  description: string;
}

export interface VulnerabilityFinding {
  id: string;
  scanId: string;
  title: string;
  category: VulnerabilityCategory;
  severity: Severity;
  cwe: string; // e.g. "CWE-89"
  owaspCategory: string; // e.g. "A03:2021-Injection"
  file: string;
  startLine: number;
  endLine: number;
  confidence: number; // 0.0 to 1.0 (e.g. 0.94)
  description: string;
  evidence: string;
  impact: string;
  dataFlow?: DataFlowStep[];
  vulnerableCode: string;
  remediationCode: string;
  remediationExplanation: string;
  bestPractices: string[];
  references: string[];
  remediationStatus: 'OPEN' | 'REMEDIATED' | 'IGNORED';
  validationStatus: ValidationStatus;
  validationNotes?: string;
  detectionSource?: 'AST' | 'ML_MODEL' | 'HYBRID_AST_AND_ML' | 'HYBRID_TAINT_AND_AST' | 'TAINT_ANALYSIS' | 'STATIC_RULES' | 'OSV_DATABASE' | 'MANAGEENGINE_BASELINE' | string;
  detectionMethods?: string[];
  confidenceRationale?: string;
  cve?: string;
}

export interface ScanOptions {
  enableAstAnalysis: boolean;
  enableDataFlow: boolean;
  enableAiClassifier: boolean;
  enableRuleMatching: boolean;
}

export interface ScanRequest {
  projectName: string;
  language: 'python' | 'javascript' | 'typescript';
  sourceCode: string;
  fileName?: string;
  options: ScanOptions;
}

export interface MlAnalysisSummary {
  modelName: string;
  version?: string;
  accuracy: number;
  precision: number;
  f1Score: number;
  totalDatasetSamples: number;
  datasetSources?: Record<string, number>;
  activeConnectors?: Array<{
    name: string;
    url: string;
    type?: string;
    status: string;
  }>;
}

export interface ScanResult {
  id: string;
  projectName: string;
  fileName: string;
  language: 'python' | 'javascript' | 'typescript';
  createdAt: string;
  completedAt?: string;
  status: ScanStatus;
  durationMs: number;
  linesAnalyzed: number;
  sourceCode: string;
  highestSeverity: Severity;
  findingsCount: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  };
  findings: VulnerabilityFinding[];
  astSummary?: {
    nodesCount: number;
    functionsFound: number;
    importsFound: string[];
    sinksIdentified: number;
  };
  mlAnalysis?: MlAnalysisSummary;
  osvFindings?: any[];
  manageEngineRules?: any[];
  isDemo?: boolean;
}

export interface ScanHistoryItem {
  id: string;
  projectName: string;
  fileName: string;
  language: 'python' | 'javascript' | 'typescript';
  createdAt: string;
  totalFindings: number;
  highestSeverity: Severity;
  status: ScanStatus;
  isDemo?: boolean;
  findingsCount?: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  };
}

export interface FixValidationRequest {
  scanId: string;
  findingId: string;
  proposedCode: string;
}

export interface FixValidationResponse {
  findingId: string;
  status: ValidationStatus;
  passed: boolean;
  message: string;
  verifiedAt: string;
  remainingFindingsCount: number;
}

export interface SecurityReport {
  scan: ScanResult;
  executiveSummary: string;
  riskScore: number; // 0 - 100
  recommendations: string[];
  generatedAt: string;
}

export interface BackendHealthResponse {
  status: 'healthy' | 'degraded' | 'offline';
  version: string;
  scannerEngine: string;
  astParserAvailable: boolean;
  aiRemediationAvailable: boolean;
  databaseConnected: boolean;
  mlModelLoaded?: boolean;
  mlAccuracy?: number;
  osvConnectorConnected?: boolean;
  manageEngineKnowledgeBaseConnected?: boolean;
  timestamp: string;
}

export interface ModelMetricsResponse {
  modelName: string;
  version: string;
  trainedAt: string;
  totalSamples: number;
  trainSamples: number;
  testSamples: number;
  featuresCount: number;
  accuracy: number;
  precision: number;
  recall: number;
  f1Score: number;
  cweAccuracy: number;
  confusionMatrix: number[][];
  cweDistribution: Record<string, number>;
  datasetSources: Record<string, number>;
  activeConnectors: Array<{
    name: string;
    url: string;
    type: string;
    status: string;
  }>;
}

export interface DatasetStatsResponse {
  totalSamples: number;
  datasetSources: Record<string, number>;
  cweDistribution: Record<string, number>;
  activeConnectors: Array<{
    name: string;
    url: string;
    status: string;
  }>;
  accuracy: number;
  precision: number;
  f1Score: number;
}

export interface OsvQueryResultItem {
  id: string;
  cve: string;
  title: string;
  details: string;
  severity: Severity;
  package: string;
  ecosystem: string;
  published?: string;
  references: string[];
  source: string;
}

export interface OsvQueryResponse {
  package: string;
  ecosystem: string;
  version?: string;
  vulnerabilitiesFound: number;
  results: OsvQueryResultItem[];
  source: string;
}

export interface ManageEngineAdvisoryItem {
  id: string;
  title: string;
  cve: string;
  cwe: string;
  severity: Severity;
  cvss: number;
  affectedProduct: string;
  source: string;
  description: string;
  codePattern: string;
  remediation: string;
  category: string;
}

export interface ManageEngineAdvisoriesResponse {
  product: string;
  url: string;
  totalAdvisories: number;
  advisories: ManageEngineAdvisoryItem[];
}

export interface AstTreeNode {
  name: string;
  type: string;
  role: 'SAFE' | 'SOURCE' | 'TRANSFORM' | 'SINK';
  description: string;
  lineno?: number;
  colOffset?: number;
  children?: AstTreeNode[];
}

export interface AstParseResponse {
  language: string;
  fileName: string;
  summary: {
    nodesCount: number;
    functionsFound: number;
    importsFound: string[];
    sinksIdentified: number;
  };
  findingsCount: number;
  findings: VulnerabilityFinding[];
  tree: AstTreeNode;
}

export interface BenchmarkItem {
  name: string;
  category: string;
  cwe: string;
  isVulnerable: boolean;
  predictedVulnerable: boolean;
  passed: boolean;
  latencyMs: number;
  detectionSource: string;
}

export interface BenchmarkRunResponse {
  totalTests: number;
  truePositives: number;
  falsePositives: number;
  trueNegatives: number;
  falseNegatives: number;
  accuracy: number;
  precision: number;
  recall: number;
  f1Score: number;
  averageLatencyMs: number;
  testedAt: string;
  results: BenchmarkItem[];
}

export interface CvssCalculationRequest {
  attackVector: string;
  attackComplexity: string;
  privilegesRequired: string;
  userInteraction: string;
  scope: string;
  confidentiality: string;
  integrity: string;
  availability: string;
}

export interface CvssCalculationResponse {
  baseScore: number;
  severity: Severity;
  vectorString: string;
  exploitabilityScore: number;
  impactScore: number;
}

export interface VivaQuestionItem {
  id: string;
  category: string;
  question: string;
  answer: string;
  formula?: string;
}

export interface VivaBankResponse {
  institution: string;
  degree: string;
  projectTitle: string;
  students: Array<{ name: string; roll: string }>;
  supervisors: string[];
  questions: VivaQuestionItem[];
}

export interface MultiFileProjectScanRequest {
  projectName: string;
  files: Array<{
    fileName: string;
    sourceCode: string;
    language?: 'python' | 'javascript' | 'typescript';
  }>;
}

