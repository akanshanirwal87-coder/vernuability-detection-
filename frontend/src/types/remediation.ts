export type VerificationStatusType =
  | 'SUGGESTED'
  | 'SYNTAX_VALID'
  | 'SECURITY_CHECK_PASSED'
  | 'REGRESSION_TESTS_PASSED'
  | 'VERIFICATION_FAILED';

export interface RemediationReport {
  findingId: string;
  targetCwe: string;
  status: VerificationStatusType;
  passed: boolean;
  message: string;
  syntaxValid: boolean;
  vulnerabilityFixed: boolean;
  regressionFree: boolean;
  unifiedDiff?: string;
  newFindings?: Array<Record<string, unknown>>;
  verifiedAt?: string;
}

export interface FixValidationRequest {
  findingId: string;
  proposedCode: string;
}

export interface FixValidationResponse {
  findingId: string;
  status: string;
  passed: boolean;
  message: string;
  verifiedAt: string;
  remainingFindingsCount: number;
}
