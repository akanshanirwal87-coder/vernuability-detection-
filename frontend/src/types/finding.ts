import type { Severity, VulnerabilityCategory } from './scan';

export type FindingStatus = 'OPEN' | 'RESOLVED' | 'FALSE_POSITIVE';

export interface FindingFilterOptions {
  search?: string;
  severity?: Severity | 'ALL';
  cwe?: string;
  category?: VulnerabilityCategory | 'ALL';
  detectionMethod?: string | 'ALL';
  status?: FindingStatus | 'ALL';
  file?: string;
}
