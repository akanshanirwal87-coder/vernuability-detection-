import { useState, useMemo } from 'react';
import type { VulnerabilityFinding, Severity } from '../types/scan';
import { FindingService } from '../services/findingService';
import type { FindingStatus } from '../types/finding';
import { compareSeverity } from '../utils/formatSeverity';

export interface FindingFilterState {
  severity?: Severity | 'ALL';
  cwe?: string;
  search?: string;
  remediationStatus?: string;
  detectionSource?: string;
}

export function useFindings(initialFindings: VulnerabilityFinding[] = []) {
  const [findings, setFindings] = useState<VulnerabilityFinding[]>(initialFindings);
  const [filters, setFilters] = useState<FindingFilterState>({
    severity: 'ALL',
    search: '',
  });
  const [sortBy, setSortBy] = useState<'severity' | 'line' | 'confidence'>('severity');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('asc');

  const filteredFindings = useMemo(() => {
    return findings.filter((f) => {
      if (filters.severity && filters.severity !== 'ALL' && f.severity !== filters.severity) {
        return false;
      }
      if (filters.cwe && !f.cwe.toLowerCase().includes(filters.cwe.toLowerCase())) {
        return false;
      }
      if (filters.remediationStatus && f.remediationStatus !== filters.remediationStatus) {
        return false;
      }
      if (filters.detectionSource && f.detectionSource !== filters.detectionSource) {
        return false;
      }
      if (filters.search) {
        const query = filters.search.toLowerCase();
        const matchesTitle = f.title.toLowerCase().includes(query);
        const matchesCwe = f.cwe.toLowerCase().includes(query);
        const matchesDesc = f.description.toLowerCase().includes(query);
        const matchesFile = f.file.toLowerCase().includes(query);
        if (!matchesTitle && !matchesCwe && !matchesDesc && !matchesFile) {
          return false;
        }
      }
      return true;
    }).sort((a, b) => {
      if (sortBy === 'severity') {
        const comp = compareSeverity(a.severity, b.severity);
        return sortOrder === 'asc' ? comp : -comp;
      }
      if (sortBy === 'line') {
        return sortOrder === 'asc' ? a.startLine - b.startLine : b.startLine - a.startLine;
      }
      if (sortBy === 'confidence') {
        return sortOrder === 'asc' ? a.confidence - b.confidence : b.confidence - a.confidence;
      }
      return 0;
    });
  }, [findings, filters, sortBy, sortOrder]);

  const updateFindingStatus = async (findingId: string, status: FindingStatus, explanation?: string) => {
    await FindingService.updateFindingStatus(findingId, status, explanation);
    setFindings((prev) =>
      prev.map((f) => (f.id === findingId ? { ...f, remediationStatus: status as any } : f))
    );
  };

  return {
    findings,
    setFindings,
    filteredFindings,
    filters,
    setFilters,
    sortBy,
    setSortBy,
    sortOrder,
    setSortOrder,
    updateFindingStatus,
  };
}

export default useFindings;
