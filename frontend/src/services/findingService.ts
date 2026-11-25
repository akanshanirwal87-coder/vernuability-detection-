import { api } from './api';
import type { FindingStatus } from '../types/finding';
import type { ApiResponse } from '../types/auth';

export class FindingService {
  static async updateFindingStatus(findingId: string, status: FindingStatus, explanation?: string): Promise<void> {
    await api.put<ApiResponse<{ id: string; status: string }>>(`/api/v1/findings/${findingId}`, {
      remediation_status: status,
      remediation_explanation: explanation || 'Updated via SecureCode AI dashboard.',
    });
  }
}

export default FindingService;
