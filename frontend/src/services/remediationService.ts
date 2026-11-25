import { api } from './api';
import type { FixValidationRequest, FixValidationResponse } from '../types/remediation';
import type { ApiResponse } from '../types/auth';

export class RemediationService {
  static async validateFix(scanId: string, request: FixValidationRequest): Promise<FixValidationResponse> {
    const res = await api.post<ApiResponse<FixValidationResponse>>(
      `/api/v1/scans/${scanId}/validate-fix`,
      request
    );
    return res.data.data;
  }
}

export default RemediationService;
