import { apiClient } from './client';

export type SeverityType = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
export type FindingStatusType =
  | 'Open'
  | 'In Review'
  | 'Confirmed'
  | 'Mitigated'
  | 'Resolved'
  | 'False Positive'
  | 'Accepted Risk';

export interface Finding {
  id: number;
  user_id: number;
  scan_id?: number | null;
  title: string;
  description: string;
  severity: SeverityType;
  cvss_score?: number | null;
  cve_id?: string | null;
  affected_url: string;
  status: FindingStatusType;
  remediation_guidance: string;
  created_at: string;
}

export interface CreateFindingPayload {
  title: string;
  description: string;
  severity: SeverityType;
  cvss_score?: number;
  cve_id?: string;
  affected_url: string;
  remediation_guidance: string;
  scan_id?: number;
}

export interface SARIFImportItem {
  title: string;
  description: string;
  severity: SeverityType;
  cvss_score?: number;
  cve_id?: string;
  affected_url: string;
  remediation_guidance: string;
}

export type SARIFImportPayload = any;

export const getFindingsApi = async (severity?: string, statusFilter?: string, scanId?: number): Promise<Finding[]> => {
  const params: Record<string, string> = {};
  if (scanId) params.scan_id = String(scanId);
  if (severity && severity !== 'All') params.severity = severity;
  if (statusFilter && statusFilter !== 'All') params.status = statusFilter;

  const response = await apiClient.get<Finding[]>('/findings', { params });
  return response.data;
};

export const getFindingByIdApi = async (findingId: number): Promise<Finding> => {
  const response = await apiClient.get<Finding>(`/findings/${findingId}`);
  return response.data;
};

export const createFindingApi = async (payload: CreateFindingPayload): Promise<Finding> => {
  const response = await apiClient.post<Finding>('/findings', payload);
  return response.data;
};

export const updateFindingStatusApi = async (findingId: number, newStatus: FindingStatusType): Promise<Finding> => {
  const response = await apiClient.patch<Finding>(`/findings/${findingId}/status`, { status: newStatus });
  return response.data;
};

export const deleteFindingApi = async (findingId: number): Promise<{ status: string; finding_id: number }> => {
  const response = await apiClient.delete<{ status: string; finding_id: number }>(`/findings/${findingId}`);
  return response.data;
};

export const importSarifApi = async (payload: SARIFImportPayload): Promise<Finding[]> => {
  const response = await apiClient.post<Finding[]>('/findings/import-sarif', payload);
  return response.data;
};
