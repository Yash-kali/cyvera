import { apiClient } from './client';

export type ScanType = 'Quick' | 'Standard' | 'Full';
export type ScanStatus = 'Pending' | 'Running' | 'Cancelling' | 'Cancelled' | 'Completed' | 'Failed';

export interface Scan {
  id: number;
  user_id: number;
  target_url: string;
  scan_type: ScanType;
  status: ScanStatus;
  security_score?: number | null;
  security_grade?: string | null;
  risk_level?: string | null;
  vulnerabilities_count?: number;
  critical_count?: number;
  authorization_confirmed?: boolean;
  authorization_timestamp?: string | null;
  current_phase?: string | null;
  progress?: number;
  started_at?: string | null;
  completed_at?: string | null;
  failure_reason?: string | null;
  created_at: string;
}

export interface CreateScanPayload {
  target_url: string;
  scan_type: ScanType;
  authorization_confirmed: boolean;
}

export interface ScanProgressResponse {
  scan_id: number;
  stage: string;
  progress: number;
  message: string;
  status?: string;
  timestamp?: string;
}

export const createScanApi = async (payload: CreateScanPayload): Promise<Scan> => {
  const response = await apiClient.post<Scan>('/scans', payload);
  return response.data;
};

export const cancelScanApi = async (scanId: number): Promise<{ success: boolean; message: string }> => {
  const response = await apiClient.post<{ success: boolean; message: string }>(`/scans/${scanId}/cancel`);
  return response.data;
};

export const getScanHistoryApi = async (): Promise<Scan[]> => {
  const response = await apiClient.get<Scan[]>('/scans');
  return response.data;
};

export const getScanDetailsApi = async (scanId: number): Promise<Scan> => {
  const response = await apiClient.get<Scan>(`/scans/${scanId}`);
  return response.data;
};

export const getScanStatusApi = async (scanId: number): Promise<ScanProgressResponse> => {
  const response = await apiClient.get<ScanProgressResponse>(`/scans/status/${scanId}`);
  return response.data;
};

export const deleteScanApi = async (scanId: number): Promise<void> => {
  await apiClient.delete(`/scans/${scanId}`);
};

export const deleteBulkScansApi = async (scanIds: number[]): Promise<void> => {
  await apiClient.post('/scans/delete-bulk', { scan_ids: scanIds });
};

export const getScanWebSocketUrl = (scanId: number, wsToken?: string): string => {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const host = window.location.hostname || 'localhost';
  const port = '8000'; // Default FastAPI backend port
  const envApiUrl = import.meta.env.VITE_API_URL;
  let baseWs = `${protocol}//${host}:${port}/ws/scans/${scanId}`;
  if (envApiUrl && envApiUrl.startsWith('http')) {
    const urlObj = new URL(envApiUrl);
    const wsProtocol = urlObj.protocol === 'https:' ? 'wss:' : 'ws:';
    baseWs = `${wsProtocol}//${urlObj.host}/ws/scans/${scanId}`;
  }
  const token = wsToken || localStorage.getItem('autopentest_jwt_token') || localStorage.getItem('token') || localStorage.getItem('access_token');
  return token ? `${baseWs}?token=${encodeURIComponent(token)}` : baseWs;
};


