import { apiClient } from './client';

export interface HeaderAuditItem {
  header: string;
  status: 'PASS' | 'MISSING';
  value: string;
}

export interface ReconDetails {
  dns: {
    ip_address: string;
    dns_status: string;
    hostname: string;
  };
  tls: {
    ssl_enabled: boolean;
    status: string;
    issuer: string;
    days_remaining: number;
    expires_on: string;
    cipher_suite: string;
    tls_version: string;
    sans_count: number;
    sample_sans: string[];
  };
  headers: {
    server_header: string;
    passed_headers: number;
    total_headers: number;
    header_score: string;
    header_details: HeaderAuditItem[];
  };
}

export interface ReconResult {
  id: number;
  user_id: number;
  scan_id?: number | null;
  target_url: string;
  ip_address: string;
  web_server: string;
  ssl_issuer: string;
  ssl_expires_days: number;
  security_score: number;
  details: ReconDetails;
  created_at: string;
}

export interface InspectPayload {
  target_url: string;
  scan_id?: number;
}

export const inspectAssetApi = async (payload: InspectPayload): Promise<ReconResult> => {
  const response = await apiClient.post<ReconResult>('/recon/inspect', payload);
  return response.data;
};

export const getReconHistoryApi = async (): Promise<ReconResult[]> => {
  const response = await apiClient.get<ReconResult[]>('/recon/history');
  return response.data;
};
