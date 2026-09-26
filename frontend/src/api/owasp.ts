import { apiClient } from './client';
import { Finding } from './findings';

export interface OWASPCategoryGroup {
  code: string;
  name: string;
  category_key: string;
  count: number;
  findings: Finding[];
}

export interface OWASPFindingsResponse {
  scan_id: number;
  total_findings: number;
  categories: OWASPCategoryGroup[];
}

export interface OWASPStatsResponse {
  scan_id: number;
  total_mapped_findings: number;
  category_counts: Record<string, number>;
  severity_breakdown: Record<string, number>;
  category_severity_matrix: Record<string, Record<string, number>>;
  top_vulnerable_category: string;
}

export const getOwaspFindingsApi = async (scanId: number): Promise<OWASPFindingsResponse> => {
  const response = await apiClient.get<OWASPFindingsResponse>(`/owasp/${scanId}`);
  return response.data;
};

export const getOwaspStatsApi = async (scanId: number): Promise<OWASPStatsResponse> => {
  const response = await apiClient.get<OWASPStatsResponse>(`/owasp/stats/${scanId}`);
  return response.data;
};
