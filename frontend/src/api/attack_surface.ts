import { apiClient } from './client';

export interface AttackSurfaceAsset {
  id: number;
  scan_id: number;
  user_id: number;
  asset_type: string;
  url: string;
  normalized_url: string;
  hostname: string;
  path: string;
  query_parameters?: string[];
  http_method: string;
  content_type?: string;
  status_code?: number;
  discovered_from: string;
  source_url?: string;
  evidence: Record<string, any>;
  confidence: string;
  evidence_status: 'OBSERVED' | 'INFERRED' | 'VERIFIED';
  in_scope: boolean;
  external: boolean;
  duplicate_key: string;
  first_seen: string;
  last_seen: string;
}

export interface AttackSurfaceSummary {
  scan_id: number;
  total_assets: number;
  in_scope_count: number;
  external_count: number;
  asset_types: Record<string, number>;
  evidence_statuses: Record<string, number>;
  discovered_from: Record<string, number>;
  crawl_stats: Record<string, any>;
}

export const getAttackSurfaceApi = async (
  scanId: number,
  params?: {
    asset_type?: string;
    evidence_status?: string;
    in_scope?: boolean;
    external?: boolean;
    skip?: number;
    limit?: number;
  }
): Promise<AttackSurfaceAsset[]> => {
  const response = await apiClient.get<AttackSurfaceAsset[]>(`/attack-surface/${scanId}`, { params });
  return response.data;
};

export const getAttackSurfaceSummaryApi = async (
  scanId: number
): Promise<AttackSurfaceSummary> => {
  const response = await apiClient.get<AttackSurfaceSummary>(`/attack-surface/${scanId}/summary`);
  return response.data;
};
