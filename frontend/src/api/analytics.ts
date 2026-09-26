import { apiClient } from './client';

export interface SeverityDistribution {
  Critical: number;
  High: number;
  Medium: number;
  Low: number;
  Info: number;
}

export interface ScanProfileDistribution {
  Quick: number;
  Standard: number;
  Full: number;
}

export interface OWASPDistributionItem {
  code: string;
  name: string;
  count: number;
}

export interface TrendDataPoint {
  date: string;
  findings: number;
  scans: number;
  risk_score: number;
}

export interface AssetRiskItem {
  target_url: string;
  total_findings: number;
  critical_count: number;
  high_count: number;
  asset_risk_score: number;
  asset_security_score: number;
  risk_rating: string;
}

export interface AnalyticsFilters {
  severity?: string;
  scan_type?: string;
  date_range?: string;
  status?: string;
}

export interface RiskSummary {
  security_score: number;
  risk_score: number;
  grade: string;
  grade_color: string;
  total_findings: number;
  open_findings: number;
  resolved_findings: number;
  sla_compliance_rate: number;
  severity_distribution: SeverityDistribution;
}

export interface AnalyticsOverview {
  total_scans: number;
  completed_scans: number;
  running_scans: number;
  failed_scans: number;
  total_findings: number;
  open_findings: number;
  resolved_findings: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  info_findings: number;
  security_score: number;
  risk_score: number;
  grade: string;
  grade_color: string;
  sla_compliance_rate: number;
  severity_distribution: SeverityDistribution;
  scan_profile_distribution: ScanProfileDistribution;
  owasp_distribution: OWASPDistributionItem[];
  trend_data: TrendDataPoint[];
  asset_risks: AssetRiskItem[];
}

export const getAnalyticsOverviewApi = async (filters?: AnalyticsFilters): Promise<AnalyticsOverview> => {
  const params = new URLSearchParams();
  if (filters?.severity && filters.severity !== 'All') params.append('severity', filters.severity);
  if (filters?.scan_type && filters.scan_type !== 'All') params.append('scan_type', filters.scan_type);
  if (filters?.date_range) params.append('date_range', filters.date_range);
  if (filters?.status && filters.status !== 'All') params.append('status', filters.status);

  const response = await apiClient.get<AnalyticsOverview>(`/analytics/overview${params.toString() ? `?${params.toString()}` : ''}`);
  return response.data;
};

export const getRiskSummaryApi = async (filters?: AnalyticsFilters): Promise<RiskSummary> => {
  const params = new URLSearchParams();
  if (filters?.severity && filters.severity !== 'All') params.append('severity', filters.severity);
  if (filters?.scan_type && filters.scan_type !== 'All') params.append('scan_type', filters.scan_type);
  if (filters?.date_range) params.append('date_range', filters.date_range);
  if (filters?.status && filters.status !== 'All') params.append('status', filters.status);

  const response = await apiClient.get<RiskSummary>(`/analytics/risk-summary${params.toString() ? `?${params.toString()}` : ''}`);
  return response.data;
};

export const getAssetRiskApi = async (filters?: AnalyticsFilters): Promise<AssetRiskItem[]> => {
  const params = new URLSearchParams();
  if (filters?.severity && filters.severity !== 'All') params.append('severity', filters.severity);
  if (filters?.scan_type && filters.scan_type !== 'All') params.append('scan_type', filters.scan_type);
  if (filters?.date_range) params.append('date_range', filters.date_range);
  if (filters?.status && filters.status !== 'All') params.append('status', filters.status);

  const response = await apiClient.get<AssetRiskItem[]>(`/analytics/asset-risk${params.toString() ? `?${params.toString()}` : ''}`);
  return response.data;
};
