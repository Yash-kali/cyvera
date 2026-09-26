import { apiClient } from './client';

export interface ScoreFactors {
  critical_vulnerabilities: number;
  high_vulnerabilities: number;
  medium_vulnerabilities: number;
  ssl_issues: number;
  missing_security_headers: number;
  open_ports: number;
}

export interface ScoreDeductions {
  critical_vulnerabilities: number;
  high_vulnerabilities: number;
  medium_vulnerabilities: number;
  ssl_issues: number;
  missing_security_headers: number;
  open_ports: number;
}

export interface SecurityScoreResponse {
  score: number;
  grade: string;
  risk_level: 'Low' | 'Medium' | 'High' | 'Critical' | string;
  factors: ScoreFactors;
  deductions: ScoreDeductions;
  scan_id: number;
  target_url: string;
}

export const getSecurityScoreApi = async (scanId: number): Promise<SecurityScoreResponse> => {
  const response = await apiClient.get<SecurityScoreResponse>(`/security-score/${scanId}`);
  return response.data;
};
