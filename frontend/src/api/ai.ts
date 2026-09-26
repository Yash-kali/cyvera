import { apiClient } from './client';

export interface AIExplanation {
  id: number;
  user_id: number;
  finding_id: number;
  executive_summary: string;
  technical_description: string;
  business_impact: string;
  attack_scenario: string;
  remediation_guidance: string;
  secure_coding_recommendations?: string;
  owasp_mapping: string;
  created_at: string;
}

export const analyzeFindingApi = async (findingId: number): Promise<AIExplanation> => {
  const response = await apiClient.post<AIExplanation>(`/ai/analyze/${findingId}`);
  return response.data;
};

export const getAiResultApi = async (findingId: number): Promise<AIExplanation> => {
  const response = await apiClient.get<AIExplanation>(`/ai/result/${findingId}`);
  return response.data;
};

export const explainVulnerabilityApi = async (findingId: number): Promise<AIExplanation> => {
  return analyzeFindingApi(findingId);
};

export const getAIExplanationApi = async (findingId: number): Promise<AIExplanation> => {
  return getAiResultApi(findingId);
};
