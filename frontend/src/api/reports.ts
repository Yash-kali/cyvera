import { apiClient } from './client';

export type ReportProfile = 'quick' | 'standard' | 'full' | 'Quick' | 'Standard' | 'Full';

export interface ReportItem {
  id: number;
  report_id_str: string;
  report_type: string;
  title: string;
  target_url: string;
  scan_id?: number;
  pages: number;
  created_at: string;
  download_url: string;
}

export const generateReportApi = async (
  scanId: number,
  scanProfile: ReportProfile = 'standard'
): Promise<ReportItem> => {
  const response = await apiClient.post<ReportItem>(
    `/reports/generate/${scanId}`,
    { scan_profile: scanProfile.toLowerCase() }
  );
  return response.data;
};

export const getReportsListApi = async (): Promise<ReportItem[]> => {
  const response = await apiClient.get<ReportItem[]>('/reports');
  return response.data;
};

export const getScanReportsApi = async (scanId: number): Promise<ReportItem[]> => {
  const response = await apiClient.get<ReportItem[]>(`/reports/${scanId}`);
  return response.data;
};

export const downloadReportByIdApi = async (reportId: string | number, reportType: string = 'Security'): Promise<void> => {
  const response = await apiClient.get(`/reports/download/${reportId}`, {
    responseType: 'blob',
  });

  const blob = new Blob([response.data], { type: 'application/pdf' });
  const url = window.URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.setAttribute('download', `AutoPentest_AI_${reportType}_Report_${reportId}.pdf`);
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.URL.revokeObjectURL(url);
};

export const deleteReportApi = async (reportId: number | string): Promise<void> => {
  await apiClient.delete(`/reports/${reportId}`);
};

export const deleteBulkReportsApi = async (reportIds: (number | string)[]): Promise<void> => {
  await apiClient.post('/reports/delete-bulk', { report_ids: reportIds });
};

export const downloadPdfReportApi = async (targetUrl: string = 'https://staging-api.autopentest.ai'): Promise<void> => {
  return downloadReportByIdApi(1);
};

