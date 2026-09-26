import { apiClient } from './client';
import { User } from './auth';

export interface UserSettings {
  id: number;
  user_id: number;
  max_concurrency: number;
  auto_patch_validation: boolean;
  db_backup_interval: 'daily' | 'weekly' | 'monthly';
  email_notifications: boolean;
  scan_completion_alerts: boolean;
  critical_finding_alerts: boolean;
  weekly_digest: boolean;
  default_scan_profile: 'Quick' | 'Standard' | 'Full';
  auto_recon_enabled: boolean;
  two_factor_enabled: boolean;
  api_key?: string | null;
  created_at: string;
  updated_at: string;
}

export interface UserSettingsUpdate {
  max_concurrency?: number;
  auto_patch_validation?: boolean;
  db_backup_interval?: 'daily' | 'weekly' | 'monthly';
  email_notifications?: boolean;
  scan_completion_alerts?: boolean;
  critical_finding_alerts?: boolean;
  weekly_digest?: boolean;
  default_scan_profile?: 'Quick' | 'Standard' | 'Full';
  auto_recon_enabled?: boolean;
  two_factor_enabled?: boolean;
}

export interface PasswordChangePayload {
  current_password: string;
  new_password: string;
  confirm_password: string;
}

export interface ApiKeyResponse {
  api_key: string;
  created_at: string;
}

export const getSettingsApi = async (): Promise<UserSettings> => {
  const response = await apiClient.get<UserSettings>('/settings');
  return response.data;
};

export const updateSettingsApi = async (payload: UserSettingsUpdate): Promise<UserSettings> => {
  const response = await apiClient.patch<UserSettings>('/settings', payload);
  return response.data;
};

export const rollApiKeyApi = async (): Promise<ApiKeyResponse> => {
  const response = await apiClient.post<ApiKeyResponse>('/settings/roll-api-key');
  return response.data;
};

export const changePasswordApi = async (payload: PasswordChangePayload): Promise<{ status: string; message: string }> => {
  const response = await apiClient.post<{ status: string; message: string }>('/auth/change-password', payload);
  return response.data;
};

export const updateProfileApi = async (payload: { username?: string; email?: string }): Promise<User> => {
  const response = await apiClient.patch<User>('/auth/profile', payload);
  return response.data;
};
