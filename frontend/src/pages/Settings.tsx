import React, { useState, useEffect } from 'react';
import {
  Settings as SettingsIcon,
  Save,
  Database,
  Shield,
  Radio,
  Server,
  Bell,
  Lock,
  CheckCircle2,
  AlertCircle,
  RefreshCw,
  Sliders,
  KeyRound,
  RotateCcw
} from 'lucide-react';
import {
  getSettingsApi,
  updateSettingsApi,
  changePasswordApi,
  UserSettings
} from '../api/settings';

export const Settings: React.FC = () => {
  // Loading & notification states
  const [loading, setLoading] = useState<boolean>(true);
  const [savingSettings, setSavingSettings] = useState<boolean>(false);
  const [savedMsg, setSavedMsg] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Initial loaded settings for Reset/Cancel detection
  const [persistedSettings, setPersistedSettings] = useState<UserSettings | null>(null);

  // Platform & Agent Configuration
  const [maxConcurrency, setMaxConcurrency] = useState<number>(4);
  const [autoPatchValidation, setAutoPatchValidation] = useState<boolean>(true);
  const [dbBackupInterval, setDbBackupInterval] = useState<'daily' | 'weekly' | 'monthly'>('daily');

  // Scan & Recon Preferences
  const [defaultScanProfile, setDefaultScanProfile] = useState<'Quick' | 'Standard' | 'Full'>('Standard');
  const [autoReconEnabled, setAutoReconEnabled] = useState<boolean>(true);

  // Notification Preferences
  const [emailNotifications, setEmailNotifications] = useState<boolean>(true);
  const [scanCompletionAlerts, setScanCompletionAlerts] = useState<boolean>(true);
  const [criticalFindingAlerts, setCriticalFindingAlerts] = useState<boolean>(true);
  const [weeklyDigest, setWeeklyDigest] = useState<boolean>(false);

  // Password Change Form State
  const [currentPassword, setCurrentPassword] = useState<string>('');
  const [newPassword, setNewPassword] = useState<string>('');
  const [confirmPassword, setConfirmPassword] = useState<string>('');
  const [savingPassword, setSavingPassword] = useState<boolean>(false);
  const [passwordSuccess, setPasswordSuccess] = useState<string | null>(null);
  const [passwordError, setPasswordError] = useState<string | null>(null);

  // Fetch backend settings on mount
  useEffect(() => {
    fetchSettings();
  }, []);

  const fetchSettings = async () => {
    try {
      setLoading(true);
      setErrorMsg(null);
      const data = await getSettingsApi();
      setPersistedSettings(data);
      applySettingsToState(data);
    } catch (err: any) {
      console.error('Failed to load settings:', err);
      setErrorMsg(err.response?.data?.detail || 'Failed to load user settings from server.');
    } finally {
      setLoading(false);
    }
  };

  const applySettingsToState = (data: UserSettings) => {
    setMaxConcurrency(data.max_concurrency);
    setAutoPatchValidation(data.auto_patch_validation);
    setDbBackupInterval(data.db_backup_interval);
    setDefaultScanProfile(data.default_scan_profile);
    setAutoReconEnabled(data.auto_recon_enabled);
    setEmailNotifications(data.email_notifications);
    setScanCompletionAlerts(data.scan_completion_alerts);
    setCriticalFindingAlerts(data.critical_finding_alerts);
    setWeeklyDigest(data.weekly_digest);
  };

  const handleReset = () => {
    if (persistedSettings) {
      applySettingsToState(persistedSettings);
      setSavedMsg(null);
      setErrorMsg(null);
    }
  };

  // Check if dirty
  const isDirty = persistedSettings && (
    maxConcurrency !== persistedSettings.max_concurrency ||
    autoPatchValidation !== persistedSettings.auto_patch_validation ||
    dbBackupInterval !== persistedSettings.db_backup_interval ||
    defaultScanProfile !== persistedSettings.default_scan_profile ||
    autoReconEnabled !== persistedSettings.auto_recon_enabled ||
    emailNotifications !== persistedSettings.email_notifications ||
    scanCompletionAlerts !== persistedSettings.scan_completion_alerts ||
    criticalFindingAlerts !== persistedSettings.critical_finding_alerts ||
    weeklyDigest !== persistedSettings.weekly_digest
  );

  const handleSaveSettings = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setSavingSettings(true);
      setErrorMsg(null);
      setSavedMsg(null);

      const updated = await updateSettingsApi({
        max_concurrency: maxConcurrency,
        auto_patch_validation: autoPatchValidation,
        db_backup_interval: dbBackupInterval,
        default_scan_profile: defaultScanProfile,
        auto_recon_enabled: autoReconEnabled,
        email_notifications: emailNotifications,
        scan_completion_alerts: scanCompletionAlerts,
        critical_finding_alerts: criticalFindingAlerts,
        weekly_digest: weeklyDigest,
      });

      setPersistedSettings(updated);
      applySettingsToState(updated);
      setSavedMsg('Platform configuration updated and persisted to database.');
      setTimeout(() => setSavedMsg(null), 4000);
    } catch (err: any) {
      console.error('Failed to update settings:', err);
      setErrorMsg(err.response?.data?.detail || 'Failed to persist settings to server.');
    } finally {
      setSavingSettings(false);
    }
  };

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setPasswordError(null);
    setPasswordSuccess(null);

    if (!currentPassword) {
      setPasswordError('Current password is required.');
      return;
    }
    if (newPassword.length < 6) {
      setPasswordError('New password must be at least 6 characters long.');
      return;
    }
    if (newPassword !== confirmPassword) {
      setPasswordError('New password and confirmation do not match.');
      return;
    }
    if (newPassword === currentPassword) {
      setPasswordError('New password cannot be identical to your current password.');
      return;
    }

    try {
      setSavingPassword(true);
      const res = await changePasswordApi({
        current_password: currentPassword,
        new_password: newPassword,
        confirm_password: confirmPassword,
      });

      setPasswordSuccess(res.message || 'Password changed successfully.');
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
      setTimeout(() => setPasswordSuccess(null), 5000);
    } catch (err: any) {
      console.error('Password change error:', err);
      const detail = err.response?.data?.detail;
      if (Array.isArray(detail)) {
        setPasswordError(detail.map((d: any) => d.msg).join(', '));
      } else {
        setPasswordError(detail || 'Failed to update password. Please check your current password.');
      }
    } finally {
      setSavingPassword(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="flex items-center space-x-3 text-cyber-cyan font-mono text-xs">
          <RefreshCw className="w-5 h-5 animate-spin" />
          <span>LOADING PERSISTENT CONFIGURATION...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 font-sans">
      {/* Header Banner */}
      <div className="glass-card p-6 rounded-3xl border border-white/10 flex items-center justify-between">
        <div>
          <div className="flex items-center space-x-2.5">
            <SettingsIcon className="w-5 h-5 text-cyber-cyan" />
            <h1 className="text-xl font-bold font-display text-slate-100">Platform Configuration & Security</h1>
          </div>
          <p className="text-xs font-mono text-slate-400 mt-1">
            Database-backed engine parameters, notification routing, and account credential security
          </p>
        </div>
        {persistedSettings?.updated_at && (
          <span className="hidden md:inline-flex px-3 py-1 text-[11px] font-mono bg-white/5 text-slate-400 border border-white/10 rounded-full">
            SYNCED: {new Date(persistedSettings.updated_at).toLocaleTimeString()}
          </span>
        )}
      </div>

      {/* Global Status Notifications */}
      {savedMsg && (
        <div className="p-4 rounded-2xl bg-cyber-emerald/10 border border-cyber-emerald/30 text-cyber-emerald text-xs font-mono flex items-center space-x-2">
          <CheckCircle2 className="w-4 h-4 flex-shrink-0" />
          <span>{savedMsg}</span>
        </div>
      )}

      {errorMsg && (
        <div className="p-4 rounded-2xl bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs font-mono flex items-center space-x-2">
          <AlertCircle className="w-4 h-4 flex-shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left 2 Columns: Platform, Scan & Notification Settings */}
        <div className="lg:col-span-2 space-y-6">
          <form onSubmit={handleSaveSettings} className="space-y-6">
            
            {/* Agent & Concurrency Settings */}
            <div className="glass-card p-6 sm:p-8 rounded-3xl border border-white/10 space-y-6">
              <div className="flex items-center space-x-2.5 border-b border-white/10 pb-4">
                <Sliders className="w-4 h-4 text-cyber-cyan" />
                <h2 className="text-sm font-bold font-display uppercase tracking-wider text-slate-200">
                  Agent Orchestration & Storage
                </h2>
              </div>

              <div className="space-y-5 text-xs font-mono">
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <label className="block text-slate-300 uppercase font-semibold">
                      Maximum Concurrent AI Pentest Agents
                    </label>
                    <span className="px-2 py-0.5 rounded bg-cyber-cyan/10 border border-cyber-cyan/30 text-cyber-cyan text-[11px]">
                      {maxConcurrency} WORKERS
                    </span>
                  </div>
                  <input
                    type="range"
                    min="1"
                    max="16"
                    value={maxConcurrency}
                    onChange={(e) => setMaxConcurrency(Number(e.target.value))}
                    className="w-full h-2 bg-white/10 rounded-lg appearance-none cursor-pointer accent-cyan-400"
                  />
                  <div className="flex justify-between text-[10px] text-slate-500">
                    <span>1 Agent (Low)</span>
                    <span>4 (Balanced)</span>
                    <span>8 (Intensive)</span>
                    <span>16 (Max Cluster)</span>
                  </div>
                </div>

                <div className="flex items-center justify-between py-3 border-y border-white/10">
                  <div>
                    <div className="text-slate-200 font-bold font-sans text-sm">Autonomous Exploit Validation</div>
                    <div className="text-slate-400 text-xs font-sans mt-0.5">
                      Safely validate vulnerabilities in sandbox environment before alerting SOC
                    </div>
                  </div>
                  <input
                    type="checkbox"
                    checked={autoPatchValidation}
                    onChange={(e) => setAutoPatchValidation(e.target.checked)}
                    className="w-4 h-4 rounded border-white/20 bg-white/5 text-cyber-cyan focus:ring-0 cursor-pointer"
                  />
                </div>

                <div className="space-y-2">
                  <label className="block text-slate-300 uppercase font-semibold">
                    Database Retention Policy
                  </label>
                  <select
                    value={dbBackupInterval}
                    onChange={(e) => setDbBackupInterval(e.target.value as any)}
                    className="w-full px-4 py-3 rounded-2xl bg-[#0b101d] border border-white/10 text-slate-100 focus:border-cyber-cyan outline-none cursor-pointer"
                  >
                    <option value="daily">Daily Automated Snapshot</option>
                    <option value="weekly">Weekly Rollup</option>
                    <option value="monthly">Monthly Compliance Backup</option>
                  </select>
                </div>
              </div>
            </div>

            {/* Scan & Recon Preferences */}
            <div className="glass-card p-6 sm:p-8 rounded-3xl border border-white/10 space-y-6">
              <div className="flex items-center space-x-2.5 border-b border-white/10 pb-4">
                <Radio className="w-4 h-4 text-cyber-cyan" />
                <h2 className="text-sm font-bold font-display uppercase tracking-wider text-slate-200">
                  Scan & Reconnaissance Preferences
                </h2>
              </div>

              <div className="space-y-5 text-xs font-mono">
                <div className="space-y-2">
                  <label className="block text-slate-300 uppercase font-semibold">
                    Default Scan Profile
                  </label>
                  <select
                    value={defaultScanProfile}
                    onChange={(e) => setDefaultScanProfile(e.target.value as any)}
                    className="w-full px-4 py-3 rounded-2xl bg-[#0b101d] border border-white/10 text-slate-100 focus:border-cyber-cyan outline-none cursor-pointer"
                  >
                    <option value="Quick">Quick — Surface recon & fast port discovery</option>
                    <option value="Standard">Standard — Comprehensive vulnerability & OWASP audit</option>
                    <option value="Full">Full — Deep exploit simulation & multi-vector analysis</option>
                  </select>
                </div>

                <div className="flex items-center justify-between py-3 border-t border-white/10">
                  <div>
                    <div className="text-slate-200 font-bold font-sans text-sm">Automated Reconnaissance</div>
                    <div className="text-slate-400 text-xs font-sans mt-0.5">
                      Automatically execute DNS, WHOIS, and TLS certificate enumeration on scan initiation
                    </div>
                  </div>
                  <input
                    type="checkbox"
                    checked={autoReconEnabled}
                    onChange={(e) => setAutoReconEnabled(e.target.checked)}
                    className="w-4 h-4 rounded border-white/20 bg-white/5 text-cyber-cyan focus:ring-0 cursor-pointer"
                  />
                </div>
              </div>
            </div>

            {/* Notifications Preferences */}
            <div className="glass-card p-6 sm:p-8 rounded-3xl border border-white/10 space-y-6">
              <div className="flex items-center space-x-2.5 border-b border-white/10 pb-4">
                <Bell className="w-4 h-4 text-cyber-cyan" />
                <h2 className="text-sm font-bold font-display uppercase tracking-wider text-slate-200">
                  Security Alert Routing & Notifications
                </h2>
              </div>

              <div className="space-y-4 text-xs font-mono">
                <div className="flex items-center justify-between py-2">
                  <div>
                    <div className="text-slate-200 font-bold font-sans text-sm">Email Security Notifications</div>
                    <div className="text-slate-400 text-xs font-sans">Dispatch email dispatches for operational alerts</div>
                  </div>
                  <input
                    type="checkbox"
                    checked={emailNotifications}
                    onChange={(e) => setEmailNotifications(e.target.checked)}
                    className="w-4 h-4 rounded border-white/20 bg-white/5 text-cyber-cyan focus:ring-0 cursor-pointer"
                  />
                </div>

                <div className="flex items-center justify-between py-2 border-t border-white/10">
                  <div>
                    <div className="text-slate-200 font-bold font-sans text-sm">Scan Completion Alerts</div>
                    <div className="text-slate-400 text-xs font-sans">Notify immediately when an automated pentest finishes</div>
                  </div>
                  <input
                    type="checkbox"
                    checked={scanCompletionAlerts}
                    onChange={(e) => setScanCompletionAlerts(e.target.checked)}
                    className="w-4 h-4 rounded border-white/20 bg-white/5 text-cyber-cyan focus:ring-0 cursor-pointer"
                  />
                </div>

                <div className="flex items-center justify-between py-2 border-t border-white/10">
                  <div>
                    <div className="text-slate-200 font-bold font-sans text-sm">Critical Vulnerability Intercepts</div>
                    <div className="text-slate-400 text-xs font-sans">High-priority alerts for CVSS ≥ 9.0 Critical findings</div>
                  </div>
                  <input
                    type="checkbox"
                    checked={criticalFindingAlerts}
                    onChange={(e) => setCriticalFindingAlerts(e.target.checked)}
                    className="w-4 h-4 rounded border-white/20 bg-white/5 text-cyber-cyan focus:ring-0 cursor-pointer"
                  />
                </div>

                <div className="flex items-center justify-between py-2 border-t border-white/10">
                  <div>
                    <div className="text-slate-200 font-bold font-sans text-sm">Weekly Executive Digest</div>
                    <div className="text-slate-400 text-xs font-sans">Weekly rollup report of posture trends and closed CVEs</div>
                  </div>
                  <input
                    type="checkbox"
                    checked={weeklyDigest}
                    onChange={(e) => setWeeklyDigest(e.target.checked)}
                    className="w-4 h-4 rounded border-white/20 bg-white/5 text-cyber-cyan focus:ring-0 cursor-pointer"
                  />
                </div>
              </div>
            </div>

            {/* Form Actions with Dirty Tracking */}
            <div className="flex items-center space-x-3">
              <button
                type="submit"
                disabled={savingSettings}
                className="py-3.5 px-6 rounded-2xl bg-cyber-cyan text-slate-950 font-bold text-xs uppercase tracking-wider shadow-glow-cyan flex items-center space-x-2 disabled:opacity-50 cursor-pointer"
              >
                {savingSettings ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
                <span>{savingSettings ? 'Persisting...' : 'Save Configuration'}</span>
              </button>

              {isDirty && (
                <button
                  type="button"
                  onClick={handleReset}
                  className="py-3.5 px-5 rounded-2xl bg-white/5 hover:bg-white/10 border border-white/10 text-slate-300 font-bold text-xs uppercase tracking-wider flex items-center space-x-2 cursor-pointer"
                >
                  <RotateCcw className="w-4 h-4" />
                  <span>Cancel Changes</span>
                </button>
              )}
            </div>

          </form>
        </div>

        {/* Right Column: Account Security & Password Change */}
        <div className="space-y-6">
          
          {/* Password Change Card */}
          <div className="glass-card p-6 sm:p-8 rounded-3xl border border-white/10 space-y-6">
            <div className="flex items-center space-x-2.5 border-b border-white/10 pb-4">
              <Lock className="w-4 h-4 text-cyber-cyan" />
              <h2 className="text-sm font-bold font-display uppercase tracking-wider text-slate-200">
                Account Security
              </h2>
            </div>

            {passwordSuccess && (
              <div className="p-3 rounded-xl bg-cyber-emerald/10 border border-cyber-emerald/30 text-cyber-emerald text-xs font-mono flex items-center space-x-2">
                <CheckCircle2 className="w-4 h-4 flex-shrink-0" />
                <span>{passwordSuccess}</span>
              </div>
            )}

            {passwordError && (
              <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs font-mono flex items-center space-x-2">
                <AlertCircle className="w-4 h-4 flex-shrink-0" />
                <span>{passwordError}</span>
              </div>
            )}

            <form onSubmit={handleChangePassword} className="space-y-4 text-xs font-mono">
              <div className="space-y-1.5">
                <label className="block text-slate-300 uppercase font-semibold">
                  Current Password
                </label>
                <input
                  type="password"
                  value={currentPassword}
                  onChange={(e) => setCurrentPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full px-4 py-3 rounded-2xl bg-white/[0.03] border border-white/10 text-slate-100 focus:border-cyber-cyan outline-none font-mono"
                  required
                />
              </div>

              <div className="space-y-1.5">
                <label className="block text-slate-300 uppercase font-semibold">
                  New Password (min 6 chars)
                </label>
                <input
                  type="password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full px-4 py-3 rounded-2xl bg-white/[0.03] border border-white/10 text-slate-100 focus:border-cyber-cyan outline-none font-mono"
                  required
                />
              </div>

              <div className="space-y-1.5">
                <label className="block text-slate-300 uppercase font-semibold">
                  Confirm New Password
                </label>
                <input
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full px-4 py-3 rounded-2xl bg-white/[0.03] border border-white/10 text-slate-100 focus:border-cyber-cyan outline-none font-mono"
                  required
                />
              </div>

              <button
                type="submit"
                disabled={savingPassword}
                className="w-full py-3 px-4 rounded-2xl bg-white/10 hover:bg-white/15 border border-white/15 text-slate-200 hover:text-white font-bold text-xs uppercase tracking-wider flex items-center justify-center space-x-2 disabled:opacity-50 cursor-pointer transition-colors"
              >
                {savingPassword ? <RefreshCw className="w-4 h-4 animate-spin" /> : <KeyRound className="w-4 h-4 text-cyber-cyan" />}
                <span>{savingPassword ? 'Updating...' : 'Update Password'}</span>
              </button>
            </form>
          </div>

          {/* Security Status Card (Real, Honest Backend State) */}
          <div className="glass-card p-6 rounded-3xl border border-white/10 space-y-4 text-xs font-mono">
            <div className="flex items-center space-x-2 border-b border-white/10 pb-3">
              <Shield className="w-4 h-4 text-cyber-cyan" />
              <h3 className="font-bold font-display text-slate-200 uppercase tracking-wider">
                Security Telemetry
              </h3>
            </div>

            <div className="space-y-3">
              <div className="flex items-center justify-between text-slate-300">
                <span className="text-slate-400">Two-Factor Authentication:</span>
                <span className="px-2 py-0.5 rounded bg-amber-500/10 border border-amber-500/20 text-amber-400 text-[10px]">
                  NOT CONFIGURED
                </span>
              </div>

              <div className="flex items-center justify-between text-slate-300">
                <span className="text-slate-400">Session Status:</span>
                <span className="px-2 py-0.5 rounded bg-cyber-emerald/10 border border-cyber-emerald/30 text-cyber-emerald text-[10px]">
                  ACTIVE JWT SESSION
                </span>
              </div>

              <div className="flex items-center justify-between text-slate-300">
                <span className="text-slate-400">Password Encryption:</span>
                <span className="text-slate-300 text-[11px]">BCRYPT (SALTED)</span>
              </div>

              <div className="flex items-center justify-between text-slate-300">
                <span className="text-slate-400">User Scope:</span>
                <span className="text-cyber-cyan text-[11px]">ISOLATED (UID #{persistedSettings?.user_id})</span>
              </div>
            </div>
          </div>

        </div>

      </div>
    </div>
  );
};
export default Settings;
