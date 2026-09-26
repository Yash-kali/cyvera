import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import {
  User,
  Shield,
  Key,
  Lock,
  Copy,
  Check,
  Save,
  CheckCircle2,
  AlertCircle,
  RefreshCw,
  KeyRound
} from 'lucide-react';
import {
  getSettingsApi,
  rollApiKeyApi,
  changePasswordApi,
  updateProfileApi
} from '../api/settings';

export const Profile: React.FC = () => {
  const { user } = useAuth();

  const [username, setUsername] = useState(user?.username || '');
  const [email, setEmail] = useState(user?.email || '');
  const [savingProfile, setSavingProfile] = useState<boolean>(false);

  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [savingPassword, setSavingPassword] = useState<boolean>(false);
  
  const [copiedKey, setCopiedKey] = useState<boolean>(false);
  const [apiKey, setApiKey] = useState<string>('Generating key...');
  const [rollingKey, setRollingKey] = useState<boolean>(false);
  
  const [saveSuccess, setSaveSuccess] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);

  useEffect(() => {
    if (user) {
      setUsername(user.username);
      setEmail(user.email);
    }
    loadApiKey();
  }, [user]);

  const loadApiKey = async () => {
    try {
      const data = await getSettingsApi();
      if (data.api_key) {
        setApiKey(data.api_key);
      } else {
        // Automatically provision key on first visit if null
        const rolled = await rollApiKeyApi();
        setApiKey(rolled.api_key);
      }
    } catch (err) {
      console.error('Failed to load API key:', err);
      setApiKey('API key unavailable');
    }
  };

  const handleCopyKey = () => {
    if (apiKey && apiKey !== 'Generating key...' && apiKey !== 'API key unavailable') {
      navigator.clipboard.writeText(apiKey);
      setCopiedKey(true);
      setTimeout(() => setCopiedKey(false), 2000);
    }
  };

  const handleGenerateNewKey = async () => {
    try {
      setRollingKey(true);
      setSaveError(null);
      const res = await rollApiKeyApi();
      setApiKey(res.api_key);
      setSaveSuccess('Cryptographic API key rolled and persisted successfully.');
      setTimeout(() => setSaveSuccess(null), 4000);
    } catch (err: any) {
      console.error('Failed to roll key:', err);
      setSaveError(err.response?.data?.detail || 'Failed to roll API key.');
    } finally {
      setRollingKey(false);
    }
  };

  const handleUpdateProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setSavingProfile(true);
      setSaveError(null);
      setSaveSuccess(null);

      const updated = await updateProfileApi({ username, email });
      setSaveSuccess('Profile credentials updated successfully.');
      setTimeout(() => setSaveSuccess(null), 4000);
    } catch (err: any) {
      console.error('Failed to update profile:', err);
      setSaveError(err.response?.data?.detail || 'Failed to update profile information.');
    } finally {
      setSavingProfile(false);
    }
  };

  const handleUpdatePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaveError(null);
    setSaveSuccess(null);

    if (!currentPassword) {
      setSaveError('Current password is required.');
      return;
    }
    if (newPassword.length < 6) {
      setSaveError('New password must be at least 6 characters long.');
      return;
    }
    if (newPassword !== confirmPassword) {
      setSaveError('New passwords do not match.');
      return;
    }
    if (newPassword === currentPassword) {
      setSaveError('New password cannot be identical to your current password.');
      return;
    }

    try {
      setSavingPassword(true);
      const res = await changePasswordApi({
        current_password: currentPassword,
        new_password: newPassword,
        confirm_password: confirmPassword,
      });
      setSaveSuccess(res.message || 'Passcode updated successfully.');
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
      setTimeout(() => setSaveSuccess(null), 4000);
    } catch (err: any) {
      console.error('Password update error:', err);
      const detail = err.response?.data?.detail;
      if (Array.isArray(detail)) {
        setSaveError(detail.map((d: any) => d.msg).join(', '));
      } else {
        setSaveError(detail || 'Failed to update passcode. Verify current password.');
      }
    } finally {
      setSavingPassword(false);
    }
  };

  return (
    <div className="space-y-8 font-sans">
      
      {/* Header Banner */}
      <div className="glass-card p-6 rounded-3xl border border-white/10 flex items-center justify-between">
        <div className="flex items-center space-x-4">
          <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-cyber-cyan/20 to-cyber-purple/30 border border-cyber-cyan/40 text-cyber-cyan flex items-center justify-center font-bold text-2xl font-display shadow-glow-cyan">
            {user?.username?.charAt(0).toUpperCase() || 'U'}
          </div>
          <div>
            <h1 className="text-2xl font-bold font-display text-slate-100 tracking-tight">
              {user?.username}
            </h1>
            <p className="text-xs font-mono text-slate-400">
              Certified Cyber Operator • Account ID #{user?.id}
            </p>
          </div>
        </div>

        <span className="hidden sm:inline-flex px-3.5 py-1 text-xs font-mono bg-cyber-emerald/10 text-cyber-emerald border border-cyber-emerald/30 rounded-full font-bold">
          ACTIVE OPERATOR
        </span>
      </div>

      {/* Feedback Messages */}
      {saveSuccess && (
        <div className="p-4 rounded-2xl bg-cyber-emerald/10 border border-cyber-emerald/30 flex items-center space-x-3 text-cyber-emerald text-xs font-mono">
          <CheckCircle2 className="w-4 h-4 flex-shrink-0" />
          <span>{saveSuccess}</span>
        </div>
      )}

      {saveError && (
        <div className="p-4 rounded-2xl bg-rose-500/10 border border-rose-500/30 flex items-center space-x-3 text-rose-400 text-xs font-mono">
          <AlertCircle className="w-4 h-4 flex-shrink-0" />
          <span>{saveError}</span>
        </div>
      )}

      {/* API Credentials Card */}
      <div className="glass-card p-6 rounded-3xl border border-white/10 space-y-4 font-mono">
        <div className="flex items-center justify-between border-b border-white/10 pb-3">
          <div className="flex items-center space-x-2">
            <Key className="w-4 h-4 text-cyber-cyan" />
            <h3 className="font-bold font-display text-slate-100 text-base">API Secret Credentials</h3>
          </div>
          <button
            onClick={handleGenerateNewKey}
            disabled={rollingKey}
            className="px-3 py-1 rounded-xl bg-white/5 border border-white/10 hover:border-white/20 text-slate-300 text-xs flex items-center space-x-1 cursor-pointer disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${rollingKey ? 'animate-spin' : ''}`} />
            <span>{rollingKey ? 'Rolling...' : 'Roll Key'}</span>
          </button>
        </div>

        <div className="flex items-center space-x-3">
          <input
            type="text"
            readOnly
            value={apiKey}
            className="flex-1 px-4 py-3 rounded-2xl bg-black/40 border border-white/10 text-cyber-cyan text-xs font-mono outline-none"
          />
          <button
            onClick={handleCopyKey}
            className="px-4 py-3 rounded-2xl bg-cyber-cyan text-slate-950 font-bold text-xs flex items-center space-x-1.5 shadow-glow-cyan cursor-pointer"
          >
            {copiedKey ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
            <span>{copiedKey ? 'COPIED' : 'COPY'}</span>
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        
        {/* Profile Details Form */}
        <div className="glass-card p-6 rounded-3xl border border-white/10 space-y-4">
          <div className="flex items-center space-x-2 border-b border-white/10 pb-3">
            <User className="w-4 h-4 text-cyber-cyan" />
            <h3 className="font-bold font-display text-slate-100 text-base">Account Identity</h3>
          </div>

          <form onSubmit={handleUpdateProfile} className="space-y-4 text-xs font-mono">
            <div className="space-y-1.5">
              <label className="block text-slate-300 uppercase font-semibold">Username</label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="w-full px-4 py-3 rounded-2xl bg-white/[0.03] border border-white/10 text-slate-100 focus:border-cyber-cyan outline-none"
                required
              />
            </div>

            <div className="space-y-1.5">
              <label className="block text-slate-300 uppercase font-semibold">Email Address</label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full px-4 py-3 rounded-2xl bg-white/[0.03] border border-white/10 text-slate-100 focus:border-cyber-cyan outline-none"
                required
              />
            </div>

            <button
              type="submit"
              disabled={savingProfile}
              className="py-3 px-5 rounded-2xl bg-white/10 hover:bg-white/15 border border-white/15 text-slate-200 font-bold text-xs uppercase tracking-wider flex items-center space-x-2 cursor-pointer disabled:opacity-50"
            >
              {savingProfile ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4 text-cyber-cyan" />}
              <span>{savingProfile ? 'Saving...' : 'Save Profile'}</span>
            </button>
          </form>
        </div>

        {/* Password Change Form */}
        <div className="glass-card p-6 rounded-3xl border border-white/10 space-y-4">
          <div className="flex items-center space-x-2 border-b border-white/10 pb-3">
            <Lock className="w-4 h-4 text-cyber-cyan" />
            <h3 className="font-bold font-display text-slate-100 text-base">Change Passcode</h3>
          </div>

          <form onSubmit={handleUpdatePassword} className="space-y-4 text-xs font-mono">
            <div className="space-y-1.5">
              <label className="block text-slate-300 uppercase font-semibold">Current Passcode</label>
              <input
                type="password"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full px-4 py-3 rounded-2xl bg-white/[0.03] border border-white/10 text-slate-100 focus:border-cyber-cyan outline-none"
                required
              />
            </div>

            <div className="space-y-1.5">
              <label className="block text-slate-300 uppercase font-semibold">New Passcode (min 6 chars)</label>
              <input
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full px-4 py-3 rounded-2xl bg-white/[0.03] border border-white/10 text-slate-100 focus:border-cyber-cyan outline-none"
                required
              />
            </div>

            <div className="space-y-1.5">
              <label className="block text-slate-300 uppercase font-semibold">Confirm New Passcode</label>
              <input
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full px-4 py-3 rounded-2xl bg-white/[0.03] border border-white/10 text-slate-100 focus:border-cyber-cyan outline-none"
                required
              />
            </div>

            <button
              type="submit"
              disabled={savingPassword}
              className="py-3 px-5 rounded-2xl bg-white/10 hover:bg-white/15 border border-white/15 text-slate-200 font-bold text-xs uppercase tracking-wider flex items-center space-x-2 cursor-pointer disabled:opacity-50"
            >
              {savingPassword ? <RefreshCw className="w-4 h-4 animate-spin" /> : <KeyRound className="w-4 h-4 text-cyber-cyan" />}
              <span>{savingPassword ? 'Updating...' : 'Update Passcode'}</span>
            </button>
          </form>
        </div>

      </div>

    </div>
  );
};
export default Profile;
