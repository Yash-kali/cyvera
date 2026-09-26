import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { createScanApi, ScanType } from '../api/scans';
import {
  Target,
  Play,
  Shield,
  Zap,
  CheckCircle2,
  AlertCircle,
  Clock,
  ArrowRight,
  Sparkles,
  Info,
  Layers,
  Activity
} from 'lucide-react';
import { motion } from 'framer-motion';

import { useScanTelemetry } from '../context/ScanContext';

export const NewScan: React.FC = () => {
  const navigate = useNavigate();
  const { refreshScans } = useScanTelemetry();

  const [targetUrl, setTargetUrl] = useState<string>('');
  const [scanType, setScanType] = useState<ScanType>('Standard');
  const [authorizationConfirmed, setAuthorizationConfirmed] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // URL Validation Logic
  const validateUrl = (url: string): string | null => {
    const trimmed = url.trim();
    if (!trimmed) return 'Target URL cannot be empty.';
    if (!trimmed.startsWith('http://') && !trimmed.startsWith('https://')) {
      return 'Target URL must start with http:// or https://';
    }
    if (trimmed.length < 8 || !trimmed.includes('.')) {
      return 'Please enter a valid domain, hostname or endpoint.';
    }
    return null;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    const validationError = validateUrl(targetUrl);
    if (validationError) {
      setError(validationError);
      return;
    }

    if (!authorizationConfirmed) {
      setError('Target authorization must be explicitly confirmed before initiating a security assessment.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const scan = await createScanApi({
        target_url: targetUrl.trim(),
        scan_type: scanType,
        authorization_confirmed: authorizationConfirmed,
      });
      await refreshScans(false);
      // Redirect to Scan Details page
      navigate(`/scans/${scan.id}`);
    } catch (err: any) {
      console.error('Failed to create scan:', err);
      const detail = err.response?.data?.detail;
      if (typeof detail === 'string') {
        setError(detail);
      } else if (Array.isArray(detail)) {
        setError(detail.map((d) => d.msg).join(', '));
      } else {
        setError('Failed to initiate scan. Please verify backend connection.');
      }
    } finally {
      setLoading(false);
    }
  };

  const scanOptions: {
    type: ScanType;
    title: string;
    duration: string;
    coverage: string;
    detail: string;
    icon: any;
    color: string;
    border: string;
  }[] = [
    {
      type: 'Quick',
      title: 'Quick Audit',
      duration: '~3-5 minutes',
      coverage: 'Port & SSL Audit',
      detail: 'Fast Posture Rating',
      icon: Zap,
      color: 'text-cyber-cyan',
      border: 'border-cyber-cyan/50 bg-cyber-cyan/10',
    },
    {
      type: 'Standard',
      title: 'Standard Audit',
      duration: '~15-20 minutes',
      coverage: 'Web App & API Scope',
      detail: 'OWASP Top 10 2021',
      icon: Shield,
      color: 'text-cyber-emerald',
      border: 'border-cyber-emerald/50 bg-cyber-emerald/10',
    },
    {
      type: 'Full',
      title: 'Full Pentest',
      duration: '~45+ minutes',
      coverage: 'Full Attack Surface',
      detail: 'Gemini AI Advisory',
      icon: Sparkles,
      color: 'text-cyber-purple',
      border: 'border-cyber-purple/50 bg-cyber-purple/10',
    },
  ];

  return (
    <div className="max-w-4xl mx-auto space-y-8 font-sans">
      
      {/* Header Banner */}
      <div className="glass-card p-6 rounded-3xl border border-white/10 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-2xl bg-cyber-cyan/10 border border-cyber-cyan/30 text-cyber-cyan shadow-glow-cyan">
            <Target className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-xl font-bold font-display text-slate-100">Deploy Autonomous Pentest Agent</h1>
            <p className="text-xs font-mono text-slate-400">Configure target URL and select AI scan intensity profile</p>
          </div>
        </div>
        <span className="hidden sm:inline-flex px-3.5 py-1 text-xs font-mono bg-cyber-emerald/10 text-cyber-emerald border border-cyber-emerald/30 rounded-full font-bold">
          FASTAPI ASYNC ENGINE CONNECTED
        </span>
      </div>

      {/* Error Alert Box */}
      {error && (
        <div className="p-4 rounded-2xl bg-cyber-rose/10 border border-cyber-rose/30 flex items-start space-x-3 text-cyber-rose text-xs font-mono">
          <AlertCircle className="w-5 h-5 flex-shrink-0 mt-0.5" />
          <div className="flex-1 font-semibold">{error}</div>
        </div>
      )}

      {/* Submission Form Card */}
      <div className="glass-card p-8 rounded-3xl border border-white/10 space-y-8">
        <form onSubmit={handleSubmit} className="space-y-8">
          
          {/* Step 1: Target URL Input with Animated Border */}
          <div className="space-y-3">
            <label className="block text-sm font-bold font-display text-slate-100">
              1. Target Endpoint / Scope URL
            </label>
            <p className="text-xs text-slate-400 font-sans">
              Specify the HTTP or HTTPS URL of the web application or API gateway scope to scan.
            </p>
            <div className="relative border-glow-gradient rounded-2xl">
              <input
                type="text"
                required
                value={targetUrl}
                onChange={(e) => {
                  setTargetUrl(e.target.value);
                  if (error) setError(null);
                }}
                placeholder="https://target-application.example.com"
                className="w-full px-5 py-4 rounded-2xl bg-[#0b101d] border border-white/10 focus:border-cyber-cyan text-slate-100 text-sm font-mono outline-none transition-all"
              />
            </div>
            <div className="text-[11px] font-mono text-slate-500 flex items-center space-x-1.5">
              <Info className="w-3.5 h-3.5 text-cyber-cyan" />
              <span>Example: https://api.staging-company.com or http://10.0.4.15:8080</span>
            </div>
          </div>

          {/* Step 2: Select Scan Type Intensity Cards */}
          <div className="space-y-4">
            <label className="block text-sm font-bold font-display text-slate-100">
              2. Select Intensity Profile
            </label>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {scanOptions.map((opt) => {
                const Icon = opt.icon;
                const isSelected = scanType === opt.type;
                return (
                  <motion.div
                    key={opt.type}
                    whileHover={{ y: -4 }}
                    onClick={() => setScanType(opt.type)}
                    className={`p-5 rounded-3xl border cursor-pointer transition-all flex flex-col justify-between space-y-4 ${
                      isSelected
                        ? opt.border
                        : 'border-white/10 bg-white/[0.02] text-slate-400 hover:border-white/20'
                    }`}
                  >
                    <div className="space-y-3">
                      <div className="flex items-center justify-between">
                        <div className={`p-2 rounded-xl border ${isSelected ? 'bg-white/10 border-white/20' : 'bg-white/5 border-white/10'}`}>
                          <Icon className={`w-4 h-4 ${opt.color}`} />
                        </div>
                        <span className="text-[10px] font-mono uppercase font-bold tracking-wider px-2 py-0.5 rounded-full bg-black/40 border border-white/10 text-slate-300">
                          {opt.type}
                        </span>
                      </div>

                      <h3 className="font-bold font-display text-slate-100 text-sm">{opt.title}</h3>

                      <div className="space-y-1.5 text-xs font-mono pt-1 text-slate-300">
                        <div className="flex items-center justify-between text-[11px]">
                          <span className="text-slate-500">Duration:</span>
                          <span className="font-semibold text-slate-200">{opt.duration}</span>
                        </div>
                        <div className="flex items-center justify-between text-[11px]">
                          <span className="text-slate-500">Coverage:</span>
                          <span className="font-semibold text-slate-200">{opt.coverage}</span>
                        </div>
                        <div className="flex items-center justify-between text-[11px]">
                          <span className="text-slate-500">Feature:</span>
                          <span className="font-semibold text-cyber-cyan">{opt.detail}</span>
                        </div>
                      </div>
                    </div>

                    <div className="pt-3 border-t border-white/10 flex items-center justify-between text-[11px] font-mono">
                      <span className="flex items-center space-x-1.5 text-slate-400">
                        <Clock className="w-3.5 h-3.5 text-cyber-cyan" />
                        <span>Est: {opt.duration}</span>
                      </span>
                      {isSelected && <CheckCircle2 className="w-4.5 h-4.5 text-cyber-cyan" />}
                    </div>
                  </motion.div>
                );
              })}
            </div>
          </div>

          {/* Authorization Attestation & Safety Scope */}
          <div className="p-4 rounded-2xl bg-cyber-cyan/5 border border-cyber-cyan/30 flex items-start space-x-3">
            <input
              type="checkbox"
              id="authConfirm"
              checked={authorizationConfirmed}
              onChange={(e) => setAuthorizationConfirmed(e.target.checked)}
              className="mt-1 h-4 w-4 rounded border-cyber-cyan/40 bg-black/40 text-cyber-cyan focus:ring-cyber-cyan cursor-pointer"
            />
            <label htmlFor="authConfirm" className="text-xs text-slate-300 leading-relaxed cursor-pointer select-none">
              <strong className="text-cyber-cyan block mb-0.5 font-mono">OPERATOR AUTHORIZATION & SCOPE ATTESTATION</strong>
              I confirm that I have explicit legal authorization to perform automated security assessments against this target domain, and agree to the platform safety limits.
            </label>
          </div>

          {/* Submit Button */}
          <div className="pt-6 border-t border-white/10 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="text-xs font-mono text-slate-400">
              Authenticated Session: <span className="text-cyber-cyan font-bold">Security Lead</span>
            </div>

            <button
              type="submit"
              disabled={loading || !authorizationConfirmed}
              className="py-4 px-8 rounded-2xl bg-gradient-to-r from-cyber-cyan to-cyber-purple hover:opacity-95 text-slate-950 font-mono font-bold text-xs uppercase tracking-wider transition-all shadow-glow-cyan flex items-center justify-center space-x-2 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? (
                <>
                  <div className="w-4 h-4 border-2 border-slate-950 border-t-transparent rounded-full animate-spin" />
                  <span>INITIALIZING SCAN AGENT...</span>
                </>
              ) : (
                <>
                  <span>DEPLOY TARGET SCAN</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </div>

        </form>
      </div>

    </div>
  );
};
