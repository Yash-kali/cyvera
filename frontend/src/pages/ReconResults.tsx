import React, { useState, useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import { inspectAssetApi, getReconHistoryApi, ReconResult } from '../api/recon';
import {
  Shield,
  Search,
  Server,
  Globe,
  Lock,
  Cpu,
  CheckCircle2,
  AlertTriangle,
  Info,
  ExternalLink,
  Code2,
  Terminal,
  Activity,
  Zap,
  ArrowRight
} from 'lucide-react';
import { motion } from 'framer-motion';

export const ReconResults: React.FC = () => {
  const location = useLocation();
  const searchParams = new URLSearchParams(location.search);
  const initialTargetFromQuery = searchParams.get('target') || '';

  const [targetUrl, setTargetUrl] = useState<string>(initialTargetFromQuery);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ReconResult | null>(null);

  const runInspection = async (urlToScan: string) => {
    if (!urlToScan) return;
    setLoading(true);
    setError(null);
    try {
      const data = await inspectAssetApi({ target_url: urlToScan });
      setResult(data);
    } catch (err: any) {
      console.error('Asset posture inspection failed:', err);
      const detail = err.response?.data?.detail;
      setError(typeof detail === 'string' ? detail : 'Asset security inspection failed.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const queryTarget = new URLSearchParams(location.search).get('target');
    if (queryTarget) {
      setTargetUrl(queryTarget);
      runInspection(queryTarget);
    } else {
      getReconHistoryApi()
        .then((history) => {
          if (history && history.length > 0) {
            setResult(history[0]);
            setTargetUrl(history[0].target_url);
          }
        })
        .catch(() => {});
    }
  }, [location.search]);

  const handleInspect = async (e: React.FormEvent) => {
    e.preventDefault();
    await runInspection(targetUrl);
  };

  return (
    <div className="space-y-8 font-sans">
      
      {/* Header Banner */}
      <div className="glass-card p-6 rounded-3xl border border-white/10 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-2xl bg-cyber-cyan/10 border border-cyber-cyan/30 text-cyber-cyan shadow-glow-cyan">
            <Globe className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-xl font-bold font-display text-slate-100">Asset Security & Posture Inspection</h1>
            <p className="text-xs font-mono text-slate-400">Audit SSL/TLS certificate health, HTTP security headers, and domain IPv4 resolution</p>
          </div>
        </div>

        <span className="hidden sm:inline-flex px-3.5 py-1 text-xs font-mono bg-cyber-emerald/10 text-cyber-emerald border border-cyber-emerald/30 rounded-full font-bold">
          RECON ENGINE ONLINE
        </span>
      </div>

      {/* Target Inspect Input */}
      <div className="glass-card p-6 rounded-3xl border border-white/10 space-y-4">
        <form onSubmit={handleInspect} className="flex flex-col sm:flex-row items-center gap-3">
          <div className="relative flex-1 w-full">
            <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
              <Search className="w-4 h-4" />
            </div>
            <input
              type="text"
              required
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="https://target-domain.example.com"
              className="w-full pl-10 pr-4 py-3 rounded-2xl bg-white/[0.03] border border-white/10 focus:border-cyber-cyan text-slate-100 text-xs font-mono outline-none"
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full sm:w-auto px-6 py-3 rounded-2xl bg-cyber-cyan hover:bg-[#00d8e6] text-slate-950 font-mono font-bold text-xs uppercase tracking-wider shadow-glow-cyan flex items-center justify-center space-x-2 disabled:opacity-50"
          >
            {loading ? (
              <>
                <div className="w-3.5 h-3.5 border-2 border-slate-950 border-t-transparent rounded-full animate-spin" />
                <span>INSPECTING...</span>
              </>
            ) : (
              <>
                <span>INSPECT POSTURE</span>
                <ArrowRight className="w-4 h-4" />
              </>
            )}
          </button>
        </form>

        {error && (
          <div className="p-3 rounded-2xl bg-cyber-rose/10 border border-cyber-rose/30 text-cyber-rose text-xs font-mono flex items-center space-x-2">
            <AlertTriangle className="w-4 h-4 flex-shrink-0" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {result && (
        <>
          {/* Top 4 Summary Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
            
            {/* Card 1: Resolved IPv4 */}
            <div className="glass-card p-5 rounded-3xl border border-white/10 space-y-2 font-mono">
              <div className="flex items-center justify-between">
                <span className="text-[11px] text-slate-400 uppercase tracking-wider">Resolved IPv4</span>
                <Server className="w-4 h-4 text-cyber-emerald" />
              </div>
              <div className="text-xl font-bold text-slate-100 font-display">{result.ip_address}</div>
              <div className="text-[11px] text-slate-500 truncate">{result.details.dns.hostname}</div>
            </div>

            {/* Card 2: Web Server */}
            <div className="glass-card p-5 rounded-3xl border border-white/10 space-y-2 font-mono">
              <div className="flex items-center justify-between">
                <span className="text-[11px] text-slate-400 uppercase tracking-wider">Web Server</span>
                <Cpu className="w-4 h-4 text-cyber-cyan" />
              </div>
              <div className="text-xl font-bold text-cyber-cyan font-display truncate">{result.web_server}</div>
              <div className="text-[11px] text-slate-500">FastAPI / Python 3.11 Backend</div>
            </div>

            {/* Card 3: TLS Expiration */}
            <div className="glass-card p-5 rounded-3xl border border-white/10 space-y-2 font-mono">
              <div className="flex items-center justify-between">
                <span className="text-[11px] text-slate-400 uppercase tracking-wider">TLS Certificate</span>
                <Lock className="w-4 h-4 text-cyber-emerald" />
              </div>
              <div className="text-xl font-bold text-cyber-emerald font-display">
                {result.ssl_expires_days} Days Valid
              </div>
              <div className="text-[11px] text-slate-500 truncate">{result.ssl_issuer}</div>
            </div>

            {/* Card 4: Posture Score */}
            <div className="glass-card p-5 rounded-3xl border border-white/10 space-y-2 font-mono">
              <div className="flex items-center justify-between">
                <span className="text-[11px] text-slate-400 uppercase tracking-wider">Recon Health</span>
                <Shield className="w-4 h-4 text-cyber-cyan" />
              </div>
              <div className="text-xl font-bold text-slate-100 font-display">{result.security_score}/100</div>
              <div className="text-[11px] text-cyber-cyan">Telemetry Pass Rate: {result.details.headers.header_score}</div>
            </div>

          </div>

          {/* Technical Details Two-Column Bento Layout */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

            {/* Column 1: HTTP Security Headers Audit */}
            <div className="glass-card p-6 rounded-3xl border border-white/10 space-y-4">
              <div className="flex items-center justify-between border-b border-white/10 pb-3 font-mono">
                <div className="flex items-center space-x-2">
                  <Terminal className="w-4 h-4 text-cyber-cyan" />
                  <span className="font-bold text-slate-100 text-sm">Security Headers Compliance</span>
                </div>
                <span className="text-xs text-cyber-cyan font-bold">
                  {result.details.headers.passed_headers} / {result.details.headers.total_headers} COMPLIANT
                </span>
              </div>

              <div className="space-y-2.5 font-mono text-xs">
                {result.details.headers.header_details.map((h) => {
                  const isPass = h.status === 'PASS';
                  return (
                    <div
                      key={h.header}
                      className="p-3 rounded-2xl bg-white/[0.02] border border-white/5 flex items-center justify-between gap-3"
                    >
                      <div className="truncate">
                        <div className="font-bold text-slate-200">{h.header}</div>
                        <div className="text-[10px] text-slate-400 truncate">{h.value}</div>
                      </div>
                      <span
                        className={`px-2 py-0.5 rounded-full text-[10px] font-bold border flex-shrink-0 ${
                          isPass
                            ? 'bg-cyber-emerald/10 border-cyber-emerald/30 text-cyber-emerald'
                            : 'bg-cyber-rose/10 border-cyber-rose/30 text-cyber-rose'
                        }`}
                      >
                        {h.status}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Column 2: Deep Cryptographic TLS / SSL Telemetry */}
            <div className="glass-card p-6 rounded-3xl border border-white/10 space-y-4">
              <div className="flex items-center justify-between border-b border-white/10 pb-3 font-mono">
                <div className="flex items-center space-x-2">
                  <Lock className="w-4 h-4 text-cyber-emerald" />
                  <span className="font-bold text-slate-100 text-sm">Cryptographic Handshake Audit</span>
                </div>
                <span className="text-xs text-cyber-emerald font-bold">
                  {result.details.tls.status}
                </span>
              </div>

              <div className="p-4 rounded-2xl bg-black/40 border border-white/10 space-y-2 font-mono text-xs">
                <div className="flex justify-between py-1 border-b border-white/5">
                  <span className="text-slate-500">Certificate Authority:</span>
                  <span className="text-slate-200 truncate max-w-[200px]">{result.details.tls.issuer}</span>
                </div>

                <div className="flex justify-between py-1 border-b border-white/5">
                  <span className="text-slate-500">Expiration Date:</span>
                  <span className="text-slate-200">
                    {new Date(result.details.tls.expires_on).toLocaleDateString()}
                  </span>
                </div>

                <div className="flex justify-between py-1 border-b border-white/5">
                  <span className="text-slate-500">Days Remaining:</span>
                  <span className="text-cyber-cyan font-bold">{result.details.tls.days_remaining} Days</span>
                </div>

                <div className="flex justify-between py-1 border-b border-white/5">
                  <span className="text-slate-500">Cipher Suite:</span>
                  <span className="text-slate-400 font-mono text-[10px] truncate max-w-[150px]">
                    {result.details.tls.cipher_suite}
                  </span>
                </div>

                <div className="flex justify-between py-1 border-b border-white/5">
                  <span className="text-slate-500">Protocol Version:</span>
                  <span className="text-cyber-purple font-bold">{result.details.tls.tls_version}</span>
                </div>
              </div>

              {/* Sample SANs list */}
              <div className="p-4 rounded-2xl bg-black/40 border border-white/10 space-y-2">
                <div className="text-[10px] text-slate-500 uppercase tracking-wider">Subject Alternative Names (SANs):</div>
                <div className="flex flex-wrap gap-1">
                  {result.details.tls.sample_sans.map((san) => (
                    <span key={san} className="px-2.5 py-0.5 rounded-full bg-white/5 border border-white/10 text-[10px] text-slate-300 font-mono">
                      {san}
                    </span>
                  ))}
                </div>
              </div>
            </div>

          </div>
        </>
      )}

      {!result && !loading && (
        <div className="glass-card p-12 rounded-3xl border border-white/10 text-center space-y-3 font-mono">
          <Globe className="w-10 h-10 text-cyber-cyan mx-auto" />
          <h3 className="text-base font-bold text-slate-200">No Asset Scanned Yet</h3>
          <p className="text-xs text-slate-400 font-sans max-w-md mx-auto">
            Enter a target domain or endpoint above to audit DNS resolution, TLS/SSL certificates, and HTTP security headers.
          </p>
        </div>
      )}

    </div>
  );
};
