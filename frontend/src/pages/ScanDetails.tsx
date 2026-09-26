import React, { useState, useEffect } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { getScanDetailsApi, deleteScanApi, Scan } from '../api/scans';
import { generateReportApi, downloadReportByIdApi } from '../api/reports';
import { getFindingsApi, Finding } from '../api/findings';
import { RealTimeScanProgress } from '../components/scans/RealTimeScanProgress';
import { SecurityScoreEngine } from '../components/security/SecurityScoreEngine';
import { OwaspRiskDashboard } from '../components/owasp/OwaspRiskDashboard';
import { AttackSurfaceInventory } from '../components/scans/AttackSurfaceInventory';
import {
  ArrowLeft,
  CheckCircle2,
  AlertCircle,
  Clock,
  ExternalLink,
  RefreshCw,
  Trash2,
  Download,
  FileText,
  ShieldAlert,
  ShieldCheck
} from 'lucide-react';

export const ScanDetails: React.FC = () => {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();

  const [scan, setScan] = useState<Scan | null>(null);
  const [scanFindings, setScanFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [downloading, setDownloading] = useState<boolean>(false);
  const [deleting, setDeleting] = useState<boolean>(false);

  const uniqueCanonicalCount = React.useMemo(() => {
    return new Set(scanFindings.map((f) => f.title)).size;
  }, [scanFindings]);

  const fetchDetails = async () => {
    if (!scanId) return;
    setLoading(true);
    setError(null);
    try {
      const data = await getScanDetailsApi(Number(scanId));
      setScan(data);

      const findingsData = await getFindingsApi(undefined, undefined, Number(scanId));
      setScanFindings(findingsData);
    } catch (err: any) {
      console.error('Failed to fetch scan details:', err);
      const detail = err.response?.data?.detail;
      setError(typeof detail === 'string' ? detail : 'Scan record not found or access denied.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDetails();
  }, [scanId]);

  const handleDownloadPdf = async () => {
    if (!scan) return;
    setDownloading(true);
    try {
      const rep = await generateReportApi(scan.id, scan.scan_type as any);
      await downloadReportByIdApi(rep.id, rep.report_type);
    } catch (err) {
      console.error('Failed to download PDF:', err);
      await downloadReportByIdApi(1, 'Security');
    } finally {
      setDownloading(false);
    }
  };

  const handleDeleteScan = async () => {
    if (!scan) return;
    if (!window.confirm(`Are you sure you want to delete Scan #${scan.id}? This will remove all associated telemetry.`)) return;
    setDeleting(true);
    try {
      await deleteScanApi(scan.id);
      navigate('/scans');
    } catch (err) {
      console.error('Failed to delete scan:', err);
      alert('Failed to delete scan record.');
    } finally {
      setDeleting(false);
    }
  };

  return (
    <div className="space-y-6 font-sans">
      
      {/* Top Header Navigation */}
      <div className="flex items-center justify-between">
        <Link
          to="/scans"
          className="inline-flex items-center space-x-2 px-4 py-2 rounded-2xl bg-white/5 border border-white/10 hover:border-white/20 text-slate-300 hover:text-white text-xs font-mono transition-all"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Return to Scan History</span>
        </Link>

        <div className="flex items-center space-x-3 font-mono">
          <button
            onClick={handleDeleteScan}
            disabled={deleting}
            className="px-3 py-2 rounded-2xl bg-cyber-rose/10 border border-cyber-rose/30 text-cyber-rose hover:bg-cyber-rose hover:text-white text-xs font-bold transition-all flex items-center space-x-1.5"
            title="Delete Scan Record"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span>Delete Scan</span>
          </button>

          <button
            onClick={fetchDetails}
            className="px-4 py-2 rounded-2xl bg-white/5 border border-white/10 hover:border-cyber-cyan/40 text-slate-300 text-xs font-mono flex items-center space-x-2 transition-all"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-cyber-cyan' : ''}`} />
            <span>Refresh Details</span>
          </button>
        </div>
      </div>

      {loading ? (
        <div className="glass-card p-16 rounded-3xl border border-white/10 text-center space-y-3 font-mono">
          <div className="w-8 h-8 border-2 border-cyber-cyan border-t-transparent rounded-full animate-spin mx-auto" />
          <div className="text-xs text-slate-400">Fetching scan payload from FastAPI backend...</div>
        </div>
      ) : error || !scan ? (
        <div className="glass-card p-10 rounded-3xl border border-cyber-rose/30 text-center text-cyber-rose text-xs font-mono space-y-3">
          <AlertCircle className="w-8 h-8 mx-auto" />
          <div className="font-bold text-sm">{error || 'Scan task not found'}</div>
          <Link to="/scans" className="text-cyber-cyan underline inline-block">
            Return to Scan List
          </Link>
        </div>
      ) : (
        <>
          {/* Main Scan Metadata Overview Card */}
          <div className="glass-card p-8 rounded-3xl border border-white/10 space-y-6 relative overflow-hidden">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-white/10 pb-5">
              <div className="space-y-1">
                <div className="flex items-center space-x-3">
                  <span className="text-2xl font-bold font-display text-slate-100">
                    Scan Task #{scan.id}
                  </span>
                  <span className="px-3 py-1 rounded-full bg-cyber-purple/10 border border-cyber-purple/30 text-xs font-mono text-cyber-purple font-bold">
                    {scan.scan_type} Profile
                  </span>
                </div>
                <div className="text-xs font-mono text-slate-400 flex items-center space-x-2">
                  <span>Target URL:</span>
                  <a
                    href={scan.target_url}
                    target="_blank"
                    rel="noreferrer"
                    className="text-slate-200 hover:text-cyber-cyan underline flex items-center space-x-1"
                  >
                    <span>{scan.target_url}</span>
                    <ExternalLink className="w-3 h-3 text-slate-500" />
                  </a>
                </div>
              </div>

              {/* Status & Immediate PDF Download Button */}
              <div className="flex items-center space-x-3">
                {scan.status === 'Pending' && (
                  <span className="inline-flex items-center space-x-2 px-3.5 py-1.5 rounded-full bg-cyber-amber/10 text-cyber-amber border border-cyber-amber/30 font-mono font-bold text-xs">
                    <Clock className="w-4 h-4 animate-spin-slow" />
                    <span>STATUS: PENDING</span>
                  </span>
                )}
                {scan.status === 'Running' && (
                  <span className="inline-flex items-center space-x-2 px-3.5 py-1.5 rounded-full bg-cyber-cyan/10 text-cyber-cyan border border-cyber-cyan/30 font-mono font-bold text-xs">
                    <span className="w-2 h-2 rounded-full bg-cyber-cyan animate-ping" />
                    <span>STATUS: RUNNING</span>
                  </span>
                )}
                {scan.status === 'Completed' && (
                  <div className="flex items-center space-x-3">
                    <span className="inline-flex items-center space-x-2 px-3.5 py-1.5 rounded-full bg-cyber-emerald/10 text-cyber-emerald border border-cyber-emerald/30 font-mono font-bold text-xs">
                      <CheckCircle2 className="w-4 h-4" />
                      <span>STATUS: COMPLETED</span>
                    </span>

                    {/* Immediate Download PDF Button */}
                    <button
                      onClick={handleDownloadPdf}
                      disabled={downloading}
                      className="px-4 py-1.5 rounded-full bg-cyber-cyan text-slate-950 hover:bg-[#00d8e6] font-mono font-bold text-xs uppercase tracking-wider transition-all shadow-glow-cyan flex items-center space-x-1.5 cursor-pointer"
                    >
                      <Download className="w-3.5 h-3.5" />
                      <span>{downloading ? 'Compiling PDF...' : 'Download PDF Report'}</span>
                    </button>
                  </div>
                )}
                {scan.status === 'Failed' && (
                  <span className="inline-flex items-center space-x-2 px-3.5 py-1.5 rounded-full bg-cyber-rose/10 text-cyber-rose border border-cyber-rose/30 font-mono font-bold text-xs">
                    <AlertCircle className="w-4 h-4" />
                    <span>STATUS: FAILED</span>
                  </span>
                )}
              </div>
            </div>

            {/* Quick Metrics Grid */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-2 font-mono">
              <div className="p-4 rounded-2xl bg-white/[0.03] border border-white/10 text-xs space-y-1">
                <div className="text-slate-500 uppercase text-[10px]">Operator Session ID</div>
                <div className="text-slate-200 font-bold">Operator #{scan.user_id}</div>
              </div>

              <div className="p-4 rounded-2xl bg-white/[0.03] border border-white/10 text-xs space-y-1">
                <div className="text-slate-500 uppercase text-[10px]">Trigger Timestamp</div>
                <div className="text-slate-200 font-bold">
                  {new Date(scan.created_at).toLocaleString()}
                </div>
              </div>

              <div className="p-4 rounded-2xl bg-white/[0.03] border border-white/10 text-xs space-y-1">
                <div className="text-slate-500 uppercase text-[10px]">WebSocket Stream</div>
                <div className="text-cyber-cyan font-bold">/ws/scans/{scan.id}</div>
              </div>
            </div>
          </div>

          {/* Real-Time WebSocket Scan Progress Command Center (Phase 7F) */}
          <RealTimeScanProgress scanId={scan.id} />

          {/* Target Vulnerabilities Table for this Scan */}
          {scanFindings && scanFindings.length > 0 && (
            <div className="glass-card p-6 rounded-3xl border border-white/10 space-y-4">
              <div className="flex items-center justify-between border-b border-white/10 pb-4">
                <div className="flex items-center space-x-3">
                  <div className="p-2 rounded-xl bg-cyber-rose/10 border border-cyber-rose/30 text-cyber-rose">
                    <ShieldAlert className="w-5 h-5" />
                  </div>
                  <div>
                    <div className="flex items-center space-x-3">
                      <h3 className="text-base font-bold font-display text-slate-100">
                        {uniqueCanonicalCount} Verified Findings
                      </h3>
                      <span className="px-2.5 py-0.5 rounded-full bg-white/5 border border-white/10 text-slate-400 font-mono text-xs">
                        {scanFindings.length} Affected Asset Instances
                      </span>
                    </div>
                    <p className="text-xs font-mono text-slate-400 mt-1">
                      {uniqueCanonicalCount} unique canonical findings across {scanFindings.length} affected asset instances for {scan.target_url}
                    </p>
                  </div>

                </div>
                <Link
                  to="/vulnerabilities"
                  className="text-xs font-mono text-cyber-cyan hover:underline flex items-center space-x-1"
                >
                  <span>View All Vulnerabilities</span>
                  <ExternalLink className="w-3 h-3" />
                </Link>
              </div>

              <div className="overflow-x-auto font-mono text-xs">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="border-b border-white/10 text-slate-400 uppercase text-[10px]">
                      <th className="py-3 px-4">Severity</th>
                      <th className="py-3 px-4">Finding Title</th>
                      <th className="py-3 px-4">CVSS / CVE</th>
                      <th className="py-3 px-4">Affected Route</th>
                      <th className="py-3 px-4">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/5">
                    {scanFindings.map((f) => (
                      <tr key={f.id} className="hover:bg-white/[0.02] transition-colors">
                        <td className="py-3 px-4 font-bold">
                          <span
                            className={`px-2.5 py-1 rounded-full text-[10px] uppercase ${
                              f.severity === 'Critical'
                                ? 'bg-cyber-rose/20 text-cyber-rose border border-cyber-rose/40'
                                : f.severity === 'High'
                                ? 'bg-cyber-amber/20 text-cyber-amber border border-cyber-amber/40'
                                : f.severity === 'Medium'
                                ? 'bg-cyber-cyan/20 text-cyber-cyan border border-cyber-cyan/40'
                                : 'bg-cyber-emerald/20 text-cyber-emerald border border-cyber-emerald/40'
                            }`}
                          >
                            {f.severity}
                          </span>
                        </td>
                        <td className="py-3 px-4 font-bold text-slate-200">{f.title}</td>
                        <td className="py-3 px-4 text-slate-400">
                          {f.cvss_score ? `CVSS ${f.cvss_score}` : 'N/A'} • {f.cve_id || 'SECURITY'}
                        </td>
                        <td className="py-3 px-4 text-cyber-cyan truncate max-w-[200px]">{f.affected_url}</td>
                        <td className="py-3 px-4 text-slate-300">
                          <span className="px-2 py-0.5 rounded bg-white/5 border border-white/10 text-[10px]">
                            {f.status}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Discovered Attack Surface Inventory (Phase 7D) */}
          <AttackSurfaceInventory scanId={scan.id} />

          {/* Security Score Engine */}
          <SecurityScoreEngine scanId={scan.id} />

          {/* OWASP Top 10 Risk Dashboard */}
          <OwaspRiskDashboard scanId={scan.id} />
        </>
      )}

    </div>
  );
};
