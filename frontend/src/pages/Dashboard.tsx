import React, { useState, useEffect, useCallback } from 'react';
import {
  Target,
  Plus,
  CheckCircle2,
  AlertCircle,
  Play,
  X,
  Loader2,
  RefreshCw,
  Trash2,
  FileText,
  AlertTriangle,
} from 'lucide-react';

import { SecurityScoreCore } from '../components/dashboard/SecurityScoreCore';
import { VulnerabilityGalaxy } from '../components/dashboard/VulnerabilityGalaxy';
import { ReconNetworkGraph } from '../components/dashboard/ReconNetworkGraph';
import { ScanActivityFeedWidget } from '../components/dashboard/ScanActivityFeedWidget';
import { OwaspDistributionWidget } from '../components/dashboard/OwaspDistributionWidget';
import { SeverityRadarChartWidget } from '../components/dashboard/SeverityRadarChartWidget';
import { AiRecommendationsWidget } from '../components/dashboard/AiRecommendationsWidget';
import { CinematicScanSequence } from '../components/scans/CinematicScanSequence';
import { soundEngine } from '../utils/soundEffects';
import {
  createScanApi,
  deleteScanApi,
  Scan,
} from '../api/scans';
import { useScanTelemetry } from '../context/ScanContext';
import { getRiskSummaryApi, RiskSummary } from '../api/analytics';
import { getFindingsApi, Finding } from '../api/findings';
import { getReconHistoryApi, ReconResult } from '../api/recon';
import { getOwaspStatsApi, OWASPStatsResponse } from '../api/owasp';

export const Dashboard: React.FC = () => {
  const {
    scans: scansList,
    isLoading,
    error,
    activeScanId,
    activeScanProgress,
    latestScan,
    latestCompletedScan,
    refreshScans,
    setActiveScanId,
    setActiveScanProgress,
  } = useScanTelemetry();

  const [modalOpen, setModalOpen] = useState<boolean>(false);
  const [targetUrl, setTargetUrl] = useState<string>('');
  const [scanType, setScanType] = useState<string>('full');
  const [isLaunching, setIsLaunching] = useState<boolean>(false);
  const [deletingId, setDeletingId] = useState<number | null>(null);

  const [riskSummary, setRiskSummary] = useState<RiskSummary | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [latestRecon, setLatestRecon] = useState<ReconResult | null>(null);
  const [owaspStats, setOwaspStats] = useState<OWASPStatsResponse | null>(null);

  // Load associated findings, recon, and OWASP data for active or latest scan
  useEffect(() => {
    let isCancelled = false;

    const loadAssociatedTelemetry = async () => {
      if (scansList.length === 0) {
        setFindings([]);
        setLatestRecon(null);
        setOwaspStats(null);
        setRiskSummary(null);
        return;
      }

      const relevantScan =
        (activeScanId ? scansList.find((s) => s.id === activeScanId) : null) ||
        latestCompletedScan ||
        latestScan;

      if (!relevantScan) return;

      try {
        const [findingsRes, reconRes, riskRes, owaspRes] = await Promise.allSettled([
          getFindingsApi(undefined, undefined, relevantScan.id),
          getReconHistoryApi(),
          getRiskSummaryApi(),
          relevantScan.status?.toLowerCase() === 'completed'
            ? getOwaspStatsApi(relevantScan.id)
            : Promise.resolve(null),
        ]);

        if (isCancelled) return;

        if (findingsRes.status === 'fulfilled') {
          setFindings(findingsRes.value);
        }
        if (reconRes.status === 'fulfilled') {
          const match =
            reconRes.value.find((r) => r.scan_id === relevantScan.id) ||
            reconRes.value[0] ||
            null;
          setLatestRecon(match);
        }
        if (riskRes.status === 'fulfilled') {
          setRiskSummary(riskRes.value);
        }
        if (owaspRes.status === 'fulfilled' && owaspRes.value) {
          setOwaspStats(owaspRes.value);
        } else {
          setOwaspStats(null);
        }
      } catch (err) {
        console.error('Failed to load associated scan telemetry:', err);
      }
    };

    loadAssociatedTelemetry();

    return () => {
      isCancelled = true;
    };
  }, [scansList, activeScanId, latestCompletedScan, latestScan]);

  const [authConfirmed, setAuthConfirmed] = useState<boolean>(false);

  const handleLaunchScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetUrl.trim() || !authConfirmed) return;

    setIsLaunching(true);
    soundEngine.playScanStarted();

    try {
      const createdScan = await createScanApi({
        target_url: targetUrl.trim(),
        scan_type: (scanType.toLowerCase().includes('quick') ? 'Quick' : (scanType.toLowerCase().includes('full') ? 'Full' : 'Standard')),
        authorization_confirmed: true,
      });

      setActiveScanId(createdScan.id);
      setActiveScanProgress({
        stage: 'Validating Target',
        progress: 10,
        status: 'Running',
      });

      await refreshScans(false);

      setIsLaunching(false);
      setModalOpen(false);
      setAuthConfirmed(false);
      setTargetUrl('');
    } catch (err: any) {
      console.error('Failed to create scan from dashboard:', err);
      setIsLaunching(false);
      alert(err.response?.data?.detail || 'Failed to launch scan. Please check target URL.');
    }
  };

  const handleDeleteScan = async (scanId: number) => {
    if (
      !window.confirm(
        `Are you sure you want to delete scan record SCN-${scanId}? All associated findings, recon, and report artifacts will be permanently deleted.`
      )
    ) {
      return;
    }

    soundEngine.playClick();
    setDeletingId(scanId);

    try {
      await deleteScanApi(scanId);
      await refreshScans(false);
    } catch (err: any) {
      console.error('Failed to delete scan:', err);
      alert(err.response?.data?.detail || 'Failed to delete scan record.');
    } finally {
      setDeletingId(null);
    }
  };

  // Compute metrics strictly from real backend data (null for honest empty state)
  const currentScore = latestCompletedScan?.security_score ?? null;
  const currentGrade = latestCompletedScan?.security_grade ?? null;
  const currentRisk = latestCompletedScan?.risk_level ?? null;

  let currentPipelineStage = 'Security Pipeline Standby — Ready for Target Scan';
  let currentPipelineProgress = 0;

  if (activeScanProgress) {
    currentPipelineStage = activeScanProgress.stage;
    currentPipelineProgress = activeScanProgress.progress;
  } else if (scansList.length > 0 && scansList[0].status?.toLowerCase() === 'completed') {
    currentPipelineStage = 'Autonomous Scan Pipeline Completed — Telemetry Verified';
    currentPipelineProgress = 100;
  } else if (scansList.length > 0 && scansList[0].status?.toLowerCase() === 'running') {
    currentPipelineStage = scansList[0].current_phase
      ? `Audit Executing — Stage: ${scansList[0].current_phase.replace(/_/g, ' ')}`
      : 'Audit Executing — Real-time Telemetry In Progress';
    currentPipelineProgress = typeof scansList[0].progress === 'number' ? scansList[0].progress : 25;
  } else if (scansList.length > 0 && (scansList[0].status?.toLowerCase() === 'cancelled' || scansList[0].status?.toLowerCase() === 'cancelling')) {
    currentPipelineStage = 'Scan Cancelled by Operator';
    currentPipelineProgress = typeof scansList[0].progress === 'number' ? scansList[0].progress : 0;
  } else if (scansList.length > 0 && scansList[0].status?.toLowerCase() === 'failed') {
    currentPipelineStage = 'Scan Execution Failed — Check Target Availability';
    currentPipelineProgress = 0;
  }

  const topFinding =
    findings.find((f) => f.severity === 'Critical') ||
    findings.find((f) => f.severity === 'High') ||
    findings[0] ||
    null;

  return (
    <div className="space-y-8 font-sans">
      {/* Enterprise Header Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 glass-card p-6 rounded-3xl border border-white/10 relative overflow-hidden bg-[#070b12]">
        <div className="space-y-1">
          <div className="flex items-center space-x-2.5">
            <span className="h-2.5 w-2.5 rounded-full bg-cyber-emerald animate-pulse" />
            <h1 className="text-2xl font-bold font-display text-slate-100 tracking-tight">
              Security Operations Center
            </h1>
          </div>
          <p className="text-xs text-slate-400 font-sans">
            Real-time vulnerability telemetry, asset posture audit, and autonomous security intelligence
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={() => {
              soundEngine.playClick();
              refreshScans(true);
            }}
            disabled={isLoading}
            className="p-2.5 rounded-xl bg-white/5 hover:bg-white/10 text-slate-300 hover:text-white border border-white/10 transition-all flex items-center justify-center cursor-pointer"
            title="Refresh Telemetry"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
          </button>

          <button
            onClick={() => {
              soundEngine.playClick();
              setModalOpen(true);
            }}
            className="px-5 py-2.5 rounded-xl bg-cyber-cyan hover:bg-[#00d8e6] text-slate-950 font-mono font-bold text-xs uppercase tracking-wider transition-colors flex items-center justify-center space-x-2 cursor-pointer shadow-glow-cyan"
          >
            <Plus className="w-4 h-4" />
            <span>New Target Scan</span>
          </button>
        </div>
      </div>

      {/* Cinematic 5-Stage Scan Pipeline Sequence — Real Progress */}
      <CinematicScanSequence currentStage={currentPipelineStage} progress={currentPipelineProgress} />

      {/* Bento Grid Tier 1: Security Score Reactor Core & Radar & Feed */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <SecurityScoreCore score={currentScore} grade={currentGrade} riskLevel={currentRisk} />
        <ScanActivityFeedWidget scans={scansList} />
        <SeverityRadarChartWidget riskSummary={riskSummary} />
      </div>

      {/* Bento Grid Tier 2: Vulnerability Galaxy & Recon Neural Map */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <VulnerabilityGalaxy findings={findings} />
        <ReconNetworkGraph recon={latestRecon} />
      </div>

      {/* Bento Grid Tier 3: OWASP Distribution Chart & AI Threat Advisor */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <OwaspDistributionWidget owaspStats={owaspStats} />
        <AiRecommendationsWidget topFinding={topFinding} />
      </div>

      {/* Recent Scans Table — Real Database Telemetry */}
      <div className="glass-card p-6 rounded-3xl border border-white/10 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-white/10 pb-4 font-mono">
          <div>
            <h3 className="text-lg font-bold font-display text-slate-100">Active Penetration Scan Queue</h3>
            <p className="text-xs text-slate-400">Database-driven target execution history & posture metrics</p>
          </div>
          <div className="flex items-center space-x-2 text-xs text-cyber-cyan font-mono">
            <span className="w-2 h-2 rounded-full bg-cyber-cyan" />
            <span>{scansList.length} Registered {scansList.length === 1 ? 'Scan' : 'Scans'}</span>
          </div>
        </div>

        {/* LOADING STATE */}
        {isLoading ? (
          <div className="py-16 flex flex-col items-center justify-center space-y-3 font-mono text-xs text-slate-400">
            <Loader2 className="w-8 h-8 text-cyber-cyan animate-spin" />
            <span>Synchronizing security operations telemetry...</span>
          </div>
        ) : error ? (
          /* ERROR STATE */
          <div className="p-6 rounded-2xl bg-cyber-rose/10 border border-cyber-rose/30 flex flex-col sm:flex-row items-center justify-between gap-4">
            <div className="flex items-center space-x-3 text-cyber-rose">
              <AlertTriangle className="w-5 h-5 flex-shrink-0" />
              <span className="text-xs font-mono">{error}</span>
            </div>
            <button
              onClick={() => refreshScans(true)}
              className="px-4 py-2 rounded-xl bg-cyber-rose/20 text-cyber-rose hover:bg-cyber-rose hover:text-white font-mono font-bold text-xs uppercase transition-all"
            >
              Retry Sync
            </button>
          </div>
        ) : scansList.length === 0 ? (
          /* EMPTY STATE */
          <div className="py-16 px-4 text-center rounded-2xl border border-dashed border-white/10 bg-black/20 flex flex-col items-center justify-center space-y-4 font-mono">
            <div className="p-4 rounded-2xl bg-white/5 border border-white/10 text-slate-400">
              <Target className="w-10 h-10 text-cyber-cyan" />
            </div>
            <div className="space-y-1">
              <h4 className="text-base font-bold text-slate-200">No scans yet</h4>
              <p className="text-xs text-slate-400 max-w-md font-sans">
                No autonomous penetration tests found for this operator account. Launch your first security audit to inspect targets and populate the real-time telemetry queue.
              </p>
            </div>
            <button
              onClick={() => {
                soundEngine.playClick();
                setModalOpen(true);
              }}
              className="px-5 py-2.5 rounded-xl bg-cyber-cyan text-slate-950 font-mono font-bold text-xs uppercase tracking-wider hover:bg-[#00d8e6] transition-colors flex items-center space-x-2 cursor-pointer shadow-glow-cyan"
            >
              <Plus className="w-4 h-4" />
              <span>Launch First Pentest</span>
            </button>
          </div>
        ) : (
          /* SUCCESS STATE - REAL SCANS TABLE */
          <div className="overflow-x-auto rounded-2xl border border-white/10 bg-black/20">
            <table className="w-full text-left text-xs font-sans">
              <thead className="bg-white/[0.03] text-slate-400 border-b border-white/10 uppercase font-mono text-[10px]">
                <tr>
                  <th className="px-4 py-3.5">Scan ID</th>
                  <th className="px-4 py-3.5">Target Scope</th>
                  <th className="px-4 py-3.5">Profile</th>
                  <th className="px-4 py-3.5">Status</th>
                  <th className="px-4 py-3.5">Vulnerabilities</th>
                  <th className="px-4 py-3.5">Security Score</th>
                  <th className="px-4 py-3.5">Timestamp</th>
                  <th className="px-4 py-3.5 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5 text-slate-300 text-xs font-mono">
                {scansList.map((scan) => {
                  const isRunning = scan.status?.toLowerCase() === 'running';
                  const isCompleted = scan.status?.toLowerCase() === 'completed';
                  const isFailed = scan.status?.toLowerCase() === 'failed';

                  return (
                    <tr key={scan.id} className="hover:bg-white/[0.02] transition-colors">
                      <td className="px-4 py-4 font-bold text-cyber-cyan">SCN-{scan.id}</td>
                      <td className="px-4 py-4 text-slate-200 font-mono max-w-[200px] truncate" title={scan.target_url}>
                        {scan.target_url}
                      </td>
                      <td className="px-4 py-4">
                        <span className="px-2 py-0.5 rounded-md bg-white/5 border border-white/10 text-[10px] uppercase font-bold text-slate-300">
                          {scan.scan_type}
                        </span>
                      </td>
                      <td className="px-4 py-4">
                        {isRunning && (
                          <span className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-full bg-cyber-cyan/10 text-cyber-cyan border border-cyber-cyan/30 font-semibold text-[10px]">
                            <span className="w-1.5 h-1.5 rounded-full bg-cyber-cyan animate-ping" />
                            <span>IN PROGRESS</span>
                          </span>
                        )}
                        {isCompleted && (
                          <span className="inline-flex items-center space-x-1 px-2.5 py-1 rounded-full bg-cyber-emerald/10 text-cyber-emerald border border-cyber-emerald/30 font-semibold text-[10px]">
                            <CheckCircle2 className="w-3 h-3" />
                            <span>COMPLETED</span>
                          </span>
                        )}
                        {isFailed && (
                          <span className="inline-flex items-center space-x-1 px-2.5 py-1 rounded-full bg-cyber-rose/10 text-cyber-rose border border-cyber-rose/30 font-semibold text-[10px]">
                            <AlertCircle className="w-3 h-3" />
                            <span>FAILED</span>
                          </span>
                        )}
                        {!isRunning && !isCompleted && !isFailed && (
                          <span className="inline-flex items-center px-2 py-0.5 rounded-full bg-white/5 text-slate-400 text-[10px]">
                            {scan.status}
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-4">
                        <span className="font-bold text-slate-100">
                          {scan.vulnerabilities_count ?? 0} Total
                        </span>
                        {(scan.critical_count ?? 0) > 0 && (
                          <span className="ml-2 text-cyber-rose font-bold">
                            ({scan.critical_count} Crit)
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-4">
                        {scan.security_score !== null && scan.security_score !== undefined ? (
                          <span className="text-cyber-cyan font-bold">
                            {scan.security_score}/100{' '}
                            <span className="text-[10px] text-slate-400 font-normal">
                              ({scan.security_grade || 'A'})
                            </span>
                          </span>
                        ) : (
                          <span className="text-slate-500 font-mono text-[10px]">
                            {isRunning ? 'Auditing...' : '--'}
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-4 text-slate-400">
                        {new Date(scan.created_at).toLocaleString([], {
                          dateStyle: 'short',
                          timeStyle: 'short',
                        })}
                      </td>
                      <td className="px-4 py-4 text-right">
                        <div className="flex items-center justify-end space-x-2">
                          <button
                            onClick={() => {
                              soundEngine.playClick();
                              window.location.href = '/reports';
                            }}
                            className="text-cyber-cyan hover:underline font-bold text-xs flex items-center space-x-1"
                            title="Inspect generated security report"
                          >
                            <FileText className="w-3.5 h-3.5" />
                            <span>Report →</span>
                          </button>

                          <button
                            onClick={() => handleDeleteScan(scan.id)}
                            disabled={deletingId === scan.id}
                            className="p-1.5 rounded-lg text-slate-500 hover:text-cyber-rose hover:bg-cyber-rose/10 transition-colors"
                            title="Delete scan record"
                          >
                            {deletingId === scan.id ? (
                              <Loader2 className="w-3.5 h-3.5 animate-spin text-cyber-rose" />
                            ) : (
                              <Trash2 className="w-3.5 h-3.5" />
                            )}
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Modal for Launching Scan */}
      {modalOpen && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4">
          <div className="w-full max-w-lg glass-card p-6 rounded-3xl border border-cyber-cyan/40 shadow-2xl space-y-5 relative">
            <div className="flex items-center justify-between border-b border-white/10 pb-3 font-mono">
              <div className="flex items-center space-x-2">
                <Target className="w-5 h-5 text-cyber-cyan" />
                <h3 className="font-bold font-display text-slate-100 text-base">Launch Pentest Agent</h3>
              </div>
              <button
                onClick={() => setModalOpen(false)}
                className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-white/5"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleLaunchScan} className="space-y-4 font-mono text-xs">
              <div className="space-y-1.5">
                <label className="block text-slate-300 uppercase font-semibold">
                  Target Scope Endpoint / Domain
                </label>
                <input
                  type="url"
                  required
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  placeholder="https://api.target-scope.com"
                  className="w-full px-4 py-3 rounded-xl bg-white/[0.03] border border-white/10 text-slate-100 focus:border-cyber-cyan outline-none font-mono"
                />
              </div>

              <div className="space-y-1.5">
                <label className="block text-slate-300 uppercase font-semibold">
                  Scan Intensity Profile
                </label>
                <select
                  value={scanType}
                  onChange={(e) => setScanType(e.target.value)}
                  className="w-full px-4 py-3 rounded-xl bg-[#0b101d] border border-white/10 text-slate-100 focus:border-cyber-cyan outline-none font-mono"
                >
                  <option value="full">Full Automated Pentest (Recon + OWASP + Exploit)</option>
                  <option value="quick">Quick Port & Vulnerability Scan</option>
                  <option value="api">API Security & BOLA Audit</option>
                </select>
              </div>

              {/* Operator Authorization Attestation */}
              <div className="p-3 rounded-xl bg-cyber-cyan/5 border border-cyber-cyan/30 flex items-start space-x-2.5">
                <input
                  type="checkbox"
                  id="dashAuthConfirm"
                  checked={authConfirmed}
                  onChange={(e) => setAuthConfirmed(e.target.checked)}
                  className="mt-0.5 h-3.5 w-3.5 rounded border-cyber-cyan/40 bg-black/40 text-cyber-cyan focus:ring-cyber-cyan cursor-pointer"
                />
                <label htmlFor="dashAuthConfirm" className="text-[11px] text-slate-300 leading-snug cursor-pointer select-none">
                  <span className="text-cyber-cyan font-bold block mb-0.5 font-mono">AUTHORIZATION CONFIRMATION</span>
                  I confirm explicit authorization to perform automated security assessments against this target domain.
                </label>
              </div>

              <div className="pt-2 flex justify-end space-x-3">
                <button
                  type="button"
                  onClick={() => setModalOpen(false)}
                  className="px-4 py-2.5 rounded-xl bg-white/5 text-slate-300 hover:bg-white/10"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isLaunching || !authConfirmed}
                  className="px-5 py-2.5 rounded-xl bg-cyber-cyan text-slate-950 font-bold uppercase tracking-wider shadow-glow-cyan flex items-center space-x-2 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {isLaunching ? (
                    <>
                      <Loader2 className="w-3.5 h-3.5 animate-spin" />
                      <span>Launching...</span>
                    </>
                  ) : (
                    <>
                      <Play className="w-3.5 h-3.5 fill-current" />
                      <span>Start Pentest</span>
                    </>
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
