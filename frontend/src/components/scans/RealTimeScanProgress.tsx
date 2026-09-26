import React from 'react';
import { useScanProgress } from '../../hooks/useScanProgress';
import { LiveProgressBar } from './LiveProgressBar';
import { TerminalActivityFeed } from './TerminalActivityFeed';
import { RefreshCw, Activity, ShieldAlert, Globe, CheckCircle2, Clock, XCircle, AlertTriangle, Layers } from 'lucide-react';

interface RealTimeScanProgressProps {
  scanId: number;
}

export const RealTimeScanProgress: React.FC<RealTimeScanProgressProps> = ({ scanId }) => {
  const {
    progress,
    state,
    stage,
    message,
    status,
    logs,
    isConnected,
    isPolling,
    error,
    requestsUsed,
    requestsRemaining,
    requestsTotal,
    discoveredAssets,
    activeFindings,
    score,
    heartbeatSecondsAgo,
    isWorkerAlive,
    timeline,
    reconnect,
  } = useScanProgress(scanId);

  const uniqueFindingsCount = React.useMemo(() => {
    return new Set(activeFindings.map((f) => f.title)).size;
  }, [activeFindings]);

  const handleInstantDownload = async () => {
    try {
      const { generateReportApi, downloadReportByIdApi } = await import('../../api/reports');
      const rep = await generateReportApi(scanId, 'standard');
      await downloadReportByIdApi(rep.id, rep.report_type);
    } catch (err) {
      console.error('Instant PDF download error:', err);
    }
  };

  const handleCancelScan = async () => {
    try {
      const { cancelScanApi } = await import('../../api/scans');
      await cancelScanApi(scanId);
    } catch (err) {
      console.error('Failed to cancel scan:', err);
    }
  };

  return (
    <div className="space-y-6 font-sans">
      {/* 1. Live Progress Bar Component with Budget & Heartbeat */}
      <LiveProgressBar
        progress={progress}
        stage={stage}
        message={message}
        status={status}
        isConnected={isConnected}
        isPolling={isPolling}
        requestsUsed={requestsUsed}
        requestsRemaining={requestsRemaining}
        requestsTotal={requestsTotal}
        heartbeatSecondsAgo={heartbeatSecondsAgo}
        isWorkerAlive={isWorkerAlive}
        onDownloadReport={handleInstantDownload}
        onCancelScan={handleCancelScan}
      />

      {/* 2. Chronological Event Timeline */}
      <div className="glass-card p-6 rounded-3xl border border-white/10 space-y-4 font-mono">
        <div className="flex items-center justify-between border-b border-white/10 pb-3">
          <div className="flex items-center space-x-2 text-slate-300 font-bold text-xs uppercase tracking-wider">
            <Clock className="w-4 h-4 text-cyber-cyan" />
            <span>Execution Timeline</span>
          </div>
          <span className="text-[11px] text-slate-400">
            Current Stage: <strong className="text-cyber-cyan">{state}</strong>
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-2">
          {timeline.map((step) => {
            const isCompleted = step.status === 'completed';
            const isInProgress = step.status === 'in_progress';
            const isFailed = step.status === 'failed';
            const isCancelled = step.status === 'cancelled';

            return (
              <div
                key={step.key}
                className={`p-3 rounded-2xl border text-xs flex flex-col justify-between transition-all ${
                  isCompleted
                    ? 'bg-cyber-emerald/10 border-cyber-emerald/30 text-cyber-emerald'
                    : isInProgress
                    ? 'bg-cyber-cyan/15 border-cyber-cyan/40 text-cyber-cyan shadow-glow-cyan/20'
                    : isFailed
                    ? 'bg-cyber-rose/10 border-cyber-rose/30 text-cyber-rose'
                    : isCancelled
                    ? 'bg-cyber-amber/10 border-cyber-amber/30 text-cyber-amber'
                    : 'bg-white/[0.02] border-white/5 text-slate-500'
                }`}
              >
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-[10px] uppercase font-bold truncate max-w-[80%]">
                    {step.title}
                  </span>
                  {isCompleted && <CheckCircle2 className="w-3.5 h-3.5 text-cyber-emerald shrink-0" />}
                  {isInProgress && <RefreshCw className="w-3.5 h-3.5 text-cyber-cyan animate-spin shrink-0" />}
                  {isFailed && <AlertTriangle className="w-3.5 h-3.5 text-cyber-rose shrink-0" />}
                  {isCancelled && <XCircle className="w-3.5 h-3.5 text-cyber-amber shrink-0" />}
                </div>
                <div className="text-[9px] text-slate-400">
                  {isCompleted ? 'Finished' : isInProgress ? 'In Progress...' : 'Queued'}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* 3. Live Telemetry Panels: Live Discovered Assets & Active Findings Stream */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Discovered In-Scope Assets Live Stream */}
        <div className="glass-card p-6 rounded-3xl border border-white/10 space-y-4 font-mono text-xs">
          <div className="flex items-center justify-between border-b border-white/10 pb-3">
            <div className="flex items-center space-x-2 text-slate-200 font-bold">
              <Globe className="w-4 h-4 text-cyber-cyan" />
              <span>Live Discovered Assets ({discoveredAssets.length})</span>
            </div>
            <span className="text-[10px] text-slate-400">Strict In-Scope Only</span>
          </div>

          {discoveredAssets.length === 0 ? (
            <div className="py-8 text-center text-slate-500 text-xs">
              Waiting for discovery engine asset stream...
            </div>
          ) : (
            <div className="max-h-48 overflow-y-auto space-y-2 pr-1">
              {discoveredAssets.slice(-8).map((asset, idx) => (
                <div
                  key={idx}
                  className="p-2 rounded-xl bg-white/[0.02] border border-white/5 flex items-center justify-between hover:bg-white/[0.04] transition-colors"
                >
                  <div className="flex items-center space-x-2 truncate max-w-[75%]">
                    <span className="px-1.5 py-0.5 rounded text-[9px] bg-cyber-purple/20 text-cyber-purple font-bold">
                      {asset.http_method || 'GET'}
                    </span>
                    <span className="truncate text-slate-300">{asset.url}</span>
                  </div>
                  <span className="text-[10px] text-slate-500 font-mono">
                    {asset.status_code ? `HTTP ${asset.status_code}` : 'OBSERVED'}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Live Verified Findings Stream */}
        <div className="glass-card p-6 rounded-3xl border border-white/10 space-y-4 font-mono text-xs">
          <div className="flex items-center justify-between border-b border-white/10 pb-3">
            <div className="flex items-center space-x-2 text-slate-200 font-bold">
              <ShieldAlert className="w-4 h-4 text-cyber-rose" />
              <span>{uniqueFindingsCount > 0 ? `${uniqueFindingsCount} Verified Findings` : 'Verified Findings'}</span>
              {activeFindings.length > 0 && (
                <span className="text-[10px] text-slate-400 font-normal">
                  ({activeFindings.length} Affected Asset Instances)
                </span>
              )}
            </div>
            {score.score !== null && (
              <span className="text-[11px] font-bold text-cyber-cyan">
                Score: {score.score.toFixed(1)}/100 (Grade {score.grade})
              </span>
            )}
          </div>

          {activeFindings.length === 0 ? (
            <div className="py-8 text-center text-slate-500 text-xs">
              No vulnerabilities identified yet. Probing attack surface...
            </div>
          ) : (
            <div className="max-h-48 overflow-y-auto space-y-2 pr-1">
              {activeFindings.slice(-6).map((finding, idx) => (
                <div
                  key={idx}
                  className="p-2.5 rounded-xl bg-white/[0.02] border border-white/5 flex items-center justify-between hover:bg-white/[0.04] transition-colors"
                >
                  <div className="truncate max-w-[70%]">
                    <div className="text-slate-200 font-bold truncate">{finding.title}</div>
                    <div className="text-[10px] text-slate-500 truncate">{finding.affected_url}</div>
                  </div>
                  <div className="flex items-center space-x-2 shrink-0">
                    <span
                      className={`px-2 py-0.5 rounded-full text-[9px] uppercase font-bold ${
                        finding.severity === 'Critical'
                          ? 'bg-cyber-rose/20 text-cyber-rose border border-cyber-rose/30'
                          : finding.severity === 'High'
                          ? 'bg-cyber-amber/20 text-cyber-amber border border-cyber-amber/30'
                          : finding.severity === 'Low'
                          ? 'bg-cyber-emerald/20 text-cyber-emerald border border-cyber-emerald/30'
                          : 'bg-cyber-cyan/20 text-cyber-cyan border border-cyber-cyan/30'
                      }`}
                    >
                      {finding.severity || 'Medium'}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* 4. Terminal Style Activity Feed */}
      <TerminalActivityFeed logs={logs} scanId={scanId} />

      {/* 5. WebSocket Connection Details Bar */}
      <div className="glass-card p-4 rounded-2xl border border-white/10 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-mono">
        <div className="flex items-center space-x-2 text-slate-400">
          <Activity className="w-4 h-4 text-cyber-cyan" />
          <span>
            Stream Endpoint: <strong className="text-slate-200">/ws/scans/{scanId}</strong>
          </span>
          <span className="text-white/20">•</span>
          <span className="text-slate-400">
            Tenant Isolated: <strong className="text-cyber-emerald">ACTIVE</strong>
          </span>
        </div>

        <div className="flex items-center space-x-3">
          {error && (
            <span className="text-cyber-rose font-bold text-[11px] truncate max-w-[280px]">
              {error}
            </span>
          )}
          <button
            onClick={reconnect}
            className="px-3 py-1.5 rounded-xl bg-white/5 border border-white/10 hover:border-cyber-cyan/40 text-slate-300 hover:text-white flex items-center space-x-1.5 transition-all text-xs cursor-pointer"
          >
            <RefreshCw className={`w-3 h-3 ${!isConnected ? 'animate-spin text-cyber-cyan' : ''}`} />
            <span>Reconnect Stream</span>
          </button>
        </div>
      </div>
    </div>
  );
};
