import React from 'react';
import { motion } from 'framer-motion';
import { Shield, Zap, Sparkles, FileText, CheckCircle2, AlertCircle, RefreshCw, XCircle, Activity, Gauge } from 'lucide-react';

interface LiveProgressBarProps {
  progress: number;
  stage: string;
  message: string;
  status: string;
  isConnected: boolean;
  isPolling: boolean;
  requestsUsed?: number;
  requestsRemaining?: number;
  requestsTotal?: number;
  heartbeatSecondsAgo?: number | null;
  isWorkerAlive?: boolean;
  onDownloadReport?: () => void;
  onCancelScan?: () => void;
}

export const LiveProgressBar: React.FC<LiveProgressBarProps> = ({
  progress,
  stage,
  message,
  status,
  isConnected,
  isPolling,
  requestsUsed = 0,
  requestsRemaining = 150,
  requestsTotal = 150,
  heartbeatSecondsAgo = null,
  isWorkerAlive = false,
  onDownloadReport,
  onCancelScan,
}) => {
  const steps = [
    { label: 'Validation', range: '0–10%', minPct: 10 },
    { label: 'Recon', range: '10–25%', minPct: 25 },
    { label: 'Discovery', range: '25–50%', minPct: 50 },
    { label: 'Testing', range: '50–80%', minPct: 80 },
    { label: 'Scoring', range: '80–88%', minPct: 88 },
    { label: 'Report', range: '88–100%', minPct: 100 },
  ];

  const isCompleted = status === 'Completed' || stage.includes('Completed') || progress >= 100;

  const getStatusBadge = () => {
    if (isCompleted) {
      return (
        <span className="inline-flex items-center space-x-1.5 px-3 py-1 rounded-full bg-cyber-emerald/10 text-cyber-emerald border border-cyber-emerald/30 font-mono text-xs font-bold">
          <CheckCircle2 className="w-3.5 h-3.5" />
          <span>COMPLETED</span>
        </span>
      );
    }
    if (status === 'Cancelled' || stage.includes('Cancelled')) {
      return (
        <span className="inline-flex items-center space-x-1.5 px-3 py-1 rounded-full bg-cyber-rose/10 text-cyber-rose border border-cyber-rose/30 font-mono text-xs font-bold">
          <XCircle className="w-3.5 h-3.5" />
          <span>CANCELLED</span>
        </span>
      );
    }
    if (status === 'Cancelling' || stage.includes('Cancelling')) {
      return (
        <span className="inline-flex items-center space-x-1.5 px-3 py-1 rounded-full bg-cyber-amber/10 text-cyber-amber border border-cyber-amber/30 font-mono text-xs font-bold">
          <RefreshCw className="w-3.5 h-3.5 animate-spin" />
          <span>CANCELLING...</span>
        </span>
      );
    }
    if (status === 'Failed' || stage.includes('Failed')) {
      return (
        <span className="inline-flex items-center space-x-1.5 px-3 py-1 rounded-full bg-cyber-rose/10 text-cyber-rose border border-cyber-rose/30 font-mono text-xs font-bold">
          <AlertCircle className="w-3.5 h-3.5" />
          <span>FAILED</span>
        </span>
      );
    }
    return (
      <span className="inline-flex items-center space-x-1.5 px-3 py-1 rounded-full bg-cyber-cyan/10 text-cyber-cyan border border-cyber-cyan/30 font-mono text-xs font-bold">
        <span className="w-2 h-2 rounded-full bg-cyber-cyan animate-ping" />
        <span>IN PROGRESS ({progress}%)</span>
      </span>
    );
  };

  return (
    <div className="glass-card p-6 rounded-3xl border border-white/10 space-y-6 relative overflow-hidden font-sans">
      {/* Top Header section */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-white/10 pb-4">
        <div>
          <div className="text-[11px] font-mono text-slate-400 uppercase tracking-wider font-semibold flex items-center space-x-2">
            <span>Execution Stage</span>
            <span className="text-white/20">•</span>
            <span className="text-cyber-cyan font-bold">{progress}%</span>
          </div>
          <div className="text-lg font-bold font-display text-slate-100 flex items-center space-x-2 pt-0.5">
            <span>{stage}</span>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          {getStatusBadge()}

          {/* Abort Scan Button for in-flight scans */}
          {(status === 'Running' || status === 'Pending') && onCancelScan && (
            <button
              onClick={onCancelScan}
              className="px-3 py-1 rounded-full bg-cyber-rose/10 text-cyber-rose hover:bg-cyber-rose/25 border border-cyber-rose/30 font-mono font-bold text-xs transition-all cursor-pointer flex items-center space-x-1"
              title="Abort in-flight scan"
            >
              <XCircle className="w-3.5 h-3.5" />
              <span>Abort Scan</span>
            </button>
          )}

          {/* Immediate Download Button Right After Scan Completion */}
          {isCompleted && onDownloadReport && (
            <motion.button
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              onClick={onDownloadReport}
              className="px-4 py-1.5 rounded-full bg-cyber-cyan text-slate-950 hover:bg-[#00d8e6] font-mono font-bold text-xs shadow-glow-cyan flex items-center space-x-1.5 transition-all cursor-pointer"
            >
              <FileText className="w-3.5 h-3.5" />
              <span>Download PDF Report</span>
            </motion.button>
          )}

          {/* Worker Vitality Badge */}
          <span
            className={`px-2.5 py-1 rounded-full text-[10px] font-mono border flex items-center space-x-1.5 ${
              isWorkerAlive
                ? 'bg-cyber-emerald/10 text-cyber-emerald border-cyber-emerald/30'
                : isConnected
                ? 'bg-cyber-cyan/10 text-cyber-cyan border-cyber-cyan/30'
                : isPolling
                ? 'bg-cyber-amber/10 text-cyber-amber border-cyber-amber/30'
                : 'bg-white/5 text-slate-400 border-white/10'
            }`}
          >
            <span
              className={`w-1.5 h-1.5 rounded-full ${
                isWorkerAlive
                  ? 'bg-cyber-emerald animate-pulse'
                  : isConnected
                  ? 'bg-cyber-cyan'
                  : 'bg-cyber-amber'
              }`}
            />
            <span>
              {isWorkerAlive
                ? `WORKER ACTIVE (${heartbeatSecondsAgo !== null ? `${heartbeatSecondsAgo}s ago` : 'now'})`
                : isConnected
                ? 'CONNECTED'
                : isPolling
                ? 'POLLING FALLBACK'
                : 'OFFLINE'}
            </span>
          </span>
        </div>
      </div>

      {/* Progress Bar with Gradient and Glow */}
      <div className="space-y-2">
        <div className="flex justify-between items-center text-xs font-mono">
          <span className="text-slate-300 truncate max-w-[70%]">{message}</span>
          <div className="flex items-center space-x-3 text-right">
            <span className="text-slate-400 text-[11px] flex items-center space-x-1">
              <Gauge className="w-3 h-3 text-cyber-purple" />
              <span>Requests: <strong>{requestsUsed}</strong> / {requestsTotal}</span>
            </span>
            <span className="text-cyber-cyan font-bold text-sm">{progress}%</span>
          </div>
        </div>

        <div className="relative w-full h-3.5 bg-black/40 rounded-full border border-white/10 p-0.5 overflow-hidden">
          <motion.div
            className="h-full rounded-full bg-gradient-to-r from-cyber-cyan via-cyber-purple to-cyber-emerald shadow-glow-cyan"
            initial={{ width: '0%' }}
            animate={{ width: `${progress}%` }}
            transition={{ duration: 0.5, ease: 'easeOut' }}
          />
        </div>
      </div>

      {/* Stage Ranges Checkpoints */}
      <div className="grid grid-cols-2 sm:grid-cols-6 gap-2 pt-1 font-mono">
        {steps.map((step, idx) => {
          const isDone = progress >= step.minPct;
          const isCurrent = progress < step.minPct && (idx === 0 || progress >= steps[idx - 1].minPct);
          return (
            <div
              key={step.label}
              className={`p-2 rounded-xl border text-center transition-all ${
                isDone
                  ? 'bg-cyber-emerald/10 border-cyber-emerald/30 text-cyber-emerald font-semibold'
                  : isCurrent
                  ? 'bg-cyber-cyan/15 border-cyber-cyan/40 text-cyber-cyan font-bold shadow-glow-cyan/20'
                  : 'bg-white/[0.02] border-white/5 text-slate-500'
              }`}
            >
              <div className="text-[10px] uppercase truncate">{step.label}</div>
              <div className="text-[9px] text-slate-400">{step.range}</div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
