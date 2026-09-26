import React, { useRef, useEffect, useState } from 'react';
import { Terminal, Copy, Check, Trash2, ArrowDown } from 'lucide-react';
import { LogEntry } from '../../hooks/useScanProgress';

interface TerminalActivityFeedProps {
  logs: LogEntry[];
  scanId?: number;
}

export const TerminalActivityFeed: React.FC<TerminalActivityFeedProps> = ({ logs, scanId }) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState<boolean>(true);
  const [copied, setCopied] = useState<boolean>(false);

  useEffect(() => {
    if (autoScroll && containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [logs, autoScroll]);

  const handleCopy = () => {
    const text = logs.map((l) => `[${l.timestamp}] [${l.stage}] ${l.message}`).join('\n');
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getBadgeStyle = (level: LogEntry['level']) => {
    switch (level) {
      case 'recon':
        return 'text-cyber-cyan bg-cyber-cyan/10 border-cyber-cyan/30';
      case 'vuln':
        return 'text-cyber-amber bg-cyber-amber/10 border-cyber-amber/30';
      case 'ai':
        return 'text-cyber-purple bg-cyber-purple/10 border-cyber-purple/30';
      case 'report':
        return 'text-blue-400 bg-blue-500/10 border-blue-500/30';
      case 'success':
        return 'text-cyber-emerald bg-cyber-emerald/10 border-cyber-emerald/30';
      case 'error':
        return 'text-cyber-rose bg-cyber-rose/10 border-cyber-rose/30';
      default:
        return 'text-slate-400 bg-white/5 border-white/10';
    }
  };

  return (
    <div className="glass-card p-6 rounded-3xl border border-white/10 space-y-4 font-sans">
      {/* Terminal Window Top Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-white/10 pb-3">
        <div className="flex items-center space-x-3 font-mono">
          <div className="flex space-x-1.5">
            <span className="w-3 h-3 rounded-full bg-cyber-rose/80 inline-block" />
            <span className="w-3 h-3 rounded-full bg-cyber-amber/80 inline-block" />
            <span className="w-3 h-3 rounded-full bg-cyber-emerald/80 inline-block" />
          </div>
          <div className="flex items-center space-x-2 text-slate-200 font-bold text-sm">
            <Terminal className="w-4 h-4 text-cyber-cyan" />
            <span>Scan Activity stdout Stream {scanId ? `#${scanId}` : ''}</span>
          </div>
        </div>

        <div className="flex items-center space-x-2 text-xs font-mono">
          <button
            onClick={() => setAutoScroll(!autoScroll)}
            className={`px-3 py-1 rounded-xl border flex items-center space-x-1 transition-all ${
              autoScroll
                ? 'bg-cyber-cyan/10 border-cyber-cyan/40 text-cyber-cyan font-semibold'
                : 'bg-white/5 border-white/10 text-slate-400'
            }`}
          >
            <ArrowDown className="w-3 h-3" />
            <span>Auto-scroll</span>
          </button>

          <button
            onClick={handleCopy}
            disabled={logs.length === 0}
            className="px-3 py-1 rounded-xl bg-white/5 border border-white/10 hover:border-white/20 text-slate-300 hover:text-white flex items-center space-x-1 transition-all disabled:opacity-40"
          >
            {copied ? <Check className="w-3 h-3 text-cyber-emerald" /> : <Copy className="w-3 h-3" />}
            <span>{copied ? 'Copied' : 'Copy'}</span>
          </button>
        </div>
      </div>

      {/* Terminal stdout Container */}
      <div
        ref={containerRef}
        className="bg-[#05070a] p-5 rounded-2xl border border-white/10 font-mono text-xs text-slate-300 space-y-2.5 min-h-[240px] max-h-[360px] overflow-y-auto"
      >
        {logs.length === 0 ? (
          <div className="text-slate-600 italic py-8 text-center">
            Initializing scan stream & listening for WebSocket broadcasts...
          </div>
        ) : (
          logs.map((log) => (
            <div key={log.id} className="flex items-start space-x-2.5 group">
              <span className="text-slate-600 select-none text-[11px] min-w-[65px] font-light">
                {log.timestamp}
              </span>
              <span className="text-slate-600 select-none">&gt;</span>
              <span className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold border ${getBadgeStyle(log.level)}`}>
                {log.stage}
              </span>
              <span className="flex-1 text-slate-200 leading-relaxed font-sans text-xs">
                {log.message}
              </span>
            </div>
          ))
        )}
      </div>
    </div>
  );
};
