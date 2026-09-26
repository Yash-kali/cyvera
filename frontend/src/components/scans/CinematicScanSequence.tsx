import React from 'react';
import { Search, Radio, ShieldAlert, Sparkles, FileText } from 'lucide-react';

interface CinematicScanSequenceProps {
  currentStage?: string;
  progress?: number;
}

export const CinematicScanSequence: React.FC<CinematicScanSequenceProps> = ({
  currentStage = 'Security Pipeline Standby — Ready for Target Scan',
  progress = 0,
}) => {
  const stages = [
    { name: 'Target Validation', icon: Search, threshold: 10 },
    { name: 'Reconnaissance', icon: Search, threshold: 25 },
    { name: 'Surface Discovery', icon: Radio, threshold: 50 },
    { name: 'Security Testing', icon: ShieldAlert, threshold: 80 },
    { name: 'Scoring & Report', icon: FileText, threshold: 100 },
  ];

  return (
    <div className="glass-card p-6 rounded-3xl border border-cyber-cyan/30 space-y-6 font-sans bg-gradient-to-r from-cyber-cyan/5 via-transparent to-cyber-purple/5 relative overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between font-mono border-b border-white/10 pb-3">
        <div className="flex items-center space-x-2">
          <div className="p-2 rounded-xl bg-cyber-cyan/20 border border-cyber-cyan/40 text-cyber-cyan shadow-glow-cyan">
            <Radio className="w-4 h-4 animate-pulse" />
          </div>
          <div>
            <h3 className="font-bold text-slate-100 font-display text-sm">Cinematic Scan Pipeline Sequence</h3>
            <p className="text-[10px] text-slate-400 font-mono">Autonomous Execution Pipeline Matrix</p>
          </div>
        </div>

        <span className="px-3 py-1 text-xs bg-cyber-cyan/20 text-cyber-cyan border border-cyber-cyan/40 rounded-full font-bold font-mono">
          {progress}% COMPLETED
        </span>
      </div>

      {/* 5-Stage Energy Pipeline Visualization */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-3 py-2 font-mono text-xs">
        {stages.map((stg, idx) => {
          const Icon = stg.icon;
          const isActive = progress >= stg.threshold - 15 && progress < stg.threshold + 5;
          const isPassed = progress >= stg.threshold;

          return (
            <div
              key={stg.name}
              className={`p-4 rounded-2xl border transition-all flex flex-col items-center justify-center text-center space-y-2 relative overflow-hidden ${
                isActive
                  ? 'bg-cyber-cyan/20 border-cyber-cyan text-cyber-cyan shadow-glow-cyan/40'
                  : isPassed
                  ? 'bg-cyber-emerald/10 border-cyber-emerald/40 text-cyber-emerald'
                  : 'bg-white/[0.02] border-white/10 text-slate-500'
              }`}
            >
              <div
                className={`p-2.5 rounded-xl border ${
                  isActive
                    ? 'bg-cyber-cyan/30 border-cyber-cyan shadow-glow-cyan animate-pulse'
                    : isPassed
                    ? 'bg-cyber-emerald/20 border-cyber-emerald/40'
                    : 'bg-white/5 border-white/10'
                }`}
              >
                <Icon className="w-5 h-5" />
              </div>
              <span className="font-bold text-xs font-display truncate w-full">{stg.name}</span>
              <span className="text-[9px] uppercase font-mono tracking-wider opacity-80">
                {isPassed ? 'DONE' : isActive ? 'EXECUTING' : 'QUEUED'}
              </span>
            </div>
          );
        })}
      </div>

      {/* Animated Flowing Energy Progress Bar */}
      <div className="w-full bg-white/5 rounded-full h-3 overflow-hidden border border-white/10 p-0.5 relative">
        <div
          className="bg-gradient-to-r from-cyber-cyan via-cyber-purple to-cyber-emerald h-full rounded-full transition-all duration-700 relative overflow-hidden"
          style={{ width: `${progress}%` }}
        >
          <div className="absolute inset-0 bg-white/30 animate-pulse" />
        </div>
      </div>
    </div>
  );
};
