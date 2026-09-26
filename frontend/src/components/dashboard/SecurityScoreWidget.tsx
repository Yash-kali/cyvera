import React from 'react';
import { ShieldCheck, TrendingUp, Award, Zap } from 'lucide-react';
import { motion } from 'framer-motion';

interface SecurityScoreWidgetProps {
  score?: number | null;
  grade?: string | null;
  riskLevel?: string | null;
}

export const SecurityScoreWidget: React.FC<SecurityScoreWidgetProps> = ({
  score = null,
  grade = null,
  riskLevel = null,
}) => {
  const hasScore = score !== null && score !== undefined;
  const strokeDashoffset = hasScore ? 283 - (283 * score) / 100 : 283;

  return (
    <motion.div
      whileHover={{ y: -4 }}
      className="glass-card p-6 rounded-3xl border border-white/10 flex flex-col justify-between space-y-4 relative overflow-hidden bg-gradient-to-b from-white/[0.04] to-transparent"
    >
      <div className="flex items-center justify-between font-mono">
        <div className="flex items-center space-x-2">
          <div className="p-2 rounded-xl bg-cyber-emerald/10 border border-cyber-emerald/30 text-cyber-emerald shadow-glow-emerald">
            <ShieldCheck className="w-4 h-4" />
          </div>
          <h3 className="font-bold text-slate-100 font-display text-sm">Security Posture Score</h3>
        </div>
        <span className={`px-2.5 py-0.5 text-[10px] border rounded-full font-bold ${
          hasScore
            ? 'bg-cyber-emerald/20 text-cyber-emerald border-cyber-emerald/40'
            : 'bg-white/5 text-slate-400 border-white/10'
        }`}>
          {grade ? (grade.startsWith('GRADE') ? grade : `GRADE ${grade}`) : 'AWAITING'}
        </span>
      </div>

      <div className="flex items-center justify-between gap-4 py-2">
        {/* SVG Circular Score Gauge */}
        <div className="relative w-28 h-28 flex items-center justify-center flex-shrink-0">
          <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
            <circle
              cx="50"
              cy="50"
              r="45"
              className="text-white/10"
              strokeWidth="8"
              stroke="currentColor"
              fill="transparent"
            />
            <circle
              cx="50"
              cy="50"
              r="45"
              className="text-cyber-emerald transition-all duration-1000 ease-out"
              strokeWidth="8"
              strokeDasharray="283"
              strokeDashoffset={strokeDashoffset}
              strokeLinecap="round"
              stroke="currentColor"
              fill="transparent"
            />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center font-mono">
            <span className="text-2xl font-bold font-display text-slate-100 tracking-tight">
              {hasScore ? score : '--'}
            </span>
            <span className="text-[9px] text-slate-400 uppercase font-sans">
              {hasScore ? 'out of 100' : 'NO DATA'}
            </span>
          </div>
        </div>

        <div className="space-y-2 flex-1 font-mono text-xs">
          <div className="p-3 rounded-2xl bg-black/40 border border-white/10 space-y-1">
            <div className="text-[10px] text-slate-400 uppercase">Evaluated Risk Tier</div>
            <div className="text-sm font-bold text-cyber-cyan">
              {riskLevel ? `${riskLevel} Risk Exposure` : 'Standby'}
            </div>
          </div>
          <div className="flex items-center space-x-1.5 text-[11px] text-cyber-emerald font-bold">
            <TrendingUp className="w-3.5 h-3.5" />
            <span>+4.2% Posture Improvement</span>
          </div>
        </div>
      </div>

      <div className="w-full bg-white/5 rounded-full h-2 overflow-hidden border border-white/10">
        <div
          className="bg-gradient-to-r from-cyber-cyan via-cyber-purple to-cyber-emerald h-full rounded-full transition-all duration-1000"
          style={{ width: `${score}%` }}
        />
      </div>
    </motion.div>
  );
};
