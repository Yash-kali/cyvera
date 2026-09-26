import React from 'react';
import { Cpu } from 'lucide-react';
import { motion } from 'framer-motion';

interface SecurityScoreCoreProps {
  score?: number | null;
  grade?: string | null;
  riskLevel?: string | null;
}

export const SecurityScoreCore: React.FC<SecurityScoreCoreProps> = ({
  score = null,
  grade = null,
  riskLevel = null,
}) => {
  const hasScore = score !== null && score !== undefined;
  const displayScore = hasScore ? (Number.isInteger(score) ? score : score.toFixed(1)) : '--';
  const displayGrade = grade ? (grade.startsWith('GRADE') ? grade : `GRADE ${grade}`) : 'AWAITING';
  const displayRisk = riskLevel ? `${riskLevel} Risk` : 'Standby';
  const displayHealth = hasScore ? (score >= 70 ? 'Nominal' : score >= 50 ? 'Degraded' : 'Critical') : 'Standby';

  return (
    <motion.div
      whileHover={{ scale: 1.02 }}
      className="glass-card p-6 rounded-3xl border border-cyber-cyan/30 flex flex-col justify-between space-y-6 relative overflow-hidden bg-gradient-to-b from-cyber-cyan/5 via-transparent to-cyber-purple/5 shadow-glow-cyan/20 font-sans"
    >
      {/* Background Ambient Glow */}
      <div className="absolute inset-0 bg-gradient-radial from-cyber-cyan/10 via-transparent to-transparent opacity-60 pointer-events-none" />

      {/* Header */}
      <div className="flex items-center justify-between font-mono z-10">
        <div className="flex items-center space-x-2">
          <div className="p-2 rounded-xl bg-cyber-cyan/20 border border-cyber-cyan/40 text-cyber-cyan shadow-glow-cyan">
            <Cpu className="w-4 h-4 animate-spin-slow" />
          </div>
          <div>
            <h3 className="font-bold text-slate-100 font-display text-sm">Security Core Reactor</h3>
            <p className="text-[10px] text-slate-400 font-mono">Autonomous Posture Assessment</p>
          </div>
        </div>

        <span className={`px-3 py-1 text-xs border rounded-full font-bold ${
          hasScore
            ? 'bg-cyber-emerald/20 text-cyber-emerald border-cyber-emerald/40 shadow-glow-emerald/20'
            : 'bg-white/5 text-slate-400 border-white/10'
        }`}>
          {displayGrade}
        </span>
      </div>

      {/* Center Holographic Energy Reactor Sphere */}
      <div className="relative h-48 w-full flex items-center justify-center z-10">
        {/* Outer Rotating Energy Ring 1 */}
        <div className="absolute w-44 h-44 rounded-full border-2 border-dashed border-cyber-cyan/40 animate-spin-slow" />

        {/* Counter-Rotating Inner Energy Ring 2 */}
        <div className="absolute w-36 h-36 rounded-full border-2 border-dotted border-cyber-purple/60 animate-spin" style={{ animationDirection: 'reverse', animationDuration: '16s' }} />

        {/* Orbiting Particle Dots */}
        <div className="absolute w-40 h-40 rounded-full animate-spin-slow">
          <span className="absolute top-0 left-1/2 -translate-x-1/2 w-2.5 h-2.5 rounded-full bg-cyber-cyan shadow-glow-cyan" />
          <span className="absolute bottom-0 left-1/2 -translate-x-1/2 w-2.5 h-2.5 rounded-full bg-cyber-emerald shadow-glow-emerald" />
        </div>

        {/* Core Glowing Orb */}
        <div className="w-28 h-28 rounded-full bg-black/80 border-2 border-cyber-cyan/60 flex flex-col items-center justify-center shadow-glow-cyan relative overflow-hidden backdrop-blur-md">
          <div className="absolute inset-0 bg-gradient-radial from-cyber-cyan/30 via-transparent to-transparent animate-pulse" />
          <span className="text-3xl font-bold font-display text-slate-100 tracking-tight z-10">{displayScore}</span>
          <span className="text-[10px] text-cyber-cyan font-mono uppercase font-bold tracking-widest z-10">
            {hasScore ? 'SCORE' : 'NO DATA'}
          </span>
        </div>
      </div>

      {/* Footer Metrics */}
      <div className="grid grid-cols-2 gap-3 text-xs font-mono z-10 border-t border-white/10 pt-3">
        <div className="p-2.5 rounded-2xl bg-black/40 border border-white/10 space-y-0.5">
          <div className="text-[10px] text-slate-400">Risk Profile</div>
          <div className="font-bold text-cyber-cyan">{displayRisk}</div>
        </div>
        <div className="p-2.5 rounded-2xl bg-black/40 border border-white/10 space-y-0.5">
          <div className="text-[10px] text-slate-400">Core Health</div>
          <div className={`font-bold ${hasScore && score >= 70 ? 'text-cyber-emerald' : 'text-slate-400'}`}>
            {displayHealth}
          </div>
        </div>
      </div>
    </motion.div>
  );
};
