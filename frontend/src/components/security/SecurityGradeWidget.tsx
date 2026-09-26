import React from 'react';
import { Award, ShieldCheck, AlertCircle, Sparkles } from 'lucide-react';

interface SecurityGradeWidgetProps {
  score: number;
  grade: string;
  riskLevel: string;
}

export const SecurityGradeWidget: React.FC<SecurityGradeWidgetProps> = ({
  score,
  grade,
  riskLevel,
}) => {
  const getGradeMeta = (g: string) => {
    switch (g.toUpperCase()) {
      case 'A':
        return {
          label: 'EXCELLENT SECURITY POSTURE',
          desc: 'Target demonstrates strong baseline defense with minimal risk exposure.',
          color: 'text-cyber-cyan',
          bg: 'bg-cyber-cyan/10 border-cyber-cyan/30',
        };
      case 'B':
        return {
          label: 'GOOD baseline DEFENSE',
          desc: 'Target meets baseline compliance with minor security configuration fixes required.',
          color: 'text-cyber-emerald',
          bg: 'bg-cyber-emerald/10 border-cyber-emerald/30',
        };
      case 'C':
        return {
          label: 'MODERATE EXPOSURE',
          desc: 'Multiple medium vulnerabilities or header deficiencies detected.',
          color: 'text-cyber-amber',
          bg: 'bg-cyber-amber/10 border-cyber-amber/30',
        };
      default:
        return {
          label: 'HIGH RISK POSTURE',
          desc: 'Critical/High severity vulnerabilities require immediate mitigation.',
          color: 'text-cyber-rose',
          bg: 'bg-cyber-rose/10 border-cyber-rose/30',
        };
    }
  };

  const meta = getGradeMeta(grade);

  return (
    <div className="glass-card p-6 rounded-3xl border border-white/10 space-y-4 font-sans flex flex-col justify-between">
      <div className="space-y-3">
        <div className="flex items-center justify-between border-b border-white/10 pb-3 font-mono">
          <div className="flex items-center space-x-2 text-xs font-bold text-slate-100">
            <Award className="w-4 h-4 text-cyber-cyan" />
            <span>Security Grade Assessment</span>
          </div>
          <span className={`px-3 py-1 rounded-full text-xs font-bold border ${meta.bg} ${meta.color}`}>
            GRADE {grade}
          </span>
        </div>

        <div className="space-y-1">
          <div className={`text-base font-bold font-display uppercase tracking-wide ${meta.color}`}>
            {meta.label}
          </div>
          <p className="text-xs text-slate-400 font-sans leading-relaxed">
            {meta.desc}
          </p>
        </div>
      </div>

      <div className="pt-3 border-t border-white/10 flex items-center justify-between font-mono text-xs">
        <span className="text-slate-400">Risk Assessment Level:</span>
        <span className={`font-bold px-2.5 py-0.5 rounded-full border ${meta.bg} ${meta.color}`}>
          {riskLevel} Risk
        </span>
      </div>
    </div>
  );
};
