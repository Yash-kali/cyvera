import React from 'react';
import { Sparkles, ChevronRight } from 'lucide-react';
import { motion } from 'framer-motion';
import { Finding } from '../../api/findings';

interface AiRecommendationsWidgetProps {
  topFinding?: Finding | null;
}

export const AiRecommendationsWidget: React.FC<AiRecommendationsWidgetProps> = ({ topFinding }) => {
  const title = topFinding
    ? `Prioritize ${topFinding.severity} Remediation: ${topFinding.title}`
    : 'Autonomous Threat Advisory: Posture Nominal';

  const advisoryText = topFinding
    ? (topFinding.remediation_guidance || topFinding.description)
    : 'All monitored target scopes report nominal posture. No critical or high-risk vulnerability anomalies are currently open for remediation. Continuous autonomous monitoring active.';

  return (
    <motion.div
      whileHover={{ y: -2 }}
      className="glass-card p-6 rounded-3xl border border-cyber-purple/30 bg-gradient-to-r from-cyber-purple/10 via-transparent to-cyber-cyan/10 flex flex-col md:flex-row items-start md:items-center justify-between gap-6 relative overflow-hidden font-sans"
    >
      <div className="space-y-2 max-w-3xl">
        <div className="inline-flex items-center space-x-2 text-cyber-purple text-xs font-mono">
          <Sparkles className="w-4 h-4 animate-pulse" />
          <span className="font-bold uppercase tracking-wider">AI Threat Advisor</span>
        </div>
        <h4 className="text-lg font-bold font-display text-slate-100">
          {title}
        </h4>
        <p className="text-slate-300 text-xs sm:text-sm font-sans leading-relaxed line-clamp-3">
          {advisoryText}
        </p>
      </div>

      <button
        onClick={() => (window.location.href = '/findings')}
        className="px-5 py-3 rounded-2xl bg-cyber-purple hover:bg-cyber-purple/90 text-white font-mono font-bold text-xs uppercase tracking-wider shadow-glow-purple flex items-center space-x-2 flex-shrink-0 cursor-pointer"
      >
        <span>Inspect Findings</span>
        <ChevronRight className="w-4 h-4" />
      </button>
    </motion.div>
  );
};
