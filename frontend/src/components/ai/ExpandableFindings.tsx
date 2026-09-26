import React, { useState } from 'react';
import { Finding } from '../../api/findings';
import { AiAnalysisPanel } from './AiAnalysisPanel';
import { ChevronDown, ChevronUp, Shield, Sparkles, ExternalLink } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

interface ExpandableFindingsProps {
  findings: Finding[];
}

export const ExpandableFindings: React.FC<ExpandableFindingsProps> = ({ findings }) => {
  const [expandedId, setExpandedId] = useState<number | null>(null);

  const toggleExpand = (id: number) => {
    setExpandedId(expandedId === id ? null : id);
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case 'Critical':
        return 'bg-cyber-rose/10 text-cyber-rose border-cyber-rose/30 shadow-glow-rose/20';
      case 'High':
        return 'bg-cyber-amber/10 text-cyber-amber border-cyber-amber/30';
      case 'Medium':
        return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30';
      default:
        return 'bg-cyber-cyan/10 text-cyber-cyan border-cyber-cyan/30';
    }
  };

  return (
    <div className="space-y-4 font-sans">
      <div className="flex items-center justify-between font-mono text-xs border-b border-white/10 pb-3">
        <div className="flex items-center space-x-2 text-slate-100 font-bold">
          <Shield className="w-4 h-4 text-cyber-cyan" />
          <span>Vulnerability Findings ({findings.length})</span>
        </div>
        <span className="text-slate-400 text-[11px]">Click any finding row to expand Gemini AI Advisory</span>
      </div>

      {findings.length === 0 ? (
        <div className="glass-card p-10 rounded-3xl border border-white/10 text-center font-mono text-xs text-slate-500">
          No security vulnerability findings logged for this scope.
        </div>
      ) : (
        <div className="space-y-3">
          {findings.map((f) => {
            const isExpanded = expandedId === f.id;
            return (
              <div
                key={f.id}
                className={`rounded-3xl border transition-all overflow-hidden ${
                  isExpanded
                    ? 'bg-white/[0.04] border-cyber-purple/40 shadow-glow-purple/10'
                    : 'bg-white/[0.02] border-white/10 hover:border-white/20'
                }`}
              >
                {/* Accordion Row Header */}
                <div
                  onClick={() => toggleExpand(f.id)}
                  className="p-5 cursor-pointer flex flex-col sm:flex-row sm:items-center justify-between gap-3 font-mono"
                >
                  <div className="flex items-center space-x-3 truncate">
                    <span className={`px-2.5 py-0.5 rounded-md text-[10px] uppercase font-bold border ${getSeverityBadge(f.severity)}`}>
                      {f.severity}
                    </span>
                    <span className="font-bold text-slate-100 font-sans text-sm truncate">
                      {f.title}
                    </span>
                  </div>

                  <div className="flex items-center space-x-4 text-xs text-slate-400">
                    <span className="hidden md:inline-block truncate max-w-[200px]">
                      {f.affected_url}
                    </span>
                    <span className="px-2 py-0.5 rounded bg-white/5 border border-white/10 font-bold text-[11px] text-cyber-cyan">
                      {f.cvss_score ? `CVSS ${f.cvss_score}` : 'CVSS N/A'}
                    </span>

                    <button className="p-1.5 rounded-xl bg-white/5 text-slate-300 hover:text-white transition-all">
                      {isExpanded ? <ChevronUp className="w-4 h-4 text-cyber-purple" /> : <ChevronDown className="w-4 h-4" />}
                    </button>
                  </div>
                </div>

                {/* Expanded AI Panel Drawer */}
                <AnimatePresence>
                  {isExpanded && (
                    <motion.div
                      initial={{ height: 0, opacity: 0 }}
                      animate={{ height: 'auto', opacity: 1 }}
                      exit={{ height: 0, opacity: 0 }}
                      transition={{ duration: 0.3 }}
                      className="px-5 pb-5 border-t border-white/10 pt-4"
                    >
                      <AiAnalysisPanel findingId={f.id} />
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
