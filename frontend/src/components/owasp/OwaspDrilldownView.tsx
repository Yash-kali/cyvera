import React from 'react';
import { OWASPCategoryGroup } from '../../api/owasp';
import { Shield, ExternalLink, AlertCircle, CheckCircle2, ChevronRight, FileText } from 'lucide-react';

interface OwaspDrilldownViewProps {
  category: OWASPCategoryGroup | null;
}

export const OwaspDrilldownView: React.FC<OwaspDrilldownViewProps> = ({ category }) => {
  if (!category) {
    return (
      <div className="glass-card p-12 rounded-3xl border border-white/10 text-center font-mono space-y-2">
        <Shield className="w-8 h-8 text-slate-500 mx-auto" />
        <div className="text-xs text-slate-400">Select an OWASP category card to inspect drill-down findings.</div>
      </div>
    );
  }

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case 'Critical':
        return 'bg-cyber-rose/10 text-cyber-rose border-cyber-rose/30';
      case 'High':
        return 'bg-cyber-amber/10 text-cyber-amber border-cyber-amber/30';
      case 'Medium':
        return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30';
      default:
        return 'bg-cyber-cyan/10 text-cyber-cyan border-cyber-cyan/30';
    }
  };

  return (
    <div className="glass-card p-6 rounded-3xl border border-white/10 space-y-6 font-sans">
      {/* Category Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-white/10 pb-4">
        <div className="flex items-center space-x-3 font-mono">
          <span className="px-3 py-1 rounded-xl bg-cyber-purple/20 border border-cyber-purple/40 text-cyber-purple font-extrabold text-sm">
            {category.code}
          </span>
          <div>
            <h3 className="font-bold text-slate-100 font-display text-base">
              {category.name}
            </h3>
            <p className="text-xs text-slate-400 font-sans">
              OWASP Top 10 2021 Security Category Breakdown
            </p>
          </div>
        </div>

        <div className="px-3.5 py-1 rounded-full bg-white/5 border border-white/10 font-mono text-xs font-bold text-slate-300">
          {category.count} Mapped {category.count === 1 ? 'Finding' : 'Findings'}
        </div>
      </div>

      {/* Findings List */}
      {category.findings.length === 0 ? (
        <div className="p-8 rounded-2xl bg-white/[0.02] border border-white/5 text-center font-mono text-xs text-slate-500 space-y-1">
          <CheckCircle2 className="w-6 h-6 text-cyber-emerald mx-auto" />
          <div>No active vulnerability findings mapped to {category.code} {category.name}.</div>
        </div>
      ) : (
        <div className="space-y-4">
          {category.findings.map((f) => (
            <div
              key={f.id}
              className="p-5 rounded-2xl bg-white/[0.03] border border-white/10 hover:border-white/20 transition-all space-y-3 font-mono"
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div className="flex items-center space-x-2">
                  <span className={`px-2.5 py-0.5 rounded-md text-[10px] uppercase font-bold border ${getSeverityBadge(f.severity)}`}>
                    {f.severity}
                  </span>
                  <span className="text-sm font-bold text-slate-100 font-sans">{f.title}</span>
                </div>
                {f.cvss_score && (
                  <span className="text-xs text-slate-400">
                    CVSS: <strong className="text-cyber-cyan">{f.cvss_score}</strong>
                  </span>
                )}
              </div>

              <p className="text-xs font-sans text-slate-300 leading-relaxed">
                {f.description}
              </p>

              <div className="p-3 rounded-xl bg-black/30 border border-white/5 text-[11px] space-y-1">
                <div className="text-slate-500 uppercase text-[10px] font-bold">Remediation Guidance</div>
                <div className="text-slate-300 font-sans">{f.remediation_guidance}</div>
              </div>

              <div className="flex items-center justify-between text-[11px] text-slate-400 pt-1 border-t border-white/5">
                <span>Affected Endpoint: <strong className="text-slate-200">{f.affected_url}</strong></span>
                <span className="text-cyber-purple font-bold">Status: {f.status}</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
