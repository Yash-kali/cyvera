import React, { useState, useEffect } from 'react';
import { getAiResultApi, analyzeFindingApi, AIExplanation } from '../../api/ai';
import { AiRiskSummaryCards } from './AiRiskSummaryCards';
import { Sparkles, RefreshCw, ShieldCheck, Terminal, Cpu, CheckCircle2, Code } from 'lucide-react';

interface AiAnalysisPanelProps {
  findingId: number;
}

export const AiAnalysisPanel: React.FC<AiAnalysisPanelProps> = ({ findingId }) => {
  const [data, setData] = useState<AIExplanation | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const fetchAnalysis = async (forceReanalyze: boolean = false) => {
    setLoading(true);
    setError(null);
    try {
      if (forceReanalyze) {
        const result = await analyzeFindingApi(findingId);
        setData(result);
      } else {
        const result = await getAiResultApi(findingId);
        setData(result);
      }
    } catch (err: any) {
      console.error('Failed to fetch AI analysis:', err);
      setError('Failed to trigger Gemini API analysis.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAnalysis(false);
  }, [findingId]);

  return (
    <div className="glass-card p-6 rounded-3xl border border-white/10 space-y-6 font-sans">
      {/* Header Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-white/10 pb-4">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-2xl bg-cyber-purple/10 border border-cyber-purple/30 text-cyber-purple shadow-glow-purple">
            <Sparkles className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <h3 className="font-bold text-slate-100 font-display text-base">
              Google Gemini Security Advisory
            </h3>
            <p className="text-xs font-mono text-slate-400">
              7-Section AI root cause, attack scenario & secure coding analysis
            </p>
          </div>
        </div>

        <button
          onClick={() => fetchAnalysis(true)}
          disabled={loading}
          className="px-4 py-2 rounded-2xl bg-gradient-to-r from-cyber-purple to-cyber-cyan hover:opacity-95 text-slate-950 font-mono font-bold text-xs flex items-center space-x-2 transition-all shadow-glow-purple disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>RE-ANALYZE WITH GEMINI</span>
        </button>
      </div>

      {loading ? (
        <div className="p-12 text-center font-mono text-xs space-y-3">
          <div className="w-8 h-8 border-2 border-cyber-purple border-t-transparent rounded-full animate-spin mx-auto" />
          <div className="text-slate-400">Querying Google Gemini API for vulnerability advisory...</div>
        </div>
      ) : data ? (
        <div className="space-y-6">
          {/* AI Risk Summary Metric Cards (Executive, Impact, Scenario, Coding) */}
          <AiRiskSummaryCards explanation={data} />

          {/* Full Technical Explanation & Remediation Steps */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono">
            <div className="p-5 rounded-2xl bg-black/40 border border-white/10 space-y-2">
              <div className="text-xs font-bold text-cyber-cyan flex items-center space-x-2">
                <Terminal className="w-4 h-4" />
                <span>Technical Explanation</span>
              </div>
              <p className="text-xs font-sans text-slate-300 leading-relaxed">
                {data.technical_description}
              </p>
            </div>

            <div className="p-5 rounded-2xl bg-black/40 border border-white/10 space-y-2">
              <div className="text-xs font-bold text-cyber-emerald flex items-center space-x-2">
                <CheckCircle2 className="w-4 h-4" />
                <span>Remediation Steps</span>
              </div>
              <p className="text-xs font-sans text-slate-300 leading-relaxed">
                {data.remediation_guidance}
              </p>
            </div>
          </div>

          {/* OWASP Mapping Badge */}
          <div className="p-4 rounded-2xl bg-white/[0.02] border border-white/10 flex items-center justify-between font-mono text-xs">
            <span className="text-slate-400">OWASP Top 10 Standard Classification:</span>
            <span className="px-3 py-1 rounded-full bg-cyber-purple/20 border border-cyber-purple/40 text-cyber-purple font-bold">
              {data.owasp_mapping}
            </span>
          </div>
        </div>
      ) : (
        <div className="p-8 text-center text-slate-500 font-mono text-xs italic">
          No AI explanation generated yet. Click 'RE-ANALYZE WITH GEMINI' to trigger.
        </div>
      )}
    </div>
  );
};
