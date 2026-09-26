import React, { useState, useEffect } from 'react';
import { getSecurityScoreApi, SecurityScoreResponse } from '../../api/securityScore';
import { CircularScoreGauge } from './CircularScoreGauge';
import { RiskSummaryCards } from './RiskSummaryCards';
import { SecurityGradeWidget } from './SecurityGradeWidget';
import { Shield, RefreshCw, AlertCircle, Cpu } from 'lucide-react';

interface SecurityScoreEngineProps {
  scanId: number;
}

export const SecurityScoreEngine: React.FC<SecurityScoreEngineProps> = ({ scanId }) => {
  const [data, setData] = useState<SecurityScoreResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const fetchScore = async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await getSecurityScoreApi(scanId);
      setData(result);
    } catch (err: any) {
      console.error('Failed to fetch security score:', err);
      setError(err.response?.data?.detail || 'Unable to calculate security posture score for this scan.');
      setData(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScore();
  }, [scanId]);

  return (
    <div className="space-y-6 font-sans">
      {/* Top Banner */}
      <div className="glass-card p-6 rounded-3xl border border-white/10 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-2xl bg-cyber-cyan/10 border border-cyber-cyan/30 text-cyber-cyan shadow-glow-cyan">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-lg font-bold font-display text-slate-100">
              Security Score Engine (Scan #{scanId})
            </h2>
            <p className="text-xs font-mono text-slate-400">
              Evaluates 6 core posture factors to compute automated security score & grade
            </p>
          </div>
        </div>

        <button
          onClick={fetchScore}
          disabled={loading}
          className="px-4 py-2 rounded-2xl bg-white/5 border border-white/10 hover:border-cyber-cyan/40 text-slate-300 text-xs font-mono flex items-center space-x-2 transition-all disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-cyber-cyan' : ''}`} />
          <span>Recalculate Score</span>
        </button>
      </div>

      {loading ? (
        <div className="glass-card p-12 rounded-3xl border border-white/10 text-center space-y-3 font-mono">
          <div className="w-8 h-8 border-2 border-cyber-cyan border-t-transparent rounded-full animate-spin mx-auto" />
          <div className="text-xs text-slate-400">Computing target security score & risk deductions...</div>
        </div>
      ) : error ? (
        <div className="glass-card p-6 rounded-3xl border border-cyber-rose/30 bg-cyber-rose/10 text-center space-y-2 font-mono">
          <div className="text-xs text-cyber-rose font-bold">{error}</div>
        </div>
      ) : data ? (
        <>
          {/* Main Visual Section: Animated Gauge & Grade Widget side-by-side */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="glass-card p-8 rounded-3xl border border-white/10 flex items-center justify-center">
              <CircularScoreGauge score={data.score} grade={data.grade} />
            </div>

            <SecurityGradeWidget
              score={data.score}
              grade={data.grade}
              riskLevel={data.risk_level}
            />
          </div>

          {/* Risk Summary Cards for 6 Factors */}
          <RiskSummaryCards
            factors={data.factors}
            deductions={data.deductions}
            riskLevel={data.risk_level}
          />
        </>
      ) : null}
    </div>
  );
};
