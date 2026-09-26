import React, { useState, useEffect } from 'react';
import { getRiskSummaryApi, getAssetRiskApi, RiskSummary, AssetRiskItem } from '../api/analytics';
import {
  ShieldCheck,
  ShieldAlert,
  Activity,
  TrendingDown,
  BarChart3,
  RefreshCw,
  Award,
  Zap
} from 'lucide-react';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
  ArcElement
} from 'chart.js';
import { Bar } from 'react-chartjs-2';

ChartJS.register(CategoryScale, LinearScale, BarElement, ArcElement, Title, Tooltip, Legend);

export const RiskAnalytics: React.FC = () => {
  const [summary, setSummary] = useState<RiskSummary | null>(null);
  const [assetRisks, setAssetRisks] = useState<AssetRiskItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);

  const fetchAnalytics = async () => {
    setLoading(true);
    try {
      const [sumData, assetData] = await Promise.all([
        getRiskSummaryApi(),
        getAssetRiskApi()
      ]);
      setSummary(sumData);
      setAssetRisks(assetData);
    } catch (err) {
      console.error('Failed to load risk analytics:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAnalytics();
  }, []);

  const barData = {
    labels: ['Critical', 'High', 'Medium', 'Low', 'Informational'],
    datasets: [
      {
        label: 'Vulnerability Count',
        data: [
          summary?.severity_distribution?.Critical ?? 0,
          summary?.severity_distribution?.High ?? 0,
          summary?.severity_distribution?.Medium ?? 0,
          summary?.severity_distribution?.Low ?? 0,
          summary?.severity_distribution?.Info ?? 0
        ],
        backgroundColor: [
          '#ff3366', // Critical Red
          '#ffb800', // High Amber
          '#00e5ff', // Medium Cyan
          '#00ff9d', // Low Green
          '#3b82f6'  // Info Blue
        ],
        borderRadius: 6,
      }
    ]
  };

  const barOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: '#0f172a',
        borderColor: '#1e293b',
        borderWidth: 1,
        titleFont: { family: 'JetBrains Mono', size: 12 },
        bodyFont: { family: 'JetBrains Mono', size: 11 }
      }
    },
    scales: {
      x: { grid: { display: false }, ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 } } },
      y: { grid: { color: 'rgba(255, 255, 255, 0.04)' }, ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 } } }
    }
  };

  return (
    <div className="space-y-8 font-mono">
      
      {/* Header Banner */}
      <div className="glass-panel p-6 rounded-2xl border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-xl bg-purple-500/10 border border-purple-500/30 text-purple-400 shadow-lg">
            <BarChart3 className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-slate-100 font-sans">Vulnerability Risk Assessment Engine</h1>
            <p className="text-xs text-slate-400">CVSS-inspired risk calculation & organizational security health analytics</p>
          </div>
        </div>

        <button
          onClick={fetchAnalytics}
          className="p-2.5 rounded-xl bg-slate-900 border border-slate-800 text-slate-400 hover:text-white"
          title="Refresh Analytics"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-[#00ff9d]' : ''}`} />
        </button>
      </div>

      {/* Top 4 Risk Score Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
        
        {/* Card 1: Security Score */}
        <div className="glass-panel p-5 rounded-2xl border border-slate-800/90 hover:border-[#00ff9d]/40 transition-all">
          <div className="flex items-center justify-between">
            <span className="text-[11px] text-slate-400 uppercase tracking-wider font-semibold">Security Health Score</span>
            <ShieldCheck className="w-4 h-4 text-[#00ff9d]" />
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <span className="text-3xl font-bold text-[#00ff9d] font-sans">
              {summary ? summary.security_score : '--'} <span className="text-sm text-slate-500">/ 100</span>
            </span>
            <span className="px-2 py-0.5 text-[10px] rounded bg-[#00ff9d]/10 text-[#00ff9d] border border-[#00ff9d]/30 font-bold">
              {summary ? summary.grade : 'STANDBY'}
            </span>
          </div>
          <div className="mt-2 text-[11px] text-slate-500">Weighted CVSS Impact Evaluated</div>
        </div>

        {/* Card 2: Risk Score */}
        <div className="glass-panel p-5 rounded-2xl border border-slate-800/90 hover:border-rose-500/40 transition-all">
          <div className="flex items-center justify-between">
            <span className="text-[11px] text-slate-400 uppercase tracking-wider font-semibold">Weighted Risk Score</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <span className="text-3xl font-bold text-rose-400 font-sans">
              {summary ? summary.risk_score : 0.0} <span className="text-sm text-slate-500">/ 100</span>
            </span>
            <span className="text-xs text-slate-400 flex items-center space-x-0.5">
              <TrendingDown className="w-3.5 h-3.5 text-cyber-cyan" />
              <span>CVSS v3.1</span>
            </span>
          </div>
          <div className="mt-2 text-[11px] text-slate-500">Lower is safer</div>
        </div>

        {/* Card 3: Active vs Resolved */}
        <div className="glass-panel p-5 rounded-2xl border border-slate-800/90 hover:border-[#00e5ff]/40 transition-all">
          <div className="flex items-center justify-between">
            <span className="text-[11px] text-slate-400 uppercase tracking-wider font-semibold">Active vs Resolved</span>
            <Activity className="w-4 h-4 text-[#00e5ff]" />
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <span className="text-3xl font-bold text-slate-100 font-sans">
              {summary ? summary.open_findings : 0} <span className="text-sm text-slate-500">/ {summary ? summary.total_findings : 0}</span>
            </span>
            <span className="text-xs text-[#00e5ff] font-bold">
              {summary ? `${summary.resolved_findings} Fixed` : '0 Fixed'}
            </span>
          </div>
          <div className="mt-2 text-[11px] text-slate-500">Open Findings Triage Rate</div>
        </div>

        {/* Card 4: SLA Compliance Rate */}
        <div className="glass-panel p-5 rounded-2xl border border-slate-800/90 hover:border-emerald-500/40 transition-all">
          <div className="flex items-center justify-between">
            <span className="text-[11px] text-slate-400 uppercase tracking-wider font-semibold">SLA Fix Rate</span>
            <Award className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <span className="text-3xl font-bold text-emerald-400 font-sans">
              {summary && summary.total_findings > 0 ? `${summary.sla_compliance_rate}%` : '--'}
            </span>
            <span className="px-2 py-0.5 text-[10px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 rounded font-bold">
              {summary && summary.sla_compliance_rate >= 80 ? 'COMPLIANT' : 'REVIEW'}
            </span>
          </div>
          <div className="mt-2 text-[11px] text-slate-500">Remediation SLA Metric</div>
        </div>

      </div>

      {/* Main Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Severity Mapping Distribution Bar Chart (2 Cols) */}
        <div className="lg:col-span-2 glass-panel p-6 rounded-2xl border border-slate-800 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div>
              <h3 className="text-sm font-bold text-slate-100 font-sans">Severity Mapping Distribution</h3>
              <p className="text-xs text-slate-400">Classified finding volume by CVSS impact level</p>
            </div>
            <span className="px-2.5 py-0.5 text-[10px] bg-slate-900 border border-slate-800 text-[#00ff9d] rounded">
              CVSS v3.1 Standards
            </span>
          </div>
          <div className="h-[240px]">
            <Bar options={barOptions} data={barData} />
          </div>
        </div>

        {/* CVSS Risk Calculation Formula Explanation Box (1 Col) */}
        <div className="glass-panel p-6 rounded-2xl border border-slate-800 space-y-4 flex flex-col justify-between">
          <div className="space-y-3">
            <div className="flex items-center space-x-2 text-purple-400">
              <Zap className="w-4 h-4" />
              <h3 className="font-bold text-xs uppercase tracking-wider font-sans">CVSS Risk Calculation Model</h3>
            </div>
            <p className="text-xs text-slate-400 font-sans leading-relaxed">
              Risk score $R$ is calculated dynamically using weighted CVSS vector impacts over active unmitigated findings:
            </p>
            <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-[11px] font-mono space-y-1.5">
              <div className="text-[#00ff9d]">R = min(100, ∑ (Weight × Open Findings))</div>
              <div className="text-slate-500">• Critical Weight: 25.0</div>
              <div className="text-slate-500">• High Weight: 15.0</div>
              <div className="text-slate-500">• Medium Weight: 5.0</div>
              <div className="text-slate-500">• Low Weight: 1.0</div>
            </div>
          </div>

          <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 text-xs flex items-center justify-between">
            <span className="text-slate-400">Security Health S = </span>
            <span className="text-[#00ff9d] font-bold">100 - R</span>
          </div>
        </div>

      </div>

      {/* Target Asset Risk Breakdown Data Table */}
      <div className="glass-panel p-6 rounded-2xl border border-slate-800 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-4">
          <div>
            <h3 className="text-base font-bold text-slate-100 font-sans">Target Asset Risk Breakdown</h3>
            <p className="text-xs text-slate-400">Per-domain asset risk ratings and security scores</p>
          </div>
        </div>

        <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-950/40">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-900/90 text-slate-400 border-b border-slate-800 uppercase text-[11px]">
              <tr>
                <th className="px-4 py-3">Target Scope Domain / Endpoint</th>
                <th className="px-4 py-3">Total Findings</th>
                <th className="px-4 py-3">Critical / High</th>
                <th className="px-4 py-3">Asset Risk Score</th>
                <th className="px-4 py-3">Asset Security Rating</th>
                <th className="px-4 py-3 text-right">Risk Level</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300 text-xs">
              {assetRisks.length > 0 ? (
                assetRisks.map((asset) => (
                  <tr key={asset.target_url} className="hover:bg-slate-900/50 transition-colors">
                    <td className="px-4 py-3.5 font-bold text-slate-200 font-mono truncate max-w-[260px]">
                      {asset.target_url}
                    </td>
                    <td className="px-4 py-3.5 text-slate-300 font-bold">{asset.total_findings}</td>
                    <td className="px-4 py-3.5">
                      <span className="text-rose-400 font-semibold">{asset.critical_count} Crit</span>
                      <span className="text-amber-400 font-semibold ml-2">({asset.high_count} High)</span>
                    </td>
                    <td className="px-4 py-3.5 font-bold text-rose-400">{asset.asset_risk_score}</td>
                    <td className="px-4 py-3.5 font-bold text-[#00ff9d]">{asset.asset_security_score} / 100</td>
                    <td className="px-4 py-3.5 text-right font-bold">
                      {asset.risk_rating === 'LOW_RISK' && (
                        <span className="px-2.5 py-0.5 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 text-[10px]">
                          LOW RISK
                        </span>
                      )}
                      {asset.risk_rating === 'MEDIUM_RISK' && (
                        <span className="px-2.5 py-0.5 rounded bg-amber-500/20 text-amber-400 border border-amber-500/30 text-[10px]">
                          MEDIUM RISK
                        </span>
                      )}
                      {asset.risk_rating === 'HIGH_RISK' && (
                        <span className="px-2.5 py-0.5 rounded bg-rose-500/20 text-rose-400 border border-rose-500/30 text-[10px]">
                          HIGH RISK
                        </span>
                      )}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-slate-500 font-mono">
                    No target domain assets with active vulnerability findings recorded.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

    </div>
  );
};

export default RiskAnalytics;
