import React from 'react';
import { Shield, AlertTriangle, ShieldAlert, Lock, FileCode, Server } from 'lucide-react';
import { ScoreFactors, ScoreDeductions } from '../../api/securityScore';

interface RiskSummaryCardsProps {
  factors: ScoreFactors;
  deductions: ScoreDeductions;
  riskLevel: string;
}

export const RiskSummaryCards: React.FC<RiskSummaryCardsProps> = ({
  factors,
  deductions,
  riskLevel,
}) => {
  const totalDeductions =
    deductions.critical_vulnerabilities +
    deductions.high_vulnerabilities +
    deductions.medium_vulnerabilities +
    deductions.ssl_issues +
    deductions.missing_security_headers +
    deductions.open_ports;

  const factorItems = [
    {
      title: 'Critical Vulnerabilities',
      count: factors.critical_vulnerabilities,
      deduction: deductions.critical_vulnerabilities,
      icon: ShieldAlert,
      color: 'text-cyber-rose',
      border: 'border-cyber-rose/30 bg-cyber-rose/10',
    },
    {
      title: 'High Vulnerabilities',
      count: factors.high_vulnerabilities,
      deduction: deductions.high_vulnerabilities,
      icon: AlertTriangle,
      color: 'text-cyber-amber',
      border: 'border-cyber-amber/30 bg-cyber-amber/10',
    },
    {
      title: 'Medium Vulnerabilities',
      count: factors.medium_vulnerabilities,
      deduction: deductions.medium_vulnerabilities,
      icon: Shield,
      color: 'text-yellow-400',
      border: 'border-yellow-500/30 bg-yellow-500/10',
    },
    {
      title: 'SSL / TLS Issues',
      count: factors.ssl_issues,
      deduction: deductions.ssl_issues,
      icon: Lock,
      color: 'text-cyber-purple',
      border: 'border-cyber-purple/30 bg-cyber-purple/10',
    },
    {
      title: 'Missing Security Headers',
      count: factors.missing_security_headers,
      deduction: deductions.missing_security_headers,
      icon: FileCode,
      color: 'text-cyber-cyan',
      border: 'border-cyber-cyan/30 bg-cyber-cyan/10',
    },
    {
      title: 'Open Risk Ports',
      count: factors.open_ports,
      deduction: deductions.open_ports,
      icon: Server,
      color: 'text-blue-400',
      border: 'border-blue-500/30 bg-blue-500/10',
    },
  ];

  return (
    <div className="space-y-4 font-sans">
      {/* Top Total Deductions Summary Card */}
      <div className="glass-card p-4 rounded-2xl border border-white/10 flex items-center justify-between font-mono">
        <div className="flex items-center space-x-3">
          <div className="p-2 rounded-xl bg-white/5 border border-white/10 text-slate-300">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <div className="text-xs text-slate-400">Total Score Deductions</div>
            <div className="text-sm font-bold text-slate-100">
              -{totalDeductions} Risk Penalty Points
            </div>
          </div>
        </div>

        <span className="px-3 py-1 rounded-full bg-white/5 border border-white/10 text-xs text-slate-300">
          6 Core Factors Evaluated
        </span>
      </div>

      {/* Grid of 6 Factor Breakdown Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 font-mono">
        {factorItems.map((item) => {
          const Icon = item.icon;
          return (
            <div
              key={item.title}
              className="p-4 rounded-2xl bg-white/[0.02] border border-white/10 space-y-2 relative overflow-hidden"
            >
              <div className="flex items-center justify-between">
                <div className={`p-2 rounded-xl border ${item.border}`}>
                  <Icon className={`w-4 h-4 ${item.color}`} />
                </div>
                <span className="text-[11px] text-slate-500 font-bold">
                  -{item.deduction} pts
                </span>
              </div>

              <div>
                <div className="text-xs font-bold text-slate-200">{item.title}</div>
                <div className="text-xs text-slate-400 mt-0.5">
                  Count: <strong className={item.color}>{item.count} detected</strong>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
