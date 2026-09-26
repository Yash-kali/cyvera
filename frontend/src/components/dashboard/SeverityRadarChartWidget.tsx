import React from 'react';
import { ShieldAlert } from 'lucide-react';
import {
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  Radar,
  ResponsiveContainer,
} from 'recharts';
import { motion } from 'framer-motion';
import { RiskSummary } from '../../api/analytics';

interface RadarVectorItem {
  subject: string;
  score: number;
  fullMark: number;
}

interface SeverityRadarChartWidgetProps {
  riskSummary?: RiskSummary | null;
  customData?: RadarVectorItem[];
}

export const SeverityRadarChartWidget: React.FC<SeverityRadarChartWidgetProps> = ({
  riskSummary,
  customData,
}) => {
  let radarData: RadarVectorItem[] = customData || [];

  if (!customData) {
    if (!riskSummary || riskSummary.total_findings === 0) {
      radarData = [
        { subject: 'Web Security', score: 100, fullMark: 100 },
        { subject: 'API Auth', score: 100, fullMark: 100 },
        { subject: 'Network Ports', score: 100, fullMark: 100 },
        { subject: 'TLS / SSL', score: 100, fullMark: 100 },
        { subject: 'IAM Access', score: 100, fullMark: 100 },
        { subject: 'Cloud Config', score: 100, fullMark: 100 },
      ];
    } else {
      const dist = riskSummary.severity_distribution;
      const critDeduction = (dist.Critical || 0) * 20;
      const highDeduction = (dist.High || 0) * 12;
      const medDeduction = (dist.Medium || 0) * 6;
      const lowDeduction = (dist.Low || 0) * 2;

      radarData = [
        { subject: 'Web Security', score: Math.max(20, 100 - critDeduction - medDeduction), fullMark: 100 },
        { subject: 'API Auth', score: Math.max(20, 100 - critDeduction - highDeduction), fullMark: 100 },
        { subject: 'Network Ports', score: Math.max(30, 100 - medDeduction - lowDeduction), fullMark: 100 },
        { subject: 'TLS / SSL', score: Math.max(40, 100 - lowDeduction), fullMark: 100 },
        { subject: 'IAM Access', score: Math.max(25, 100 - highDeduction - medDeduction), fullMark: 100 },
        { subject: 'Cloud Config', score: Math.max(30, 100 - highDeduction), fullMark: 100 },
      ];
    }
  }

  const sorted = [...radarData].sort((a, b) => a.score - b.score);
  const lowest = sorted[0];
  const highest = sorted[sorted.length - 1];

  return (
    <motion.div
      whileHover={{ y: -4 }}
      className="glass-card p-6 rounded-3xl border border-white/10 flex flex-col justify-between space-y-4 font-sans"
    >
      <div className="flex items-center justify-between font-mono border-b border-white/10 pb-3">
        <div className="flex items-center space-x-2">
          <div className="p-2 rounded-xl bg-cyber-cyan/10 border border-cyber-cyan/30 text-cyber-cyan shadow-glow-cyan">
            <ShieldAlert className="w-4 h-4" />
          </div>
          <h3 className="font-bold text-slate-100 font-display text-sm">Severity Compliance Radar</h3>
        </div>
        <span className="text-[10px] font-mono text-cyber-cyan">6 AUDIT VECTORS</span>
      </div>

      <div className="h-56 w-full flex items-center justify-center">
        <ResponsiveContainer width="100%" height="100%">
          <RadarChart cx="50%" cy="50%" outerRadius="70%" data={radarData}>
            <PolarGrid stroke="rgba(255,255,255,0.1)" />
            <PolarAngleAxis dataKey="subject" stroke="#94a3b8" tick={{ fill: '#94a3b8', fontSize: 10 }} />
            <PolarRadiusAxis angle={30} domain={[0, 100]} stroke="rgba(255,255,255,0.1)" />
            <Radar name="Security Posture" dataKey="score" stroke="#00f0ff" fill="#00f0ff" fillOpacity={0.3} />
          </RadarChart>
        </ResponsiveContainer>
      </div>

      <div className="flex items-center justify-between text-[10px] font-mono text-slate-400 border-t border-white/5 pt-2">
        <span>Lowest Vector: <strong className="text-cyber-amber">{lowest?.subject || 'Nominal'} ({lowest?.score || 100}%)</strong></span>
        <span className="text-cyber-emerald">Highest: {highest?.subject || 'Nominal'} ({highest?.score || 100}%)</span>
      </div>
    </motion.div>
  );
};
