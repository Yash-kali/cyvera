import React from 'react';
import { Layers } from 'lucide-react';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts';
import { motion } from 'framer-motion';
import { OWASPStatsResponse } from '../../api/owasp';

interface OwaspItem {
  name: string;
  value: number;
  color: string;
}

interface OwaspDistributionWidgetProps {
  owaspStats?: OWASPStatsResponse | null;
  customData?: OwaspItem[];
}

const COLOR_PALETTE = ['#00f0ff', '#7000ff', '#ff0055', '#ffb700', '#00c070', '#3b82f6', '#ec4899'];

export const OwaspDistributionWidget: React.FC<OwaspDistributionWidgetProps> = ({
  owaspStats,
  customData,
}) => {
  let displayData: OwaspItem[] = customData || [];

  if (!customData && owaspStats && owaspStats.category_counts) {
    displayData = Object.entries(owaspStats.category_counts)
      .filter(([_, count]) => count > 0)
      .map(([name, value], idx) => ({
        name,
        value,
        color: COLOR_PALETTE[idx % COLOR_PALETTE.length],
      }));
  }

  const hasData = displayData.length > 0;

  return (
    <motion.div
      whileHover={{ y: -4 }}
      className="glass-card p-6 rounded-3xl border border-white/10 flex flex-col justify-between space-y-4 font-sans"
    >
      <div className="flex items-center justify-between font-mono border-b border-white/10 pb-3">
        <div className="flex items-center space-x-2">
          <div className="p-2 rounded-xl bg-cyber-purple/10 border border-cyber-purple/30 text-cyber-purple shadow-glow-purple/20">
            <Layers className="w-4 h-4" />
          </div>
          <h3 className="font-bold text-slate-100 font-display text-sm">OWASP Category Distribution</h3>
        </div>
        <span className="text-[10px] font-mono text-slate-400">TOP 10 2021</span>
      </div>

      <div className="h-52 w-full flex items-center justify-center">
        {!hasData ? (
          <div className="text-center text-slate-500 font-mono text-xs py-10">
            No mapped OWASP vulnerabilities in current scope.
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={displayData}
                cx="50%"
                cy="50%"
                innerRadius={50}
                outerRadius={75}
                paddingAngle={4}
                dataKey="value"
              >
                {displayData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} stroke="rgba(0,0,0,0.4)" strokeWidth={2} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  backgroundColor: '#0b101d',
                  borderColor: 'rgba(255,255,255,0.1)',
                  borderRadius: '12px',
                  fontSize: '11px',
                  color: '#fff',
                }}
              />
            </PieChart>
          </ResponsiveContainer>
        )}
      </div>

      {hasData && (
        <div className="grid grid-cols-2 gap-2 text-[10px] font-mono border-t border-white/5 pt-2">
          {displayData.map((d) => (
            <div key={d.name} className="flex items-center space-x-1.5 truncate">
              <span className="w-2.5 h-2.5 rounded-full flex-shrink-0" style={{ backgroundColor: d.color }} />
              <span className="text-slate-300 truncate">{d.name}</span>
              <span className="text-slate-500 font-bold">({d.value})</span>
            </div>
          ))}
        </div>
      )}
    </motion.div>
  );
};
