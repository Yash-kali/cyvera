import React from 'react';
import { motion } from 'framer-motion';
import { OWASPCategoryGroup } from '../../api/owasp';

interface CategoryDistributionChartProps {
  categories: OWASPCategoryGroup[];
  selectedCategory: string | null;
  onSelectCategory: (code: string) => void;
}

export const CategoryDistributionChart: React.FC<CategoryDistributionChartProps> = ({
  categories,
  selectedCategory,
  onSelectCategory,
}) => {
  const maxCount = Math.max(...categories.map((c) => c.count), 1);

  return (
    <div className="glass-card p-6 rounded-3xl border border-white/10 space-y-4 font-sans">
      <div className="flex items-center justify-between border-b border-white/10 pb-3 font-mono">
        <div>
          <h3 className="font-bold text-slate-100 font-display text-sm">
            OWASP Top 10 2021 Distribution
          </h3>
          <p className="text-[11px] text-slate-400 font-sans">
            Category vulnerability counts across A01 to A10
          </p>
        </div>
        <span className="text-[10px] text-cyber-cyan px-2.5 py-1 rounded-full bg-cyber-cyan/10 border border-cyber-cyan/30">
          SELECT BAR TO DRILL-DOWN
        </span>
      </div>

      {/* Bar Chart Container */}
      <div className="space-y-3 pt-2">
        {categories.map((cat) => {
          const isSelected = selectedCategory === cat.code;
          const percentage = (cat.count / maxCount) * 100;

          return (
            <div
              key={cat.code}
              onClick={() => onSelectCategory(cat.code)}
              className={`p-3 rounded-2xl border cursor-pointer transition-all ${
                isSelected
                  ? 'bg-cyber-cyan/10 border-cyber-cyan/50 shadow-glow-cyan/20'
                  : 'bg-white/[0.02] border-white/5 hover:border-white/20'
              }`}
            >
              <div className="flex items-center justify-between text-xs font-mono mb-1.5">
                <div className="flex items-center space-x-2 truncate">
                  <span className="px-2 py-0.5 rounded-md bg-white/10 text-cyber-cyan font-bold text-[10px]">
                    {cat.code}
                  </span>
                  <span className="text-slate-200 font-semibold truncate">{cat.name}</span>
                </div>
                <span className="text-slate-400 font-bold ml-2">
                  {cat.count} {cat.count === 1 ? 'issue' : 'issues'}
                </span>
              </div>

              {/* Progress track */}
              <div className="relative w-full h-2.5 bg-black/40 rounded-full border border-white/10 overflow-hidden">
                <motion.div
                  className={`h-full rounded-full ${
                    cat.count > 0
                      ? 'bg-gradient-to-r from-cyber-cyan to-cyber-purple shadow-glow-cyan'
                      : 'bg-slate-700/40'
                  }`}
                  initial={{ width: '0%' }}
                  animate={{ width: `${cat.count > 0 ? Math.max(percentage, 8) : 0}%` }}
                  transition={{ duration: 0.8, ease: 'easeOut' }}
                />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
