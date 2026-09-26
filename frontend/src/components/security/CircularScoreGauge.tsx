import React from 'react';
import { motion } from 'framer-motion';

interface CircularScoreGaugeProps {
  score: number;
  grade: string;
  size?: number;
  strokeWidth?: number;
}

export const CircularScoreGauge: React.FC<CircularScoreGaugeProps> = ({
  score,
  grade,
  size = 200,
  strokeWidth = 14,
}) => {
  const center = size / 2;
  const radius = center - strokeWidth;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  const getGaugeColor = (s: number) => {
    if (s >= 80) return { stroke: '#00f0ff', glow: 'shadow-glow-cyan', text: 'text-cyber-cyan' };
    if (s >= 65) return { stroke: '#10b981', glow: 'shadow-glow-emerald', text: 'text-cyber-emerald' };
    if (s >= 50) return { stroke: '#f59e0b', glow: 'shadow-glow-amber', text: 'text-cyber-amber' };
    return { stroke: '#f43f5e', glow: 'shadow-glow-rose', text: 'text-cyber-rose' };
  };

  const color = getGaugeColor(score);

  return (
    <div className="relative flex flex-col items-center justify-center font-sans">
      <div className="relative" style={{ width: size, height: size }}>
        <svg width={size} height={size} className="transform -rotate-90">
          {/* Outer track background */}
          <circle
            cx={center}
            cy={center}
            r={radius}
            stroke="rgba(255, 255, 255, 0.08)"
            strokeWidth={strokeWidth}
            fill="transparent"
          />

          {/* Animated score arc fill */}
          <motion.circle
            cx={center}
            cy={center}
            r={radius}
            stroke={color.stroke}
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            initial={{ strokeDashoffset: circumference }}
            animate={{ strokeDashoffset }}
            transition={{ duration: 1.2, ease: 'easeOut' }}
            strokeLinecap="round"
            fill="transparent"
          />
        </svg>

        {/* Center score & grade readout */}
        <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
          <motion.span
            initial={{ opacity: 0, scale: 0.5 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.5, delay: 0.3 }}
            className={`text-4xl font-extrabold font-display ${color.text}`}
          >
            {typeof score === 'number' ? (Number.isInteger(score) ? score : score.toFixed(1)) : score}
          </motion.span>
          <span className="text-[10px] font-mono text-slate-400 uppercase tracking-widest">
            OUT OF 100
          </span>
          <div className="mt-1 px-3 py-0.5 rounded-full bg-white/10 border border-white/20 text-xs font-mono font-bold text-slate-100">
            GRADE {grade}
          </div>
        </div>
      </div>
    </div>
  );
};
