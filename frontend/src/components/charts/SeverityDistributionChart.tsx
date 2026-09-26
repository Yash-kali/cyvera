import React from 'react';
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from 'chart.js';
import { Doughnut } from 'react-chartjs-2';

ChartJS.register(ArcElement, Tooltip, Legend);

export const SeverityDistributionChart: React.FC = () => {
  const options = {
    responsive: true,
    maintainAspectRatio: false,
    cutout: '70%',
    plugins: {
      legend: {
        position: 'bottom' as const,
        labels: {
          color: '#94a3b8',
          font: {
            family: 'JetBrains Mono, monospace',
            size: 11,
          },
          usePointStyle: true,
          pointStyle: 'circle',
          padding: 15,
        },
      },
      tooltip: {
        backgroundColor: '#0f172a',
        borderColor: '#1e293b',
        borderWidth: 1,
        titleColor: '#00ff9d',
        bodyColor: '#e2e8f0',
        titleFont: { family: 'JetBrains Mono', size: 12 },
        bodyFont: { family: 'JetBrains Mono', size: 11 },
        padding: 10,
      },
    },
  };

  const data = {
    labels: ['Critical (37)', 'High (84)', 'Medium (192)', 'Low (340)'],
    datasets: [
      {
        label: 'Vulnerabilities',
        data: [37, 84, 192, 340],
        backgroundColor: [
          '#ff3366', // Critical Red
          '#ffb800', // High Amber
          '#00e5ff', // Medium Cyan
          '#00ff9d', // Low Green
        ],
        borderColor: '#0b1120',
        borderWidth: 3,
        hoverOffset: 6,
      },
    ],
  };

  return (
    <div className="relative w-full h-[260px] flex items-center justify-center">
      <Doughnut options={options} data={data} />
      <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none pb-8">
        <span className="text-2xl font-bold text-slate-100 font-mono">653</span>
        <span className="text-[10px] text-slate-400 font-mono uppercase tracking-widest">TOTAL FINDINGS</span>
      </div>
    </div>
  );
};
