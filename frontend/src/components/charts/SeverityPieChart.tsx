import React from 'react';
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from 'chart.js';
import { Pie } from 'react-chartjs-2';

ChartJS.register(ArcElement, Tooltip, Legend);

interface SeverityPieChartProps {
  critical?: number;
  high?: number;
  medium?: number;
  low?: number;
  info?: number;
}

export const SeverityPieChart: React.FC<SeverityPieChartProps> = ({
  critical = 4,
  high = 8,
  medium = 14,
  low = 22,
  info = 9,
}) => {
  const options = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'bottom' as const,
        labels: {
          color: '#94a3b8',
          font: {
            family: 'JetBrains Mono, monospace',
            size: 10,
          },
          usePointStyle: true,
          pointStyle: 'circle',
          padding: 12,
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
    labels: [
      `Critical (${critical})`,
      `High (${high})`,
      `Medium (${medium})`,
      `Low (${low})`,
      `Info (${info})`,
    ],
    datasets: [
      {
        label: 'Vulnerability Findings',
        data: [critical, high, medium, low, info],
        backgroundColor: [
          '#ff3366', // Critical Red
          '#ffb800', // High Amber
          '#00e5ff', // Medium Cyan
          '#00ff9d', // Low Green
          '#3b82f6', // Info Blue
        ],
        borderColor: '#06090f',
        borderWidth: 2,
        hoverOffset: 6,
      },
    ],
  };

  return (
    <div className="w-full h-[240px] flex items-center justify-center">
      <Pie options={options} data={data} />
    </div>
  );
};
