import React from 'react';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
} from 'chart.js';
import { Bar } from 'react-chartjs-2';

ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend
);

export const OwaspDistributionChart: React.FC = () => {
  const options = {
    indexAxis: 'y' as const, // Horizontal Bar Chart
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: '#0f172a',
        borderColor: '#1e293b',
        borderWidth: 1,
        titleColor: '#00e5ff',
        bodyColor: '#e2e8f0',
        titleFont: { family: 'JetBrains Mono', size: 12 },
        bodyFont: { family: 'JetBrains Mono', size: 11 },
        padding: 10,
      },
    },
    scales: {
      x: {
        grid: { color: 'rgba(255, 255, 255, 0.04)' },
        ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 } },
      },
      y: {
        grid: { display: false },
        ticks: { color: '#94a3b8', font: { family: 'JetBrains Mono', size: 10 } },
      },
    },
  };

  const labels = [
    'A01: Broken Access Control',
    'A02: Cryptographic Failures',
    'A03: Injection (SQL/XSS)',
    'A04: Insecure Design',
    'A05: Security Misconfig',
    'A06: Outdated Components',
  ];

  const data = {
    labels,
    datasets: [
      {
        label: 'Vulnerability Count',
        data: [14, 8, 12, 5, 18, 9],
        backgroundColor: '#00e5ff',
        borderRadius: 4,
        hoverBackgroundColor: '#00ff9d',
      },
    ],
  };

  return (
    <div className="w-full h-[240px]">
      <Bar options={options} data={data} />
    </div>
  );
};
