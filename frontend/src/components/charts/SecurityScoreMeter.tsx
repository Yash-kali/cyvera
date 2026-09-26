import React from 'react';
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from 'chart.js';
import { Doughnut } from 'react-chartjs-2';
import { ShieldCheck, Award } from 'lucide-react';

ChartJS.register(ArcElement, Tooltip, Legend);

interface SecurityScoreMeterProps {
  score?: number;
  grade?: string;
  riskScore?: number;
}

export const SecurityScoreMeter: React.FC<SecurityScoreMeterProps> = ({
  score = 0,
  grade = 'AWAITING',
  riskScore = 0,
}) => {
  const options = {
    responsive: true,
    maintainAspectRatio: false,
    circumference: 240,
    rotation: 240,
    cutout: '78%',
    plugins: {
      legend: { display: false },
      tooltip: { enabled: false },
    },
  };

  const remaining = Math.max(0, 100 - score);

  const data = {
    labels: ['Security Health', 'Risk Exposure'],
    datasets: [
      {
        data: [score, remaining],
        backgroundColor: [
          score >= 85 ? '#00ff9d' : score >= 70 ? '#00e5ff' : score >= 50 ? '#ffb800' : '#ff3366',
          '#1e293b',
        ],
        borderColor: '#06090f',
        borderWidth: 3,
      },
    ],
  };

  return (
    <div className="relative w-full h-[240px] flex flex-col items-center justify-center">
      <Doughnut options={options} data={data} />
      <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none pt-4">
        <div className="flex items-center space-x-1 text-[#00ff9d]">
          <ShieldCheck className="w-5 h-5" />
          <span className="text-3xl font-bold font-sans tracking-tight">{score}</span>
          <span className="text-xs text-slate-500 font-mono">/ 100</span>
        </div>
        <div className="mt-1 px-2.5 py-0.5 rounded bg-[#00ff9d]/10 text-[#00ff9d] border border-[#00ff9d]/30 font-bold font-mono text-[10px]">
          {grade}
        </div>
        <div className="mt-2 text-[10px] text-slate-500 font-mono">
          Weighted Risk: <span className="text-rose-400 font-semibold">{riskScore}</span>
        </div>
      </div>
    </div>
  );
};
