import React from 'react';
import { AIExplanation } from '../../api/ai';
import { Sparkles, DollarSign, Crosshair, Code2 } from 'lucide-react';

interface AiRiskSummaryCardsProps {
  explanation: AIExplanation;
}

export const AiRiskSummaryCards: React.FC<AiRiskSummaryCardsProps> = ({ explanation }) => {
  const cards = [
    {
      title: 'Executive Summary',
      text: explanation.executive_summary,
      icon: Sparkles,
      color: 'text-cyber-cyan',
      border: 'border-cyber-cyan/30 bg-cyber-cyan/10',
    },
    {
      title: 'Business Impact',
      text: explanation.business_impact,
      icon: DollarSign,
      color: 'text-cyber-amber',
      border: 'border-cyber-amber/30 bg-cyber-amber/10',
    },
    {
      title: 'Attack Scenario',
      text: explanation.attack_scenario,
      icon: Crosshair,
      color: 'text-cyber-rose',
      border: 'border-cyber-rose/30 bg-cyber-rose/10',
    },
    {
      title: 'Secure Coding Advice',
      text: explanation.secure_coding_recommendations || explanation.remediation_guidance,
      icon: Code2,
      color: 'text-cyber-purple',
      border: 'border-cyber-purple/30 bg-cyber-purple/10',
    },
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-sans">
      {cards.map((card) => {
        const Icon = card.icon;
        return (
          <div
            key={card.title}
            className="p-5 rounded-2xl bg-white/[0.02] border border-white/10 space-y-2.5 relative overflow-hidden"
          >
            <div className="flex items-center space-x-2.5 font-mono">
              <div className={`p-2 rounded-xl border ${card.border}`}>
                <Icon className={`w-4 h-4 ${card.color}`} />
              </div>
              <h4 className="font-bold text-slate-100 text-xs font-display">{card.title}</h4>
            </div>
            <p className="text-xs text-slate-300 font-sans leading-relaxed">
              {card.text}
            </p>
          </div>
        );
      })}
    </div>
  );
};
