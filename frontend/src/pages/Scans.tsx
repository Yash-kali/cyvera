import React, { useState } from 'react';
import { Target, Play, Filter, CheckCircle2, AlertCircle, Clock, ExternalLink } from 'lucide-react';

export const Scans: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'all' | 'active' | 'completed'>('all');

  const targetsList = [
    { id: 'SCN-9021', target: 'https://staging-api.autopentest.ai', status: 'IN_PROGRESS', score: '84%', vulns: 4, critical: 1, duration: '12m 40s', agent: 'AI Agent #1' },
    { id: 'SCN-9020', target: 'https://auth.company.internal', status: 'COMPLETED', score: '92%', vulns: 12, critical: 3, duration: '45m 10s', agent: 'AI Agent #3' },
    { id: 'SCN-9019', target: 'https://payment-gateway-v2.net', status: 'COMPLETED', score: '98%', vulns: 2, critical: 0, duration: '28m 05s', agent: 'AI Agent #2' },
    { id: 'SCN-9018', target: 'https://k8s-ingress.production.io', status: 'FAILED', score: 'N/A', vulns: 0, critical: 0, duration: '02m 14s', agent: 'AI Agent #1' },
    { id: 'SCN-9017', target: 'https://crm.corp.enterprise.com', status: 'COMPLETED', score: '78%', vulns: 18, critical: 5, duration: '1h 12m', agent: 'AI Agent #4' },
  ];

  const filteredTargets = targetsList.filter(t => {
    if (activeTab === 'active') return t.status === 'IN_PROGRESS';
    if (activeTab === 'completed') return t.status === 'COMPLETED';
    return true;
  });

  return (
    <div className="space-y-6 font-mono">
      <div className="glass-panel p-6 rounded-2xl border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <Target className="w-5 h-5 text-[#00ff9d]" />
            <h1 className="text-xl font-bold text-slate-100 font-sans">Target Scan Management</h1>
          </div>
          <p className="text-xs text-slate-400 mt-1">Configure & monitor target scopes for automated penetration testing</p>
        </div>

        <div className="flex items-center space-x-2 bg-slate-900 p-1 rounded-xl border border-slate-800 text-xs">
          <button
            onClick={() => setActiveTab('all')}
            className={`px-3 py-1.5 rounded-lg transition-colors ${activeTab === 'all' ? 'bg-[#00ff9d]/10 text-[#00ff9d] border border-[#00ff9d]/30 font-bold' : 'text-slate-400'}`}
          >
            All Targets (5)
          </button>
          <button
            onClick={() => setActiveTab('active')}
            className={`px-3 py-1.5 rounded-lg transition-colors ${activeTab === 'active' ? 'bg-[#00ff9d]/10 text-[#00ff9d] border border-[#00ff9d]/30 font-bold' : 'text-slate-400'}`}
          >
            Active (1)
          </button>
          <button
            onClick={() => setActiveTab('completed')}
            className={`px-3 py-1.5 rounded-lg transition-colors ${activeTab === 'completed' ? 'bg-[#00ff9d]/10 text-[#00ff9d] border border-[#00ff9d]/30 font-bold' : 'text-slate-400'}`}
          >
            Completed (3)
          </button>
        </div>
      </div>

      <div className="glass-panel p-6 rounded-2xl border border-slate-800">
        <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-950/40">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-900/90 text-slate-400 border-b border-slate-800 uppercase text-[11px]">
              <tr>
                <th className="px-4 py-3">Scan ID</th>
                <th className="px-4 py-3">Target Scope URL</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Security Rating</th>
                <th className="px-4 py-3">Findings</th>
                <th className="px-4 py-3">Agent</th>
                <th className="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300 text-xs">
              {filteredTargets.map((scan) => (
                <tr key={scan.id} className="hover:bg-slate-900/50 transition-colors">
                  <td className="px-4 py-3.5 font-bold text-[#00ff9d]">{scan.id}</td>
                  <td className="px-4 py-3.5 font-mono text-slate-200 flex items-center space-x-1.5">
                    <span>{scan.target}</span>
                    <ExternalLink className="w-3 h-3 text-slate-500" />
                  </td>
                  <td className="px-4 py-3.5">
                    {scan.status === 'IN_PROGRESS' && (
                      <span className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-full bg-blue-500/10 text-blue-400 border border-blue-500/30 font-semibold text-[10px]">
                        <span className="w-1.5 h-1.5 rounded-full bg-blue-400 animate-ping" />
                        <span>RUNNING</span>
                      </span>
                    )}
                    {scan.status === 'COMPLETED' && (
                      <span className="inline-flex items-center space-x-1 px-2.5 py-1 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 font-semibold text-[10px]">
                        <CheckCircle2 className="w-3 h-3" />
                        <span>FINISHED</span>
                      </span>
                    )}
                    {scan.status === 'FAILED' && (
                      <span className="inline-flex items-center space-x-1 px-2.5 py-1 rounded-full bg-rose-500/10 text-rose-400 border border-rose-500/30 font-semibold text-[10px]">
                        <AlertCircle className="w-3 h-3" />
                        <span>ERROR</span>
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3.5 font-bold text-[#00e5ff]">{scan.score}</td>
                  <td className="px-4 py-3.5">
                    {scan.vulns} Vulns ({scan.critical} Crit)
                  </td>
                  <td className="px-4 py-3.5 text-slate-400">{scan.agent}</td>
                  <td className="px-4 py-3.5 text-right">
                    <button className="text-[#00ff9d] hover:underline font-semibold">Details</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
