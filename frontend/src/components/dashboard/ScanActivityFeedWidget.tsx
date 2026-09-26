import React from 'react';
import { Activity, Radio, CheckCircle2, AlertCircle, Download } from 'lucide-react';
import { motion } from 'framer-motion';
import { Scan } from '../../api/scans';

export interface ActivityItem {
  id: string;
  scanIdNumber?: number;
  target: string;
  stage: string;
  status: 'IN_PROGRESS' | 'COMPLETED' | 'FAILED';
  vulnsCount: number;
  timestamp: string;
}

interface ScanActivityFeedWidgetProps {
  scans?: Scan[];
  activities?: ActivityItem[];
}

export const ScanActivityFeedWidget: React.FC<ScanActivityFeedWidgetProps> = ({
  scans,
  activities: customActivities,
}) => {
  const displayActivities: ActivityItem[] = customActivities || (scans ? scans.map((s) => {
    const isCompleted = s.status?.toLowerCase() === 'completed';
    const isRunning = s.status?.toLowerCase() === 'running';
    const statusVal: 'IN_PROGRESS' | 'COMPLETED' | 'FAILED' = isCompleted
      ? 'COMPLETED'
      : isRunning
      ? 'IN_PROGRESS'
      : 'FAILED';

    return {
      id: `SCN-${s.id}`,
      scanIdNumber: s.id,
      target: s.target_url,
      stage: isCompleted ? 'Scan Completed' : isRunning ? 'Audit Executing' : 'Scan Failed',
      status: statusVal,
      vulnsCount: s.vulnerabilities_count || 0,
      timestamp: new Date(s.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };
  }) : []);

  return (
    <motion.div
      whileHover={{ y: -4 }}
      className="glass-card p-6 rounded-3xl border border-white/10 flex flex-col justify-between space-y-4 font-sans"
    >
      <div className="flex items-center justify-between font-mono border-b border-white/10 pb-3">
        <div className="flex items-center space-x-2">
          <div className="p-2 rounded-xl bg-cyber-cyan/10 border border-cyber-cyan/30 text-cyber-cyan shadow-glow-cyan">
            <Activity className="w-4 h-4" />
          </div>
          <h3 className="font-bold text-slate-100 font-display text-sm">Scan Activity Feed</h3>
        </div>
        <div className="flex items-center space-x-1.5 text-[10px] text-cyber-cyan font-mono">
          <span className="w-2 h-2 rounded-full bg-cyber-cyan animate-ping" />
          <span>LIVE STREAM</span>
        </div>
      </div>

      <div className="space-y-2.5 font-mono text-xs overflow-y-auto max-h-[220px] pr-1">
        {displayActivities.length === 0 ? (
          <div className="py-8 text-center text-slate-500 font-mono text-xs">
            No recent scan activity recorded.
          </div>
        ) : (
          displayActivities.map((act) => (
            <div
              key={act.id}
              className="p-3 rounded-2xl bg-white/[0.02] border border-white/10 hover:border-white/20 transition-all flex items-center justify-between gap-3"
            >
              <div className="flex items-center space-x-2.5 truncate">
                {act.status === 'IN_PROGRESS' && <Radio className="w-4 h-4 text-cyber-cyan animate-pulse flex-shrink-0" />}
                {act.status === 'COMPLETED' && <CheckCircle2 className="w-4 h-4 text-cyber-emerald flex-shrink-0" />}
                {act.status === 'FAILED' && <AlertCircle className="w-4 h-4 text-cyber-rose flex-shrink-0" />}

                <div className="truncate">
                  <div className="font-bold text-slate-200 truncate">{act.target}</div>
                  <div className="text-[10px] text-slate-400 font-mono">{act.stage}</div>
                </div>
              </div>

              <div className="flex items-center space-x-2.5 text-right flex-shrink-0">
                {act.status === 'COMPLETED' && act.scanIdNumber && (
                  <button
                    onClick={async (e) => {
                      e.stopPropagation();
                      const { downloadReportByIdApi } = await import('../../api/reports');
                      await downloadReportByIdApi(act.scanIdNumber!, 'Security');
                    }}
                    className="px-2 py-0.5 rounded-lg bg-cyber-cyan/20 border border-cyber-cyan/40 text-cyber-cyan hover:bg-cyber-cyan hover:text-slate-950 font-bold text-[10px] transition-all flex items-center space-x-1"
                    title="Download PDF Report Immediately"
                  >
                    <Download className="w-3 h-3" />
                    <span>PDF</span>
                  </button>
                )}
                <span className="px-2 py-0.5 rounded bg-white/5 border border-white/10 font-bold text-[10px] text-cyber-purple">
                  {act.vulnsCount} Vulns
                </span>
                <span className="text-[10px] text-slate-500">{act.timestamp}</span>
              </div>
            </div>
          ))
        )}
      </div>
    </motion.div>
  );
};
