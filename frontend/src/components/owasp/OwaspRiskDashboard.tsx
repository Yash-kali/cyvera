import React, { useState, useEffect } from 'react';
import { getOwaspFindingsApi, getOwaspStatsApi, OWASPFindingsResponse, OWASPStatsResponse } from '../../api/owasp';
import { CategoryDistributionChart } from './CategoryDistributionChart';
import { OwaspDrilldownView } from './OwaspDrilldownView';
import { Shield, RefreshCw, Layers, AlertTriangle } from 'lucide-react';

interface OwaspRiskDashboardProps {
  scanId: number;
}

export const OwaspRiskDashboard: React.FC<OwaspRiskDashboardProps> = ({ scanId }) => {
  const [findingsData, setFindingsData] = useState<OWASPFindingsResponse | null>(null);
  const [statsData, setStatsData] = useState<OWASPStatsResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [selectedCategoryCode, setSelectedCategoryCode] = useState<string>('A01');

  const fetchData = async () => {
    setLoading(true);
    try {
      const [fRes, sRes] = await Promise.all([
        getOwaspFindingsApi(scanId),
        getOwaspStatsApi(scanId),
      ]);
      setFindingsData(fRes);
      setStatsData(sRes);
      if (fRes.categories && fRes.categories.length > 0) {
        const topCat = fRes.categories.find((c) => c.count > 0) || fRes.categories[0];
        setSelectedCategoryCode(topCat.code);
      }
    } catch (err) {
      console.error('Failed to fetch OWASP mapping data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [scanId]);

  const selectedCategoryGroup =
    findingsData?.categories.find((c) => c.code === selectedCategoryCode) || null;

  return (
    <div className="space-y-6 font-sans">
      {/* OWASP Header Banner */}
      <div className="glass-card p-6 rounded-3xl border border-white/10 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-2xl bg-cyber-purple/10 border border-cyber-purple/30 text-cyber-purple shadow-glow-purple">
            <Layers className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-lg font-bold font-display text-slate-100">
              OWASP Top 10 2021 Mapping Dashboard
            </h2>
            <p className="text-xs font-mono text-slate-400">
              Automated classification & severity breakdown for Scan #{scanId}
            </p>
          </div>
        </div>

        <button
          onClick={fetchData}
          disabled={loading}
          className="px-4 py-2 rounded-2xl bg-white/5 border border-white/10 hover:border-cyber-cyan/40 text-slate-300 text-xs font-mono flex items-center space-x-2 transition-all disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-cyber-cyan' : ''}`} />
          <span>Refresh Mapping</span>
        </button>
      </div>

      {loading ? (
        <div className="glass-card p-12 rounded-3xl border border-white/10 text-center space-y-3 font-mono">
          <div className="w-8 h-8 border-2 border-cyber-purple border-t-transparent rounded-full animate-spin mx-auto" />
          <div className="text-xs text-slate-400">Categorizing findings into OWASP Top 10 (A01-A10)...</div>
        </div>
      ) : findingsData && statsData ? (
        <>
          {/* Quick Metrics Bar */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 font-mono">
            <div className="p-4 rounded-2xl bg-white/[0.03] border border-white/10 text-xs space-y-1">
              <div className="text-slate-500 uppercase text-[10px]">Total Mapped Findings</div>
              <div className="text-slate-100 font-bold text-base">
                {statsData.total_mapped_findings} Findings Evaluated
              </div>
            </div>

            <div className="p-4 rounded-2xl bg-white/[0.03] border border-white/10 text-xs space-y-1">
              <div className="text-slate-500 uppercase text-[10px]">Highest Risk Category</div>
              <div className="text-cyber-rose font-bold text-base truncate">
                {statsData.top_vulnerable_category}
              </div>
            </div>

            <div className="p-4 rounded-2xl bg-white/[0.03] border border-white/10 text-xs space-y-1">
              <div className="text-slate-500 uppercase text-[10px]">Categories Triggered</div>
              <div className="text-cyber-cyan font-bold text-base">
                {findingsData.categories.filter((c) => c.count > 0).length} / 10 OWASP Categories
              </div>
            </div>
          </div>

          {/* Interactive Visual Dashboard Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            <div className="lg:col-span-5">
              <CategoryDistributionChart
                categories={findingsData.categories}
                selectedCategory={selectedCategoryCode}
                onSelectCategory={(code) => setSelectedCategoryCode(code)}
              />
            </div>

            <div className="lg:col-span-7">
              <OwaspDrilldownView category={selectedCategoryGroup} />
            </div>
          </div>
        </>
      ) : null}
    </div>
  );
};
