import React, { useState, useEffect } from 'react';
import {
  getFindingsApi,
  updateFindingStatusApi,
  Finding,
  FindingStatusType
} from '../api/findings';
import { explainVulnerabilityApi, AIExplanation } from '../api/ai';
import { ExpandableFindings } from '../components/ai/ExpandableFindings';
import {
  ShieldAlert,
  AlertCircle,
  CheckCircle2,
  Search,
  Filter,
  RefreshCw,
  Sparkles,
  ShieldCheck,
  Award,
  Layers,
  X,
  BookOpen,
  Cpu,
  TrendingUp,
  FileText,
  ChevronRight
} from 'lucide-react';
import { motion } from 'framer-motion';

export const FindingsDashboard: React.FC = () => {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const [severityFilter, setSeverityFilter] = useState<string>('All');
  const [statusFilter, setStatusFilter] = useState<string>('All');
  const [searchQuery, setSearchQuery] = useState<string>('');

  const [aiModalOpen, setAiModalOpen] = useState<boolean>(false);
  const [aiFinding, setAiFinding] = useState<Finding | null>(null);
  const [aiExplanation, setAiExplanation] = useState<AIExplanation | null>(null);
  const [aiLoading, setAiLoading] = useState<boolean>(false);

  const fetchFindings = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getFindingsApi(severityFilter, statusFilter);
      setFindings(data);
    } catch (err: any) {
      console.error('Failed to fetch findings:', err);
      setError('Could not load vulnerability findings from database.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFindings();
  }, [severityFilter, statusFilter]);

  const handleOpenAiModal = async (finding: Finding) => {
    setAiFinding(finding);
    setAiModalOpen(true);
    setAiLoading(true);
    setAiExplanation(null);
    try {
      const data = await explainVulnerabilityApi(finding.id);
      setAiExplanation(data);
    } catch (err) {
      console.error('Failed to generate AI explanation:', err);
    } finally {
      setAiLoading(false);
    }
  };

  const handleStatusChange = async (findingId: number, newStatus: FindingStatusType) => {
    try {
      const updated = await updateFindingStatusApi(findingId, newStatus);
      setFindings((prev) => prev.map((f) => (f.id === findingId ? updated : f)));
    } catch (err) {
      console.error('Failed to update status:', err);
    }
  };

  const filteredFindings = findings.filter((f) => {
    const matchesSearch =
      f.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.affected_url.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (f.cve_id && f.cve_id.toLowerCase().includes(searchQuery.toLowerCase()));
    return matchesSearch;
  });

  return (
    <div className="space-y-8 font-sans">
      
      {/* Header Banner */}
      <div className="glass-card p-6 rounded-3xl border border-white/10 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-2xl bg-cyber-purple/10 border border-cyber-purple/30 text-cyber-purple shadow-glow-purple">
            <Layers className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-xl font-bold font-display text-slate-100">Findings Triage & Lifecycle Matrix</h1>
            <p className="text-xs font-mono text-slate-400">High-density vulnerability triage workspace with instant status updates</p>
          </div>
        </div>

        <button
          onClick={fetchFindings}
          className="p-2.5 rounded-2xl bg-white/5 border border-white/10 hover:border-white/20 text-slate-300 transition-colors font-mono"
          title="Refresh Findings"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-cyber-cyan' : ''}`} />
        </button>
      </div>

      {/* Filters Bar */}
      <div className="glass-card p-4 rounded-3xl border border-white/10 flex flex-col md:flex-row md:items-center justify-between gap-4 font-mono text-xs">
        <div className="flex items-center space-x-2 bg-black/40 p-1 rounded-2xl border border-white/10 overflow-x-auto">
          {['All', 'Critical', 'High', 'Medium', 'Low'].map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={`px-3.5 py-1.5 rounded-xl font-bold transition-all ${
                severityFilter === sev
                  ? 'bg-cyber-purple/20 text-cyber-purple border border-cyber-purple/40 shadow-glow-purple/20'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {sev}
            </button>
          ))}
        </div>

        <div className="relative w-full md:w-80">
          <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
            <Search className="w-4 h-4" />
          </div>
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search Findings..."
            className="w-full pl-10 pr-4 py-2.5 rounded-2xl bg-white/[0.03] border border-white/10 focus:border-cyber-purple text-xs text-slate-200 placeholder-slate-500 outline-none font-mono"
          />
        </div>
      </div>

      {/* Expandable Interactive Findings Accordion List with Gemini AI Advisory */}
      <ExpandableFindings findings={filteredFindings} />

    </div>
  );
};

