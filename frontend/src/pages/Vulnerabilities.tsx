import React, { useState, useEffect } from 'react';
import {
  getFindingsApi,
  updateFindingStatusApi,
  importSarifApi,
  Finding,
  FindingStatusType
} from '../api/findings';
import { explainVulnerabilityApi, AIExplanation } from '../api/ai';
import {
  ShieldAlert,
  AlertCircle,
  CheckCircle2,
  Clock,
  ExternalLink,
  Search,
  RefreshCw,
  FileJson,
  Upload,
  X,
  Sparkles,
  ShieldCheck,
  BookOpen,
  Cpu,
  TrendingUp,
  Award,
  Layers,
  Code,
  ChevronRight,
  Shield,
  Activity
} from 'lucide-react';
import { motion } from 'framer-motion';

export const Vulnerabilities: React.FC = () => {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const [severityFilter, setSeverityFilter] = useState<string>('All');
  const [statusFilter, setStatusFilter] = useState<string>('All');
  const [searchQuery, setSearchQuery] = useState<string>('');

  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [updatingStatus, setUpdatingStatus] = useState<boolean>(false);

  // AI Modal State
  const [aiModalOpen, setAiModalOpen] = useState<boolean>(false);
  const [aiFinding, setAiFinding] = useState<Finding | null>(null);
  const [aiExplanation, setAiExplanation] = useState<AIExplanation | null>(null);
  const [aiLoading, setAiLoading] = useState<boolean>(false);

  // Import Modal State
  const [importModalOpen, setImportModalOpen] = useState<boolean>(false);
  const [importJsonText, setImportJsonText] = useState<string>(`{
  "tool_name": "Trivy Container & Dependency Audit",
  "findings": [
    {
      "title": "SQL Injection in User Authentication Route",
      "description": "Unsanitized user payload in query concatenation allows authentication bypass.",
      "severity": "Critical",
      "cvss_score": 9.1,
      "cve_id": "OWASP-A03-2021",
      "affected_url": "https://auth.company.internal/login",
      "remediation_guidance": "Use parameterized queries or SQLAlchemy ORM session binding."
    }
  ]
}`);
  const [importing, setImporting] = useState<boolean>(false);

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

  const handleStatusChange = async (findingId: number, newStatus: FindingStatusType) => {
    setUpdatingStatus(true);
    try {
      const updated = await updateFindingStatusApi(findingId, newStatus);
      setFindings((prev) => prev.map((f) => (f.id === findingId ? updated : f)));
      if (selectedFinding && selectedFinding.id === findingId) {
        setSelectedFinding(updated);
      }
    } catch (err) {
      console.error('Failed to update status:', err);
    } finally {
      setUpdatingStatus(false);
    }
  };

  const handleOpenAiModal = async (finding: Finding) => {
    setAiFinding(finding);
    setAiModalOpen(true);
    setAiExplanation(null);
    setAiLoading(true);

    try {
      const result = await explainVulnerabilityApi(finding.id);
      setAiExplanation(result);
    } catch (err) {
      console.error('AI Advisory generation failed:', err);
    } finally {
      setAiLoading(false);
    }
  };

  const handleImportSarif = async (e: React.FormEvent) => {
    e.preventDefault();
    setImporting(true);
    try {
      const parsed = JSON.parse(importJsonText);
      await importSarifApi(parsed);
      setImportModalOpen(false);
      fetchFindings();
    } catch (err: any) {
      alert(err?.response?.data?.detail || err?.message || 'Failed to parse or ingest SARIF report JSON.');
    } finally {
      setImporting(false);
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
      
      {/* Top Header Banner */}
      <div className="glass-card p-6 rounded-3xl border border-white/10 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-2xl bg-cyber-rose/10 border border-cyber-rose/30 text-cyber-rose shadow-glow-rose/20">
            <ShieldAlert className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-xl font-bold font-display text-slate-100">Threat Intelligence & Vulnerability Center</h1>
            <p className="text-xs font-mono text-slate-400">Triage vulnerability findings, inspect CVSS scores, and generate 6-section Gemini AI advisories</p>
          </div>
        </div>

        <div className="flex items-center space-x-3 font-mono">
          <button
            onClick={() => setImportModalOpen(true)}
            className="px-4 py-2.5 rounded-2xl bg-white/5 border border-white/10 hover:border-cyber-cyan/40 text-slate-300 hover:text-white text-xs flex items-center space-x-2 transition-all"
          >
            <FileJson className="w-4 h-4 text-cyber-cyan" />
            <span>Import Audit (SARIF)</span>
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="glass-card p-4 rounded-3xl border border-white/10 flex flex-col md:flex-row md:items-center justify-between gap-4 font-mono text-xs">
        
        {/* Severity Filters */}
        <div className="flex items-center space-x-1.5 bg-black/40 p-1 rounded-2xl border border-white/10 overflow-x-auto">
          {['All', 'Critical', 'High', 'Medium', 'Low'].map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={`px-3.5 py-1.5 rounded-xl font-bold transition-all ${
                severityFilter === sev
                  ? sev === 'Critical'
                    ? 'bg-cyber-rose/20 text-cyber-rose border border-cyber-rose/40 shadow-glow-rose/20'
                    : 'bg-cyber-cyan/20 text-cyber-cyan border border-cyber-cyan/40 shadow-glow-cyan/20'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {sev}
            </button>
          ))}
        </div>

        {/* Search Input */}
        <div className="relative w-full md:w-80">
          <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
            <Search className="w-4 h-4" />
          </div>
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Filter by title, CVE ID, URL..."
            className="w-full pl-10 pr-4 py-2.5 rounded-2xl bg-white/[0.03] border border-white/10 focus:border-cyber-cyan text-xs text-slate-200 placeholder-slate-500 outline-none font-mono"
          />
        </div>

      </div>

      {/* Findings Grid */}
      {loading ? (
        <div className="glass-card p-16 rounded-3xl border border-white/10 text-center space-y-3 font-mono">
          <div className="w-8 h-8 border-2 border-cyber-cyan border-t-transparent rounded-full animate-spin mx-auto" />
          <div className="text-xs text-slate-400">Querying threat intelligence database...</div>
        </div>
      ) : error ? (
        <div className="glass-card p-8 rounded-3xl border border-cyber-rose/30 text-center text-cyber-rose text-xs font-mono space-y-2">
          <AlertCircle className="w-6 h-6 mx-auto" />
          <div>{error}</div>
        </div>
      ) : filteredFindings.length === 0 ? (
        <div className="glass-card p-16 rounded-3xl border border-white/10 text-center space-y-3 font-mono">
          <ShieldCheck className="w-10 h-10 text-cyber-emerald mx-auto" />
          <div className="text-slate-200 font-bold font-display text-base">No Matching Vulnerabilities</div>
          <p className="text-xs text-slate-400 font-sans max-w-sm mx-auto">
            Zero findings match your severity filter or search parameters.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {filteredFindings.map((finding) => (
            <motion.div
              key={finding.id}
              whileHover={{ y: -4 }}
              className="glass-card p-6 rounded-3xl border border-white/10 space-y-4 relative overflow-hidden flex flex-col justify-between"
            >
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2 font-mono">
                    <span
                      className={`px-3 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider border ${
                        finding.severity === 'Critical'
                          ? 'bg-cyber-rose/20 text-cyber-rose border-cyber-rose/40 shadow-glow-rose/20'
                          : finding.severity === 'High'
                          ? 'bg-cyber-amber/20 text-cyber-amber border-cyber-amber/40'
                          : 'bg-cyber-cyan/20 text-cyber-cyan border-cyber-cyan/40'
                      }`}
                    >
                      {finding.severity} • {finding.cvss_score ? `CVSS ${finding.cvss_score}` : 'CVSS N/A'}
                    </span>
                    {finding.cve_id && (
                      <span className="text-[10px] text-slate-400 font-bold">{finding.cve_id}</span>
                    )}
                  </div>

                  <span
                    className={`px-2.5 py-0.5 rounded-full text-[10px] font-mono font-semibold border ${
                      finding.status === 'Resolved'
                        ? 'bg-cyber-emerald/10 text-cyber-emerald border-cyber-emerald/30'
                        : 'bg-white/5 text-slate-400 border-white/10'
                    }`}
                  >
                    {finding.status}
                  </span>
                </div>

                <h3 className="text-base font-bold font-display text-slate-100">{finding.title}</h3>
                <p className="text-xs font-sans text-slate-400 leading-relaxed line-clamp-2">{finding.description}</p>

                <div className="p-3 rounded-2xl bg-black/40 border border-white/10 text-[11px] font-mono text-slate-300 truncate">
                  Scope: {finding.affected_url}
                </div>
              </div>

              <div className="pt-4 border-t border-white/10 flex items-center justify-between font-mono text-xs">
                <button
                  onClick={() => setSelectedFinding(finding)}
                  className="text-slate-400 hover:text-white underline"
                >
                  View Details
                </button>

                <button
                  onClick={() => handleOpenAiModal(finding)}
                  className="px-4 py-2 rounded-2xl bg-cyber-purple/20 hover:bg-cyber-purple/30 text-cyber-purple border border-cyber-purple/40 font-bold flex items-center space-x-1.5 shadow-glow-purple/20 transition-all"
                >
                  <Sparkles className="w-4 h-4 text-cyber-purple" />
                  <span>AI Advisory</span>
                </button>
              </div>
            </motion.div>
          ))}
        </div>
      )}

      {/* 6-Section Gemini AI Security Advisory Modal */}
      {aiModalOpen && aiFinding && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4">
          <div className="w-full max-w-3xl glass-card p-6 sm:p-8 rounded-3xl border border-cyber-purple/40 shadow-2xl space-y-6 relative max-h-[90vh] overflow-y-auto">
            
            <div className="flex items-center justify-between border-b border-white/10 pb-4">
              <div className="flex items-center space-x-3 font-mono">
                <div className="p-2 rounded-2xl bg-cyber-purple/20 border border-cyber-purple/40 text-cyber-purple shadow-glow-purple">
                  <Sparkles className="w-6 h-6 animate-pulse" />
                </div>
                <div>
                  <div className="font-bold text-xs uppercase text-cyber-purple tracking-widest">Gemini AI Security Advisory</div>
                  <h3 className="text-lg font-bold font-display text-slate-100">{aiFinding.title}</h3>
                </div>
              </div>

              <button
                onClick={() => setAiModalOpen(false)}
                className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-white/5"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {aiLoading ? (
              <div className="py-16 text-center space-y-3 font-mono">
                <div className="w-8 h-8 border-2 border-cyber-purple border-t-transparent rounded-full animate-spin mx-auto" />
                <div className="text-xs text-slate-300 font-bold">Synthesizing 6-Section Security Advisory with Gemini API...</div>
              </div>
            ) : aiExplanation ? (
              <div className="space-y-6 text-xs font-sans">
                
                {/* OWASP Badge */}
                <div className="p-3.5 rounded-2xl bg-cyber-cyan/10 border border-cyber-cyan/30 text-cyber-cyan font-mono text-xs font-bold flex items-center space-x-2">
                  <Award className="w-4 h-4" />
                  <span>OWASP Classification: {aiExplanation.owasp_mapping}</span>
                </div>

                {/* 1. Executive Summary */}
                <div className="space-y-1.5">
                  <div className="text-xs font-mono text-slate-300 uppercase font-bold flex items-center space-x-1.5">
                    <Shield className="w-4 h-4 text-cyber-cyan" />
                    <span>1. Executive Summary</span>
                  </div>
                  <div className="p-4 rounded-2xl bg-white/[0.03] border border-white/10 text-slate-300 leading-relaxed">
                    {aiExplanation.executive_summary}
                  </div>
                </div>

                {/* 2. Technical Root Cause */}
                <div className="space-y-1.5">
                  <div className="text-xs font-mono text-slate-300 uppercase font-bold flex items-center space-x-1.5">
                    <Code className="w-4 h-4 text-cyber-purple" />
                    <span>2. Technical Root Cause</span>
                  </div>
                  <div className="p-4 rounded-2xl bg-white/[0.03] border border-white/10 text-slate-300 leading-relaxed">
                    {aiExplanation.technical_description}
                  </div>
                </div>

                {/* 3. Business Impact */}
                <div className="space-y-1.5">
                  <div className="text-xs font-mono text-slate-300 uppercase font-bold flex items-center space-x-1.5">
                    <TrendingUp className="w-4 h-4 text-cyber-rose" />
                    <span>3. Business Impact</span>
                  </div>
                  <div className="p-4 rounded-2xl bg-white/[0.03] border border-white/10 text-slate-300 leading-relaxed">
                    {aiExplanation.business_impact}
                  </div>
                </div>

                {/* 4. Attack Scenario */}
                <div className="space-y-1.5">
                  <div className="text-xs font-mono text-slate-300 uppercase font-bold flex items-center space-x-1.5">
                    <Activity className="w-4 h-4 text-cyber-amber" />
                    <span>4. Conceptual Attack Scenario</span>
                  </div>
                  <div className="p-4 rounded-2xl bg-white/[0.03] border border-white/10 text-slate-300 leading-relaxed font-mono text-[11px]">
                    {aiExplanation.attack_scenario}
                  </div>
                </div>

                {/* 5. Remediation Guidance */}
                <div className="space-y-1.5">
                  <div className="text-xs font-mono text-cyber-emerald uppercase font-bold flex items-center space-x-1.5">
                    <BookOpen className="w-4 h-4" />
                    <span>5. Developer Fix Guidance</span>
                  </div>
                  <div className="p-4 rounded-2xl bg-black/50 border border-cyber-emerald/30 text-cyber-emerald font-mono text-xs leading-relaxed">
                    {aiExplanation.remediation_guidance}
                  </div>
                </div>

              </div>
            ) : (
              <div className="py-8 text-center text-cyber-rose font-mono text-xs">Failed to load AI payload.</div>
            )}

          </div>
        </div>
      )}

      {/* Standard Finding Detail Modal */}
      {selectedFinding && !aiModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4">
          <div className="w-full max-w-2xl glass-card p-6 sm:p-8 rounded-3xl border border-white/10 shadow-2xl space-y-6 relative max-h-[90vh] overflow-y-auto">
            
            <div className="flex items-center justify-between border-b border-white/10 pb-4 font-mono">
              <div className="space-y-1">
                <div className="flex items-center space-x-2">
                  <span className="px-3 py-1 rounded-full bg-cyber-rose/20 text-cyber-rose border border-cyber-rose/40 text-xs font-bold">
                    {selectedFinding.severity} • {selectedFinding.cvss_score ? `CVSS ${selectedFinding.cvss_score}` : 'CVSS N/A'}
                  </span>
                  <span className="text-xs text-slate-400 font-bold">{selectedFinding.cve_id}</span>
                </div>
                <h3 className="text-lg font-bold font-display text-slate-100">{selectedFinding.title}</h3>
              </div>

              <button
                onClick={() => setSelectedFinding(null)}
                className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-white/5"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-4 text-xs font-sans">
              <div>
                <label className="block font-mono text-slate-500 uppercase font-bold text-[10px]">Affected Target Scope</label>
                <div className="text-slate-200 font-mono mt-1 p-3 rounded-2xl bg-black/40 border border-white/10">
                  {selectedFinding.affected_url}
                </div>
              </div>

              <div>
                <label className="block font-mono text-slate-500 uppercase font-bold text-[10px]">Vulnerability Description</label>
                <p className="text-slate-300 leading-relaxed mt-1 p-4 rounded-2xl bg-white/[0.03] border border-white/10">
                  {selectedFinding.description}
                </p>
              </div>

              <div>
                <label className="block font-mono text-cyber-emerald uppercase font-bold text-[10px]">Remediation Guidance</label>
                <div className="text-slate-200 font-mono mt-1 p-4 rounded-2xl bg-black/40 border border-cyber-emerald/30 leading-relaxed text-[#00ff9d]">
                  {selectedFinding.remediation_guidance}
                </div>
              </div>

              <div className="pt-3 border-t border-white/10 flex flex-col sm:flex-row items-center justify-between gap-3 font-mono">
                <button
                  onClick={() => {
                    const f = selectedFinding;
                    setSelectedFinding(null);
                    handleOpenAiModal(f);
                  }}
                  className="px-4 py-2.5 rounded-2xl bg-cyber-purple/20 text-cyber-purple border border-cyber-purple/40 font-bold text-xs flex items-center space-x-2 shadow-glow-purple/20"
                >
                  <Sparkles className="w-4 h-4 text-cyber-purple" />
                  <span>Generate Full AI Security Advisory</span>
                </button>

                <div className="flex items-center space-x-2">
                  {(['Open', 'In Review', 'Resolved', 'False Positive'] as const).map((st) => (
                    <button
                      key={st}
                      disabled={updatingStatus}
                      onClick={() => handleStatusChange(selectedFinding.id, st)}
                      className={`px-3 py-1.5 rounded-xl text-xs font-bold transition-all border ${
                        selectedFinding.status === st
                          ? 'bg-cyber-cyan text-slate-950 border-cyber-cyan'
                          : 'bg-white/5 text-slate-400 border-white/10 hover:text-white'
                      }`}
                    >
                      {st}
                    </button>
                  ))}
                </div>
              </div>
            </div>

          </div>
        </div>
      )}

      {/* SARIF Report Import Modal */}
      {importModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4 font-mono">
          <div className="w-full max-w-xl glass-card p-6 rounded-3xl border border-cyber-cyan/40 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <div className="flex items-center space-x-2">
                <FileJson className="w-5 h-5 text-cyber-cyan" />
                <h3 className="font-bold font-display text-slate-100 text-base">Import Security Audit Report</h3>
              </div>
              <button
                onClick={() => setImportModalOpen(false)}
                className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-white/5"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleImportSarif} className="space-y-4 text-xs">
              <textarea
                rows={8}
                value={importJsonText}
                onChange={(e) => setImportJsonText(e.target.value)}
                className="w-full p-4 rounded-2xl bg-black/50 border border-white/10 text-cyber-cyan font-mono outline-none"
              />

              <div className="flex justify-end space-x-3">
                <button
                  type="button"
                  onClick={() => setImportModalOpen(false)}
                  className="px-4 py-2.5 rounded-2xl bg-white/5 text-slate-300 text-xs"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={importing}
                  className="px-5 py-2.5 rounded-2xl bg-cyber-cyan text-slate-950 font-bold text-xs uppercase shadow-glow-cyan flex items-center space-x-2"
                >
                  {importing ? <span>Importing...</span> : <span>Ingest Audit Payload</span>}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

    </div>
  );
};
