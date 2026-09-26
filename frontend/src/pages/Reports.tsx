import React, { useState, useEffect } from 'react';
import {
  generateReportApi,
  downloadReportByIdApi,
  getReportsListApi,
  deleteReportApi,
  deleteBulkReportsApi,
  ReportItem,
  ReportProfile
} from '../api/reports';
import { getScanHistoryApi, Scan } from '../api/scans';
import {
  FileText,
  Download,
  Shield,
  Zap,
  Sparkles,
  Plus,
  Trash2,
  Target,
  AlertCircle
} from 'lucide-react';
import { motion } from 'framer-motion';

export const Reports: React.FC = () => {
  const [reports, setReports] = useState<ReportItem[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [downloading, setDownloading] = useState<boolean>(false);
  const [generating, setGenerating] = useState<boolean>(false);
  const [selectedScanId, setSelectedScanId] = useState<number | null>(null);
  const [selectedProfile, setSelectedProfile] = useState<ReportProfile>('standard');
  
  // Selection state for delete feature
  const [selectedReportIds, setSelectedReportIds] = useState<(number | string)[]>([]);
  const [deleting, setDeleting] = useState<boolean>(false);

  const fetchReportsAndScans = async () => {
    setLoading(true);
    try {
      const [reportsData, scansData] = await Promise.all([
        getReportsListApi(),
        getScanHistoryApi()
      ]);
      setReports(reportsData);
      setScans(scansData);
      if (scansData.length > 0) {
        setSelectedScanId(scansData[0].id);
      }
    } catch (err) {
      console.error('Failed to load reports & scans:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReportsAndScans();
  }, []);

  const handleGenerateReport = async (profileToGen?: ReportProfile) => {
    const profile = profileToGen || selectedProfile;
    if (!selectedScanId) {
      alert('No scanned target selected. Please run a target scan first.');
      return;
    }
    setGenerating(true);
    try {
      const newReport = await generateReportApi(selectedScanId, profile);
      setReports((prev) => [newReport, ...prev]);
      await downloadReportByIdApi(newReport.id, newReport.report_type);
    } catch (err: any) {
      console.error('Failed to generate report:', err);
      const detail = err.response?.data?.detail || 'Failed to generate report for selected scan.';
      alert(detail);
    } finally {
      setGenerating(false);
    }
  };

  const handleDownload = async (reportId: string | number, reportType: string) => {
    setDownloading(true);
    try {
      await downloadReportByIdApi(reportId, reportType);
    } catch (err) {
      console.error('PDF download error:', err);
    } finally {
      setDownloading(false);
    }
  };

  const handleToggleSelectReport = (id: number | string) => {
    setSelectedReportIds((prev) =>
      prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]
    );
  };

  const handleDeleteSingleReport = async (reportId: number | string) => {
    if (!window.confirm(`Are you sure you want to delete report #${reportId}?`)) return;
    setDeleting(true);
    try {
      await deleteReportApi(reportId);
      setReports((prev) => prev.filter((r) => r.id !== reportId && r.report_id_str !== reportId));
      setSelectedReportIds((prev) => prev.filter((item) => item !== reportId));
    } catch (err) {
      console.error('Failed to delete report:', err);
      alert('Failed to delete report artifact.');
    } finally {
      setDeleting(false);
    }
  };

  const handleDeleteBulkReports = async () => {
    if (selectedReportIds.length === 0) return;
    if (!window.confirm(`Are you sure you want to delete ${selectedReportIds.length} selected reports?`)) return;
    setDeleting(true);
    try {
      await deleteBulkReportsApi(selectedReportIds);
      setReports((prev) => prev.filter((r) => !selectedReportIds.includes(r.id) && !selectedReportIds.includes(r.report_id_str)));
      setSelectedReportIds([]);
    } catch (err) {
      console.error('Failed to bulk delete reports:', err);
      alert('Failed to delete selected reports.');
    } finally {
      setDeleting(false);
    }
  };

  const profilesConfig = [
    {
      key: 'quick' as ReportProfile,
      name: 'Quick Recon Audit Report',
      targetAudience: 'Managers, Clients & C-Suite Stakeholders',
      pagesEst: '5–10 Pages',
      purpose: 'Executive Security Snapshot',
      icon: Zap,
      color: 'text-cyber-cyan',
      border: 'border-cyber-cyan/40 bg-cyber-cyan/5',
      sections: [
        '1. Cover Page', '2. Executive Summary', '3. Target Scope', '4. DNS Analysis',
        '5. SSL/TLS Certificate Review', '6. Security Header Analysis', '7. Tech Stack Detection',
        '8. Asset Health Score', '9. Quick Recommendations'
      ]
    },
    {
      key: 'standard' as ReportProfile,
      name: 'Standard Vulnerability Audit Report',
      targetAudience: 'Security Teams, Developers & Tech Leads',
      pagesEst: '15–30 Pages',
      purpose: 'OWASP Vulnerability Assessment',
      icon: Shield,
      color: 'text-cyber-emerald',
      border: 'border-cyber-emerald/40 bg-cyber-emerald/5',
      sections: [
        '1. Cover Page', '2. Executive Summary', '3. Scope & Rules', '4. Recon Findings',
        '5. OWASP Top 10 Mappings', '6. Vulnerability Summary', '7. CVSS Risk Matrix',
        '8. Technical Findings Breakdown', '9. Evidence Summaries', '10. Remediation Guidance',
        '11. Security Score', '12. Audit Sign-Off'
      ]
    },
    {
      key: 'full' as ReportProfile,
      name: 'Full Autonomous Pentest Report',
      targetAudience: 'CISOs, Consultants & Enterprise Auditors',
      pagesEst: '40–80 Pages',
      purpose: 'Enterprise Penetration Testing Audit',
      icon: Sparkles,
      color: 'text-cyber-purple',
      border: 'border-cyber-purple/40 bg-cyber-purple/5',
      sections: [
        '1. Cover Page', '2. Letter of Engagement', '3. Executive Overview', '4. Methodology',
        '5. Scope & Rules', '6. Technical Recon', '7. Enumeration', '8. Attack Surface Topology',
        '9. Vulnerability Assessment', '10. Exploitation Validation', '11. MITRE ATT&CK Mapping',
        '12. Gemini AI Root Cause', '13. Security Score Core', '14. Enterprise Risk Heatmap',
        '15. Business Impact', '16. 90-Day Remediation Roadmap', '17. Raw Appendix'
      ]
    }
  ];

  return (
    <div className="space-y-8 font-sans">
      
      {/* Header Banner */}
      <div className="glass-card p-6 rounded-3xl border border-white/10 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-2xl bg-cyber-cyan/10 border border-cyber-cyan/30 text-cyber-cyan shadow-glow-cyan">
            <FileText className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-xl font-bold font-display text-slate-100">Adaptive PDF Report Generation Engine</h1>
            <p className="text-xs font-mono text-slate-400">Generate PDF audit reports exclusively from your executed target scans</p>
          </div>
        </div>

        <button
          onClick={() => handleGenerateReport()}
          disabled={generating || !selectedScanId}
          className="px-5 py-3 rounded-2xl bg-gradient-to-r from-cyber-cyan to-cyber-purple hover:opacity-90 text-slate-950 font-mono font-bold text-xs uppercase tracking-wider transition-all shadow-glow-cyan flex items-center justify-center space-x-2 disabled:opacity-50"
        >
          {generating ? (
            <>
              <div className="w-3.5 h-3.5 border-2 border-slate-950 border-t-transparent rounded-full animate-spin" />
              <span>COMPILING ADAPTIVE PDF...</span>
            </>
          ) : (
            <>
              <Plus className="w-4 h-4" />
              <span>Generate {selectedProfile.toUpperCase()} PDF Report</span>
            </>
          )}
        </button>
      </div>

      {/* Target Scan Scope Selection Bar */}
      <div className="glass-card p-5 rounded-3xl border border-white/10 space-y-3 font-mono">
        <div className="flex items-center space-x-2 text-xs font-bold text-slate-200">
          <Target className="w-4 h-4 text-cyber-cyan" />
          <span>Select Scanned Target Scope for PDF Generation:</span>
        </div>

        {scans.length === 0 ? (
          <div className="p-3 rounded-2xl bg-white/[0.02] border border-white/10 text-xs text-slate-400 flex items-center space-x-2">
            <AlertCircle className="w-4 h-4 text-cyber-amber" />
            <span>No target scans found. Please deploy a scan in <b>New Scan</b> first to generate PDF reports.</span>
          </div>
        ) : (
          <div className="flex flex-col sm:flex-row items-center gap-3">
            <select
              value={selectedScanId || ''}
              onChange={(e) => setSelectedScanId(Number(e.target.value))}
              className="w-full sm:w-auto flex-1 px-4 py-2.5 rounded-2xl bg-black/50 border border-white/10 focus:border-cyber-cyan text-xs text-slate-200 outline-none font-mono"
            >
              {scans.map((s) => (
                <option key={s.id} value={s.id} className="bg-slate-900 text-slate-200">
                  Scan #{s.id} — {s.target_url} ({s.scan_type} Profile • {s.status})
                </option>
              ))}
            </select>
            <span className="text-[11px] text-slate-400 font-sans">
              Selected target scan ID #{selectedScanId}
            </span>
          </div>
        )}
      </div>

      {/* Profile Selection Cards */}
      <div className="space-y-4 font-sans">
        <h3 className="text-sm font-bold font-display text-slate-100 uppercase tracking-wider font-mono">
          Select Adaptive Report Profile
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
          {profilesConfig.map((p) => {
            const Icon = p.icon;
            const isSelected = selectedProfile === p.key;
            return (
              <motion.div
                key={p.key}
                whileHover={{ y: -4 }}
                onClick={() => setSelectedProfile(p.key)}
                className={`p-6 rounded-3xl border cursor-pointer transition-all flex flex-col justify-between space-y-4 ${
                  isSelected ? p.border : 'border-white/10 bg-white/[0.02] text-slate-400 hover:border-white/20'
                }`}
              >
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <div className={`p-2 rounded-xl border ${isSelected ? 'bg-white/10 border-white/20' : 'bg-white/5 border-white/10'}`}>
                      <Icon className={`w-5 h-5 ${p.color}`} />
                    </div>
                    <span className="text-[10px] font-mono uppercase font-bold tracking-wider px-2 py-0.5 rounded-full bg-black/40 border border-white/10 text-slate-300">
                      {p.pagesEst}
                    </span>
                  </div>

                  <h4 className="font-bold font-display text-slate-100 text-base">{p.name}</h4>
                  <div className="text-xs text-slate-400 font-sans">{p.purpose}</div>

                  <div className="pt-2 border-t border-white/10 space-y-1 text-xs font-mono">
                    <div className="text-[10px] text-slate-500">Target Audience:</div>
                    <div className="text-slate-300 font-semibold text-[11px]">{p.targetAudience}</div>
                  </div>

                  <div className="space-y-1 text-[10px] font-mono text-slate-400 pt-2 border-t border-white/5">
                    <div className="text-slate-500 uppercase font-bold">Key Included Sections:</div>
                    {p.sections.slice(0, 5).map((sec) => (
                      <div key={sec} className="truncate text-slate-300">{sec}</div>
                    ))}
                    {p.sections.length > 5 && (
                      <div className="text-cyber-cyan font-bold">+ {p.sections.length - 5} More Sections...</div>
                    )}
                  </div>
                </div>

                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    setSelectedProfile(p.key);
                    handleGenerateReport(p.key);
                  }}
                  disabled={generating || !selectedScanId}
                  className={`w-full py-2.5 px-3 rounded-xl font-mono font-bold text-xs uppercase tracking-wider transition-all flex items-center justify-center space-x-1.5 ${
                    isSelected
                      ? 'bg-cyber-cyan text-slate-950 shadow-glow-cyan'
                      : 'bg-white/5 text-slate-300 hover:bg-white/10 border border-white/10'
                  }`}
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Generate & Download ({p.pagesEst})</span>
                </button>
              </motion.div>
            );
          })}
        </div>
      </div>

      {/* Generated Report Packages Table / Grid */}
      <div className="space-y-4 font-sans pt-4 border-t border-white/10">
        <div className="flex items-center justify-between font-mono">
          <div className="flex items-center space-x-3">
            <h3 className="text-sm font-bold font-display text-slate-100 uppercase tracking-wider">
              Saved Report Artifacts
            </h3>
            <span className="text-xs text-slate-400">{reports.length} Reports</span>
          </div>

          {/* Bulk Delete Reports Button */}
          {selectedReportIds.length > 0 && (
            <motion.button
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              onClick={handleDeleteBulkReports}
              disabled={deleting}
              className="px-4 py-2 rounded-2xl bg-cyber-rose/20 border border-cyber-rose/50 text-cyber-rose hover:bg-cyber-rose hover:text-white font-bold text-xs uppercase tracking-wider transition-all flex items-center space-x-1.5"
            >
              <Trash2 className="w-4 h-4" />
              <span>Delete Selected ({selectedReportIds.length})</span>
            </motion.button>
          )}
        </div>

        {loading ? (
          <div className="p-12 text-center font-mono text-xs text-slate-400">
            Fetching available PDF report artifacts...
          </div>
        ) : reports.length === 0 ? (
          <div className="glass-card p-12 rounded-3xl border border-white/10 text-center space-y-3 font-mono">
            <FileText className="w-10 h-10 text-slate-600 mx-auto" />
            <div className="text-slate-200 font-bold text-base font-display">No Reports Generated Yet</div>
            <p className="text-xs text-slate-400 max-w-sm mx-auto font-sans">
              Select one of your scanned targets above and click <b>Generate & Download</b> to compile your first executive PDF report.
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            {reports.map((rep) => {
              const repId = rep.id || rep.report_id_str;
              const isSelected = selectedReportIds.includes(repId);
              return (
                <motion.div
                  key={repId}
                  whileHover={{ y: -4 }}
                  className={`glass-card p-6 rounded-3xl border transition-all flex flex-col justify-between space-y-4 ${
                    isSelected ? 'border-cyber-cyan/50 bg-cyber-cyan/5' : 'border-white/10'
                  }`}
                >
                  <div className="space-y-3 font-mono">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2.5">
                        <input
                          type="checkbox"
                          checked={isSelected}
                          onChange={() => handleToggleSelectReport(repId)}
                          className="rounded border-white/20 bg-white/5 text-cyber-cyan focus:ring-0 cursor-pointer"
                        />
                        <span className="px-2.5 py-0.5 text-[10px] bg-cyber-purple/10 text-cyber-purple border border-cyber-purple/30 rounded-full font-bold">
                          {rep.report_id_str || `REP-${rep.id}`}
                        </span>
                      </div>

                      <div className="flex items-center space-x-2">
                        <span className="px-2.5 py-0.5 text-[10px] bg-cyber-cyan/10 text-cyber-cyan border border-cyber-cyan/30 rounded-full font-bold">
                          {rep.report_type || 'Standard'} Profile ({rep.pages || 15} Pgs)
                        </span>

                        <button
                          onClick={() => handleDeleteSingleReport(repId)}
                          className="p-1 rounded-lg hover:bg-cyber-rose/20 text-slate-500 hover:text-cyber-rose transition-colors"
                          title="Delete Report Artifact"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>

                    <h4 className="font-bold text-slate-100 text-base font-display leading-tight">
                      {rep.title}
                    </h4>

                    <div className="p-3 rounded-2xl bg-black/40 border border-white/10 text-xs space-y-1">
                      <div className="text-slate-400 truncate">
                        <span className="text-slate-500">Target Scope:</span> {rep.target_url}
                      </div>
                      <div className="text-slate-400">
                        <span className="text-slate-500">Scan Task:</span> Task #{rep.scan_id || 1}
                      </div>
                    </div>
                  </div>

                  <button
                    onClick={() => handleDownload(repId, rep.report_type || 'Security')}
                    disabled={downloading}
                    className="w-full py-3 px-4 rounded-2xl bg-white/5 hover:bg-white/10 text-cyber-cyan font-mono font-bold text-xs uppercase tracking-wider transition-all border border-white/10 flex items-center justify-center space-x-2"
                  >
                    <Download className="w-4 h-4" />
                    <span>Download {rep.report_type || 'PDF'} Document ({rep.pages || 15} Pgs)</span>
                  </button>
                </motion.div>
              );
            })}
          </div>
        )}
      </div>

    </div>
  );
};
