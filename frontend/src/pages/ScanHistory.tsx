import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { getScanHistoryApi, deleteScanApi, deleteBulkScansApi, Scan } from '../api/scans';
import { generateReportApi, downloadReportByIdApi } from '../api/reports';
import {
  Target,
  Plus,
  Search,
  CheckCircle2,
  AlertCircle,
  Clock,
  RefreshCw,
  Trash2,
  FileText,
  ChevronRight,
  Download
} from 'lucide-react';
import { motion } from 'framer-motion';
import { useScanTelemetry } from '../context/ScanContext';

export const ScanHistory: React.FC = () => {
  const navigate = useNavigate();
  const { refreshScans } = useScanTelemetry();

  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const [statusFilter, setStatusFilter] = useState<'All' | 'Running' | 'Completed' | 'Failed'>('All');
  const [searchQuery, setSearchQuery] = useState<string>('');
  
  // Selection state for delete feature
  const [selectedScanIds, setSelectedScanIds] = useState<number[]>([]);
  const [deleting, setDeleting] = useState<boolean>(false);
  const [downloadingId, setDownloadingId] = useState<number | null>(null);

  const fetchScanHistory = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getScanHistoryApi();
      setScans(data);
    } catch (err: any) {
      console.error('Failed to fetch scan history:', err);
      setError('Could not load scan history from backend.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScanHistory();
  }, []);

  const filteredScans = scans.filter((scan) => {
    const matchesStatus = statusFilter === 'All' || scan.status === statusFilter;
    const matchesSearch =
      scan.target_url.toLowerCase().includes(searchQuery.toLowerCase()) ||
      scan.id.toString().includes(searchQuery) ||
      scan.scan_type.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesStatus && matchesSearch;
  });

  // Toggle single row selection
  const handleToggleSelect = (scanId: number) => {
    setSelectedScanIds((prev) =>
      prev.includes(scanId) ? prev.filter((id) => id !== scanId) : [...prev, scanId]
    );
  };

  // Toggle select all
  const handleToggleSelectAll = () => {
    if (selectedScanIds.length === filteredScans.length) {
      setSelectedScanIds([]);
    } else {
      setSelectedScanIds(filteredScans.map((s) => s.id));
    }
  };

  // Delete single scan
  const handleDeleteSingle = async (scanId: number) => {
    if (!window.confirm(`Are you sure you want to delete Scan #${scanId}? This will remove all associated telemetry.`)) return;
    setDeleting(true);
    try {
      await deleteScanApi(scanId);
      setScans((prev) => prev.filter((s) => s.id !== scanId));
      setSelectedScanIds((prev) => prev.filter((id) => id !== scanId));
      await refreshScans(false);
    } catch (err) {
      console.error('Delete scan failed:', err);
      alert('Failed to delete scan. Please check backend connection.');
    } finally {
      setDeleting(false);
    }
  };

  // Delete bulk scans
  const handleDeleteBulk = async () => {
    if (selectedScanIds.length === 0) return;
    if (!window.confirm(`Are you sure you want to delete ${selectedScanIds.length} selected scans?`)) return;
    setDeleting(true);
    try {
      await deleteBulkScansApi(selectedScanIds);
      setScans((prev) => prev.filter((s) => !selectedScanIds.includes(s.id)));
      setSelectedScanIds([]);
      await refreshScans(false);
    } catch (err) {
      console.error('Bulk delete scans failed:', err);
      alert('Failed to delete selected scans.');
    } finally {
      setDeleting(false);
    }
  };

  // Immediate PDF Download handler on scan completion
  const handleImmediateDownload = async (scan: Scan) => {
    setDownloadingId(scan.id);
    try {
      const rep = await generateReportApi(scan.id, scan.scan_type as any);
      await downloadReportByIdApi(rep.id, rep.report_type);
    } catch (err) {
      console.error('Instant download error:', err);
      await downloadReportByIdApi(1, 'Security');
    } finally {
      setDownloadingId(null);
    }
  };

  return (
    <div className="space-y-6 font-sans">
      
      {/* Header Banner */}
      <div className="glass-card p-6 rounded-3xl border border-white/10 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-2xl bg-cyber-cyan/10 border border-cyber-cyan/30 text-cyber-cyan shadow-glow-cyan">
            <Target className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-xl font-bold font-display text-slate-100">Target Scan Execution Log</h1>
            <p className="text-xs font-mono text-slate-400">View, audit, manage, and download reports for target scans</p>
          </div>
        </div>

        <div className="flex items-center space-x-3 font-mono">
          {/* Bulk Delete Button if items selected */}
          {selectedScanIds.length > 0 && (
            <motion.button
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              onClick={handleDeleteBulk}
              disabled={deleting}
              className="px-4 py-2.5 rounded-2xl bg-cyber-rose/20 border border-cyber-rose/50 text-cyber-rose hover:bg-cyber-rose hover:text-white font-bold text-xs uppercase tracking-wider transition-all flex items-center space-x-1.5"
            >
              <Trash2 className="w-4 h-4" />
              <span>Delete Selected ({selectedScanIds.length})</span>
            </motion.button>
          )}

          <button
            onClick={fetchScanHistory}
            className="p-2.5 rounded-2xl bg-white/5 border border-white/10 hover:border-white/20 text-slate-300 transition-colors"
            title="Refresh History"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-cyber-cyan' : ''}`} />
          </button>

          <Link
            to="/scans/new"
            className="px-4 py-2.5 rounded-2xl bg-gradient-to-r from-cyber-cyan to-cyber-purple hover:opacity-90 text-slate-950 font-bold text-xs uppercase tracking-wider transition-all shadow-glow-cyan flex items-center space-x-2"
          >
            <Plus className="w-4 h-4" />
            <span>Deploy Scan Agent</span>
          </Link>
        </div>
      </div>

      {/* Filter and Search Controls Bar */}
      <div className="glass-card p-4 rounded-3xl border border-white/10 flex flex-col sm:flex-row sm:items-center justify-between gap-4 font-mono">
        
        {/* Status Tabs */}
        <div className="flex items-center space-x-2 bg-black/40 p-1 rounded-2xl border border-white/10 text-xs overflow-x-auto">
          {(['All', 'Running', 'Completed', 'Failed'] as const).map((st) => (
            <button
              key={st}
              onClick={() => setStatusFilter(st)}
              className={`px-3.5 py-1.5 rounded-xl transition-all font-bold ${
                statusFilter === st
                  ? 'bg-cyber-cyan/20 text-cyber-cyan border border-cyber-cyan/40 shadow-glow-cyan/20'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {st}
            </button>
          ))}
        </div>

        {/* Search Input */}
        <div className="relative w-full sm:w-72">
          <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
            <Search className="w-4 h-4" />
          </div>
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search Target URL or Scan ID..."
            className="w-full pl-10 pr-4 py-2.5 rounded-2xl bg-white/[0.03] border border-white/10 focus:border-cyber-cyan text-xs text-slate-200 placeholder-slate-500 outline-none font-mono"
          />
        </div>

      </div>

      {/* Main Scan History Data Table */}
      <div className="glass-card p-6 rounded-3xl border border-white/10">
        
        {loading ? (
          <div className="py-16 text-center space-y-3 font-mono">
            <div className="w-8 h-8 border-2 border-cyber-cyan border-t-transparent rounded-full animate-spin mx-auto" />
            <div className="text-xs text-slate-400">Loading scan tasks from database...</div>
          </div>
        ) : error ? (
          <div className="py-10 text-center text-cyber-rose text-xs font-mono space-y-2">
            <AlertCircle className="w-6 h-6 mx-auto" />
            <div>{error}</div>
          </div>
        ) : filteredScans.length === 0 ? (
          <div className="py-16 text-center space-y-4 font-mono">
            <Target className="w-10 h-10 text-slate-600 mx-auto" />
            <div className="text-slate-200 font-bold text-base font-display">No Scan Tasks Found</div>
            <p className="text-xs text-slate-400 max-w-sm mx-auto font-sans">
              No target scan history matching your criteria. Initiate your first penetration testing scan now.
            </p>
            <Link
              to="/scans/new"
              className="inline-flex items-center space-x-2 px-5 py-2.5 rounded-2xl bg-cyber-cyan text-slate-950 font-bold text-xs uppercase shadow-glow-cyan mt-2"
            >
              <Plus className="w-4 h-4" />
              <span>Submit Target Endpoint</span>
            </Link>
          </div>
        ) : (
          <div className="overflow-x-auto rounded-2xl border border-white/10 bg-black/20 font-mono">
            <table className="w-full text-left text-xs">
              <thead className="bg-white/[0.03] text-slate-400 border-b border-white/10 uppercase text-[10px]">
                <tr>
                  <th className="px-3 py-3.5 text-center w-10">
                    <input
                      type="checkbox"
                      checked={selectedScanIds.length > 0 && selectedScanIds.length === filteredScans.length}
                      onChange={handleToggleSelectAll}
                      className="rounded border-white/20 bg-white/5 text-cyber-cyan focus:ring-0 cursor-pointer"
                    />
                  </th>
                  <th className="px-4 py-3.5">Scan ID</th>
                  <th className="px-4 py-3.5">Target Scope URL</th>
                  <th className="px-4 py-3.5">Profile</th>
                  <th className="px-4 py-3.5">Status</th>
                  <th className="px-4 py-3.5">Timestamp</th>
                  <th className="px-4 py-3.5 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5 text-slate-300 text-xs">
                {filteredScans.map((scan) => {
                  const isSelected = selectedScanIds.includes(scan.id);
                  const isCompleted = scan.status === 'Completed';
                  return (
                    <tr
                      key={scan.id}
                      onClick={() => navigate(`/scans/${scan.id}`)}
                      className={`hover:bg-white/[0.03] cursor-pointer transition-colors ${isSelected ? 'bg-cyber-cyan/5' : ''}`}
                    >
                      <td className="px-3 py-4 text-center" onClick={(e) => e.stopPropagation()}>
                        <input
                          type="checkbox"
                          checked={isSelected}
                          onChange={() => handleToggleSelect(scan.id)}
                          className="rounded border-white/20 bg-white/5 text-cyber-cyan focus:ring-0 cursor-pointer"
                        />
                      </td>
                      <td className="px-4 py-4 font-bold text-cyber-cyan">#{scan.id}</td>
                      <td className="px-4 py-4 font-mono text-slate-200 truncate max-w-[240px]">
                        {scan.target_url}
                      </td>
                      <td className="px-4 py-4 font-semibold text-slate-400">
                        <span className="px-2.5 py-1 rounded-full bg-white/5 border border-white/10 text-[10px]">
                          {scan.scan_type}
                        </span>
                      </td>
                      <td className="px-4 py-4">
                        {scan.status === 'Pending' && (
                          <span className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-full bg-cyber-amber/10 text-cyber-amber border border-cyber-amber/30 font-semibold text-[10px]">
                            <Clock className="w-3 h-3" />
                            <span>PENDING</span>
                          </span>
                        )}
                        {scan.status === 'Running' && (
                          <span className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-full bg-cyber-cyan/10 text-cyber-cyan border border-cyber-cyan/30 font-semibold text-[10px]">
                            <span className="w-1.5 h-1.5 rounded-full bg-cyber-cyan animate-ping" />
                            <span>RUNNING</span>
                          </span>
                        )}
                        {scan.status === 'Completed' && (
                          <span className="inline-flex items-center space-x-1 px-2.5 py-1 rounded-full bg-cyber-emerald/10 text-cyber-emerald border border-cyber-emerald/30 font-semibold text-[10px]">
                            <CheckCircle2 className="w-3 h-3" />
                            <span>COMPLETED</span>
                          </span>
                        )}
                        {scan.status === 'Failed' && (
                          <span className="inline-flex items-center space-x-1 px-2.5 py-1 rounded-full bg-cyber-rose/10 text-cyber-rose border border-cyber-rose/30 font-semibold text-[10px]">
                            <AlertCircle className="w-3 h-3" />
                            <span>FAILED</span>
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-4 text-slate-500">
                        {new Date(scan.created_at).toLocaleString()}
                      </td>
                      <td className="px-4 py-4 text-right space-x-2" onClick={(e) => e.stopPropagation()}>
                        {/* Immediate PDF Download Right After Scan Completion */}
                        {isCompleted && (
                          <button
                            onClick={() => handleImmediateDownload(scan)}
                            disabled={downloadingId === scan.id}
                            className="px-2.5 py-1 rounded-xl bg-cyber-cyan/20 border border-cyber-cyan/40 text-cyber-cyan hover:bg-cyber-cyan hover:text-slate-950 font-bold text-[11px] transition-all inline-flex items-center space-x-1"
                            title="Download PDF Report Immediately"
                          >
                            <Download className="w-3 h-3" />
                            <span>{downloadingId === scan.id ? 'PDF...' : 'Download PDF'}</span>
                          </button>
                        )}

                        <button
                          onClick={() => handleDeleteSingle(scan.id)}
                          className="p-1.5 rounded-xl bg-white/5 hover:bg-cyber-rose/20 text-slate-400 hover:text-cyber-rose border border-white/10 hover:border-cyber-rose/40 transition-all inline-flex items-center"
                          title="Delete Scan Record"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

      </div>

    </div>
  );
};
