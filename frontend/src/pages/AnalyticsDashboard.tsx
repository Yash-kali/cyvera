import React, { useState, useEffect } from 'react';
import { NavLink } from 'react-router-dom';
import {
  getAnalyticsOverviewApi,
  AnalyticsOverview,
  AnalyticsFilters
} from '../api/analytics';
import {
  BarChart3,
  Filter,
  RefreshCw,
  TrendingUp,
  ShieldCheck,
  Calendar,
  Zap,
  Target,
  ShieldAlert,
  Layers,
  AlertCircle,
  PlusCircle,
  Clock,
  Activity
} from 'lucide-react';
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  AreaChart,
  Area
} from 'recharts';

export const AnalyticsDashboard: React.FC = () => {
  const [data, setData] = useState<AnalyticsOverview | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Multi-Parameter Filter States
  const [severityFilter, setSeverityFilter] = useState<string>('All');
  const [scanTypeFilter, setScanTypeFilter] = useState<string>('All');
  const [dateRangeFilter, setDateRangeFilter] = useState<string>('30d');
  const [statusFilter, setStatusFilter] = useState<string>('All');

  const fetchAnalytics = async () => {
    setLoading(true);
    setError(null);
    try {
      const filters: AnalyticsFilters = {
        severity: severityFilter,
        scan_type: scanTypeFilter,
        date_range: dateRangeFilter,
        status: statusFilter
      };
      const overview = await getAnalyticsOverviewApi(filters);
      setData(overview);
    } catch (err: any) {
      console.error('Failed to load analytics overview:', err);
      setError(err?.response?.data?.detail || 'Failed to load security telemetry from server.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAnalytics();
  }, [severityFilter, scanTypeFilter, dateRangeFilter, statusFilter]);

  // Derive dynamic Severity Pie Data directly from real backend state
  const severityPieData = React.useMemo(() => {
    if (!data || !data.severity_distribution) return [];
    const dist = data.severity_distribution;
    const items = [
      { name: 'Critical', value: dist.Critical || 0, color: '#ff2a6d' },
      { name: 'High', value: dist.High || 0, color: '#ffb800' },
      { name: 'Medium', value: dist.Medium || 0, color: '#00f0ff' },
      { name: 'Low', value: dist.Low || 0, color: '#7000ff' },
      { name: 'Info', value: dist.Info || 0, color: '#3b82f6' }
    ];
    // Filter out 0 counts so donut chart doesn't render empty slice fragments
    const active = items.filter((d) => d.value > 0);
    return active.length > 0 ? active : [];
  }, [data]);

  // Derive dynamic Scan Profile Data
  const scanProfileData = React.useMemo(() => {
    if (!data || !data.scan_profile_distribution) return [];
    const prof = data.scan_profile_distribution;
    return [
      { name: 'Quick', count: prof.Quick || 0, fill: '#00f0ff' },
      { name: 'Standard', count: prof.Standard || 0, fill: '#7000ff' },
      { name: 'Full', count: prof.Full || 0, fill: '#ff2a6d' }
    ];
  }, [data]);

  // Derive OWASP distribution directly from backend
  const owaspData = React.useMemo(() => {
    if (!data || !data.owasp_distribution) return [];
    return data.owasp_distribution.map((item) => ({
      code: item.code,
      name: item.name,
      count: item.count
    }));
  }, [data]);

  // Check whether user has completely empty state under current scope
  const isCompletelyEmpty = !loading && data && data.total_scans === 0 && data.total_findings === 0;

  return (
    <div className="space-y-8 font-sans">
      
      {/* Header Banner */}
      <div className="glass-card p-6 rounded-3xl border border-white/10 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-2xl bg-cyber-purple/10 border border-cyber-purple/30 text-cyber-purple shadow-glow-purple">
            <BarChart3 className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-xl font-bold font-display text-slate-100">Security Analytics Command Dashboard</h1>
            <p className="text-xs font-mono text-slate-400">Database-driven vulnerability metrics, Recharts visual telemetry & multi-filter intelligence</p>
          </div>
        </div>

        <div className="flex items-center space-x-3">
          <NavLink
            to="/analytics/risk"
            className="px-4 py-2 rounded-xl bg-white/5 border border-white/10 text-xs font-mono text-slate-300 hover:text-white hover:border-cyber-cyan/40 transition-colors flex items-center space-x-1.5"
          >
            <Zap className="w-3.5 h-3.5 text-cyber-cyan" />
            <span>Risk Assessment Engine</span>
          </NavLink>

          <button
            onClick={fetchAnalytics}
            className="p-2.5 rounded-2xl bg-white/5 border border-white/10 text-slate-300 hover:text-white transition-colors font-mono"
            title="Refresh Analytics"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-cyber-cyan' : ''}`} />
          </button>
        </div>
      </div>

      {/* Filter Controls Bar */}
      <div className="glass-card p-4 rounded-3xl border border-white/10 flex flex-col gap-4 font-mono text-xs">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2 text-slate-300 uppercase tracking-wider font-bold">
            <Filter className="w-4 h-4 text-cyber-cyan" />
            <span>Multi-Parameter Telemetry Filters:</span>
          </div>
          {(severityFilter !== 'All' || scanTypeFilter !== 'All' || dateRangeFilter !== '30d' || statusFilter !== 'All') && (
            <button
              onClick={() => {
                setSeverityFilter('All');
                setScanTypeFilter('All');
                setDateRangeFilter('30d');
                setStatusFilter('All');
              }}
              className="text-[10px] text-cyber-rose hover:underline"
            >
              Reset Filters
            </button>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {/* Severity Filter */}
          <div className="flex items-center space-x-1 bg-black/40 p-1 rounded-2xl border border-white/10">
            <span className="text-[10px] text-slate-500 uppercase px-2 font-mono">Severity:</span>
            {['All', 'Critical', 'High', 'Medium', 'Low', 'Info'].map((sev) => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={`px-2.5 py-1 rounded-xl transition-all font-bold text-[11px] ${
                  severityFilter === sev
                    ? 'bg-cyber-cyan/20 text-cyber-cyan border border-cyber-cyan/40'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>

          {/* Scan Type Filter */}
          <div className="flex items-center space-x-1 bg-black/40 p-1 rounded-2xl border border-white/10">
            <span className="text-[10px] text-slate-500 uppercase px-2 font-mono">Profile:</span>
            {['All', 'Quick', 'Standard', 'Full'].map((type) => (
              <button
                key={type}
                onClick={() => setScanTypeFilter(type)}
                className={`px-2.5 py-1 rounded-xl transition-all font-bold text-[11px] ${
                  scanTypeFilter === type
                    ? 'bg-cyber-purple/20 text-cyber-purple border border-cyber-purple/40'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {type}
              </button>
            ))}
          </div>

          {/* Date Range Filter */}
          <div className="flex items-center space-x-1 bg-black/40 p-1 rounded-2xl border border-white/10">
            <span className="text-[10px] text-slate-500 uppercase px-2 font-mono">Window:</span>
            {[
              { label: '7 Days', val: '7d' },
              { label: '30 Days', val: '30d' },
              { label: '90 Days', val: '90d' },
              { label: 'All Time', val: 'all' }
            ].map((d) => (
              <button
                key={d.val}
                onClick={() => setDateRangeFilter(d.val)}
                className={`px-2.5 py-1 rounded-xl transition-all font-bold text-[11px] ${
                  dateRangeFilter === d.val
                    ? 'bg-cyber-emerald/20 text-cyber-emerald border border-cyber-emerald/40'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {d.label}
              </button>
            ))}
          </div>

          {/* Status Filter */}
          <div className="flex items-center space-x-1 bg-black/40 p-1 rounded-2xl border border-white/10">
            <span className="text-[10px] text-slate-500 uppercase px-2 font-mono">Status:</span>
            {['All', 'Completed', 'Running', 'Failed'].map((st) => (
              <button
                key={st}
                onClick={() => setStatusFilter(st)}
                className={`px-2.5 py-1 rounded-xl transition-all font-bold text-[11px] ${
                  statusFilter === st
                    ? 'bg-amber-400/20 text-amber-300 border border-amber-400/40'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {st}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Error Alert */}
      {error && (
        <div className="p-4 rounded-2xl bg-cyber-rose/10 border border-cyber-rose/30 text-cyber-rose flex items-center justify-between font-mono text-xs">
          <div className="flex items-center space-x-2">
            <AlertCircle className="w-4 h-4 flex-shrink-0" />
            <span>{error}</span>
          </div>
          <button onClick={fetchAnalytics} className="underline hover:text-white">Retry</button>
        </div>
      )}

      {/* KPI Cards Summary Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
        
        {/* Card 1: Total Scans */}
        <div className="glass-card p-5 rounded-2xl border border-white/10 hover:border-cyber-cyan/40 transition-all font-mono">
          <div className="flex items-center justify-between">
            <span className="text-[11px] text-slate-400 uppercase tracking-wider font-semibold">Total Scans Executed</span>
            <Target className="w-4 h-4 text-cyber-cyan" />
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <span className="text-3xl font-bold text-slate-100 font-sans">
              {data ? data.total_scans : 0}
            </span>
            <span className="text-xs text-cyber-cyan font-semibold">
              {data ? `${data.completed_scans} Completed` : '0 Completed'}
            </span>
          </div>
          <div className="mt-2 text-[10px] text-slate-500 flex items-center space-x-2">
            <span>Running: {data ? data.running_scans : 0}</span>
            <span>•</span>
            <span>Failed: {data ? data.failed_scans : 0}</span>
          </div>
        </div>

        {/* Card 2: Active Findings */}
        <div className="glass-card p-5 rounded-2xl border border-white/10 hover:border-cyber-rose/40 transition-all font-mono">
          <div className="flex items-center justify-between">
            <span className="text-[11px] text-slate-400 uppercase tracking-wider font-semibold">Vulnerability Findings</span>
            <ShieldAlert className="w-4 h-4 text-cyber-rose" />
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <span className="text-3xl font-bold text-slate-100 font-sans">
              {data ? data.total_findings : 0}
            </span>
            <span className="px-2 py-0.5 text-[10px] rounded bg-cyber-rose/10 text-cyber-rose border border-cyber-rose/30 font-bold">
              {data ? `${data.critical_findings} Critical` : '0 Critical'}
            </span>
          </div>
          <div className="mt-2 text-[10px] text-slate-500">
            High: {data ? data.high_findings : 0} | Med: {data ? data.medium_findings : 0} | Low: {data ? data.low_findings : 0}
          </div>
        </div>

        {/* Card 3: Security Score */}
        <div className="glass-card p-5 rounded-2xl border border-white/10 hover:border-cyber-emerald/40 transition-all font-mono">
          <div className="flex items-center justify-between">
            <span className="text-[11px] text-slate-400 uppercase tracking-wider font-semibold">Security Health Score</span>
            <ShieldCheck className="w-4 h-4 text-cyber-emerald" />
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <span className="text-3xl font-bold text-cyber-emerald font-sans">
              {data && data.total_scans > 0 ? `${data.security_score}` : '--'} <span className="text-sm text-slate-500">/ 100</span>
            </span>
            <span className="px-2 py-0.5 text-[10px] rounded bg-cyber-emerald/10 text-cyber-emerald border border-cyber-emerald/30 font-bold">
              {data && data.total_scans > 0 ? data.grade : 'STANDBY'}
            </span>
          </div>
          <div className="mt-2 text-[10px] text-slate-500">
            Risk Impact: {data ? data.risk_score : 0.0} / 100
          </div>
        </div>

        {/* Card 4: SLA Compliance Rate */}
        <div className="glass-card p-5 rounded-2xl border border-white/10 hover:border-cyber-purple/40 transition-all font-mono">
          <div className="flex items-center justify-between">
            <span className="text-[11px] text-slate-400 uppercase tracking-wider font-semibold">Remediation SLA Rate</span>
            <Zap className="w-4 h-4 text-cyber-purple" />
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <span className="text-3xl font-bold text-cyber-purple font-sans">
              {data ? `${data.sla_compliance_rate}%` : '--'}
            </span>
            <span className="px-2 py-0.5 text-[10px] rounded bg-cyber-purple/10 text-cyber-purple border border-cyber-purple/30 font-bold">
              {data && data.sla_compliance_rate >= 80 ? 'OPTIMAL' : 'REVIEW'}
            </span>
          </div>
          <div className="mt-2 text-[10px] text-slate-500">
            Open: {data ? data.open_findings : 0} | Fixed: {data ? data.resolved_findings : 0}
          </div>
        </div>

      </div>

      {/* Honest Empty State Banner when 0 records exist */}
      {isCompletelyEmpty ? (
        <div className="glass-card p-12 rounded-3xl border border-white/10 text-center space-y-4 font-mono">
          <div className="w-16 h-16 rounded-3xl bg-cyber-cyan/10 border border-cyber-cyan/30 text-cyber-cyan mx-auto flex items-center justify-center">
            <Activity className="w-8 h-8" />
          </div>
          <h2 className="text-lg font-bold font-sans text-slate-200">No Scan Telemetry Available</h2>
          <p className="text-xs text-slate-400 max-w-md mx-auto leading-relaxed">
            No scans or vulnerability findings have been recorded for your account under the active filter parameters. Execute an automated security audit to generate real-time analytics.
          </p>
          <div className="pt-2">
            <NavLink
              to="/scans/new"
              className="inline-flex items-center space-x-2 px-5 py-2.5 rounded-2xl bg-cyber-cyan text-black font-bold text-xs hover:bg-cyber-cyan/90 shadow-glow-cyan transition-all"
            >
              <PlusCircle className="w-4 h-4" />
              <span>Launch Target Scan</span>
            </NavLink>
          </div>
        </div>
      ) : (
        <>
          {/* Charts Row 1: Severity Pie & Scan Profile Bar */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            
            {/* Severity Distribution Pie Chart */}
            <div className="glass-card p-6 rounded-3xl border border-white/10 space-y-4 font-mono">
              <div className="flex items-center justify-between border-b border-white/10 pb-3">
                <div>
                  <h3 className="text-base font-bold font-display text-slate-100">Severity Distribution</h3>
                  <p className="text-xs text-slate-400">Database-backed risk breakdown by severity tier</p>
                </div>
                <span className="text-[10px] px-2.5 py-1 rounded-full bg-white/5 border border-white/10 text-slate-400">
                  {data ? data.total_findings : 0} Findings
                </span>
              </div>

              <div className="h-64 w-full flex items-center justify-center">
                {severityPieData.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={severityPieData}
                        cx="50%"
                        cy="50%"
                        innerRadius={60}
                        outerRadius={85}
                        paddingAngle={5}
                        dataKey="value"
                      >
                        {severityPieData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#0b101d',
                          borderColor: 'rgba(255,255,255,0.1)',
                          borderRadius: '12px',
                          color: '#fff',
                          fontFamily: 'monospace',
                          fontSize: '12px'
                        }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="text-slate-500 text-xs text-center">
                    No severity findings matching active filters.
                  </div>
                )}
              </div>

              {/* Dynamic Legend Cards */}
              <div className="grid grid-cols-5 gap-2 text-center text-[11px]">
                {[
                  { name: 'Critical', val: data?.severity_distribution?.Critical || 0, color: '#ff2a6d' },
                  { name: 'High', val: data?.severity_distribution?.High || 0, color: '#ffb800' },
                  { name: 'Medium', val: data?.severity_distribution?.Medium || 0, color: '#00f0ff' },
                  { name: 'Low', val: data?.severity_distribution?.Low || 0, color: '#7000ff' },
                  { name: 'Info', val: data?.severity_distribution?.Info || 0, color: '#3b82f6' },
                ].map((d) => (
                  <div key={d.name} className="p-2 rounded-xl bg-white/[0.03] border border-white/5">
                    <div className="text-slate-400 text-[10px]">{d.name}</div>
                    <div className="font-bold font-display text-slate-100 text-sm" style={{ color: d.color }}>{d.val}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* Scan Profile Distribution Bar Chart */}
            <div className="glass-card p-6 rounded-3xl border border-white/10 space-y-4 font-mono">
              <div className="flex items-center justify-between border-b border-white/10 pb-3">
                <div>
                  <h3 className="text-base font-bold font-display text-slate-100">Scan Profile Distribution</h3>
                  <p className="text-xs text-slate-400">Audit volume across Quick, Standard, and Full profiles</p>
                </div>
                <span className="text-[10px] px-2.5 py-1 rounded-full bg-white/5 border border-white/10 text-slate-400">
                  {data ? data.total_scans : 0} Scans
                </span>
              </div>

              <div className="h-64 w-full flex items-center justify-center">
                {scanProfileData.some(d => d.count > 0) ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={scanProfileData} margin={{ top: 20, right: 20, left: -20, bottom: 5 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                      <XAxis dataKey="name" stroke="#64748b" tick={{ fill: '#94a3b8', fontSize: 11 }} />
                      <YAxis stroke="#64748b" tick={{ fill: '#94a3b8', fontSize: 11 }} allowDecimals={false} />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#0b101d',
                          borderColor: 'rgba(255,255,255,0.1)',
                          borderRadius: '12px',
                          color: '#fff',
                          fontFamily: 'monospace',
                          fontSize: '12px'
                        }}
                      />
                      <Bar dataKey="count" radius={[8, 8, 0, 0]}>
                        {scanProfileData.map((entry, index) => (
                          <Cell key={`bar-${index}`} fill={entry.fill} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="text-slate-500 text-xs text-center">
                    No scan profiles executed matching active filters.
                  </div>
                )}
              </div>

              <div className="grid grid-cols-3 gap-2 text-center text-[11px]">
                {scanProfileData.map((p) => (
                  <div key={p.name} className="p-2 rounded-xl bg-white/[0.03] border border-white/5">
                    <div className="text-slate-400 text-[10px]">{p.name} Scans</div>
                    <div className="font-bold font-display text-slate-100 text-sm" style={{ color: p.fill }}>{p.count}</div>
                  </div>
                ))}
              </div>
            </div>

          </div>

          {/* Charts Row 2: Chronological Activity Trends & OWASP Top 10 Distribution */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

            {/* Chronological Trends Over Time */}
            <div className="glass-card p-6 rounded-3xl border border-white/10 space-y-4 font-mono">
              <div className="flex items-center justify-between border-b border-white/10 pb-3">
                <div className="flex items-center space-x-2">
                  <TrendingUp className="w-4 h-4 text-cyber-cyan" />
                  <div>
                    <h3 className="text-base font-bold font-display text-slate-100">Telemetry Trends Over Time</h3>
                    <p className="text-xs text-slate-400">Historical vulnerability detections and scan activity</p>
                  </div>
                </div>
              </div>

              <div className="h-64 w-full flex items-center justify-center">
                {data?.trend_data && data.trend_data.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={data.trend_data} margin={{ top: 10, right: 20, left: -20, bottom: 0 }}>
                      <defs>
                        <linearGradient id="findingsGrad" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#ff2a6d" stopOpacity={0.4}/>
                          <stop offset="95%" stopColor="#ff2a6d" stopOpacity={0}/>
                        </linearGradient>
                        <linearGradient id="scansGrad" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#00f0ff" stopOpacity={0.4}/>
                          <stop offset="95%" stopColor="#00f0ff" stopOpacity={0}/>
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                      <XAxis dataKey="date" stroke="#64748b" tick={{ fill: '#94a3b8', fontSize: 10 }} />
                      <YAxis stroke="#64748b" tick={{ fill: '#94a3b8', fontSize: 10 }} allowDecimals={false} />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#0b101d',
                          borderColor: 'rgba(255,255,255,0.1)',
                          borderRadius: '12px',
                          color: '#fff',
                          fontFamily: 'monospace',
                          fontSize: '12px'
                        }}
                      />
                      <Area type="monotone" dataKey="findings" stroke="#ff2a6d" fillOpacity={1} fill="url(#findingsGrad)" name="Findings" />
                      <Area type="monotone" dataKey="scans" stroke="#00f0ff" fillOpacity={1} fill="url(#scansGrad)" name="Scans" />
                    </AreaChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="text-slate-500 text-xs text-center">
                    No time-series scan activity recorded for this period.
                  </div>
                )}
              </div>
            </div>

            {/* OWASP Top 10 Distribution */}
            <div className="glass-card p-6 rounded-3xl border border-white/10 space-y-4 font-mono">
              <div className="flex items-center justify-between border-b border-white/10 pb-3">
                <div className="flex items-center space-x-2">
                  <Layers className="w-4 h-4 text-cyber-purple" />
                  <div>
                    <h3 className="text-base font-bold font-display text-slate-100">OWASP Top 10 Classification</h3>
                    <p className="text-xs text-slate-400">Classified finding counts mapped to OWASP 2021 categories</p>
                  </div>
                </div>
              </div>

              <div className="h-64 w-full flex items-center justify-center">
                {owaspData.some(d => d.count > 0) ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart
                      layout="vertical"
                      data={owaspData.filter(d => d.count > 0)}
                      margin={{ top: 10, right: 30, left: 20, bottom: 5 }}
                    >
                      <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                      <XAxis type="number" stroke="#64748b" tick={{ fill: '#94a3b8', fontSize: 10 }} allowDecimals={false} />
                      <YAxis type="category" dataKey="code" stroke="#64748b" tick={{ fill: '#94a3b8', fontSize: 10 }} />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#0b101d',
                          borderColor: 'rgba(255,255,255,0.1)',
                          borderRadius: '12px',
                          color: '#fff',
                          fontFamily: 'monospace',
                          fontSize: '12px'
                        }}
                      />
                      <Bar dataKey="count" fill="#a855f7" radius={[0, 6, 6, 0]} name="Findings Count" />
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="text-slate-500 text-xs text-center">
                    No OWASP category findings recorded.
                  </div>
                )}
              </div>
            </div>

          </div>

          {/* Domain Risk Ratings Table */}
          <div className="glass-card p-6 rounded-3xl border border-white/10 space-y-4">
            <div className="flex items-center justify-between border-b border-white/10 pb-3 font-mono">
              <div>
                <h3 className="text-base font-bold font-display text-slate-100">Target Asset Risk Index</h3>
                <p className="text-xs text-slate-400">Calculated domain risk scores & health ratings from actual findings</p>
              </div>
              <span className="text-[10px] px-2.5 py-1 rounded-full bg-white/5 border border-white/10 text-slate-400">
                {data?.asset_risks?.length || 0} Targets Evaluated
              </span>
            </div>

            <div className="space-y-3 font-mono text-xs">
              {data?.asset_risks && data.asset_risks.length > 0 ? (
                data.asset_risks.map((item) => (
                  <div key={item.target_url} className="p-4 rounded-2xl bg-white/[0.03] border border-white/10 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <div className="space-y-1">
                      <div className="font-bold text-slate-200">{item.target_url}</div>
                      <div className="text-[10px] text-slate-400">
                        Findings: {item.total_findings} Total ({item.critical_count} Critical, {item.high_count} High)
                      </div>
                    </div>

                    <div className="flex items-center space-x-4">
                      <div className="text-right">
                        <span
                          className={`px-3 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider border ${
                            item.risk_rating === 'HIGH_RISK'
                              ? 'bg-cyber-rose/20 text-cyber-rose border-cyber-rose/40'
                              : item.risk_rating === 'MEDIUM_RISK'
                              ? 'bg-amber-400/20 text-amber-300 border-amber-400/40'
                              : 'bg-cyber-emerald/20 text-cyber-emerald border-cyber-emerald/40'
                          }`}
                        >
                          {item.risk_rating.replace('_', ' ')}
                        </span>
                        <div className="text-xs font-bold text-slate-300 mt-1">
                          Risk Score: {item.asset_risk_score}
                        </div>
                      </div>
                    </div>
                  </div>
                ))
              ) : (
                <div className="text-slate-500 text-xs text-center py-6">
                  No target assets associated with findings under current filters.
                </div>
              )}
            </div>
          </div>
        </>
      )}

    </div>
  );
};

export default AnalyticsDashboard;
