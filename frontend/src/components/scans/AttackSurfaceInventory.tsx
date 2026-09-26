import React, { useState, useEffect } from 'react';
import {
  Globe,
  Layers,
  FileCode,
  FormInput,
  Network,
  Radio,
  ExternalLink,
  Search,
  Filter,
  CheckCircle2,
  HelpCircle,
  Eye,
  X
} from 'lucide-react';
import {
  getAttackSurfaceApi,
  getAttackSurfaceSummaryApi,
  AttackSurfaceAsset,
  AttackSurfaceSummary
} from '../../api/attack_surface';

interface AttackSurfaceInventoryProps {
  scanId: number;
}

export const AttackSurfaceInventory: React.FC<AttackSurfaceInventoryProps> = ({ scanId }) => {
  const [assets, setAssets] = useState<AttackSurfaceAsset[]>([]);
  const [summary, setSummary] = useState<AttackSurfaceSummary | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [selectedType, setSelectedType] = useState<string>('ALL');
  const [selectedStatus, setSelectedStatus] = useState<string>('ALL');
  const [selectedAsset, setSelectedAsset] = useState<AttackSurfaceAsset | null>(null);

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [assetsData, summaryData] = await Promise.all([
        getAttackSurfaceApi(scanId, { limit: 200 }),
        getAttackSurfaceSummaryApi(scanId)
      ]);
      setAssets(assetsData);
      setSummary(summaryData);
    } catch (err: any) {
      console.error('Failed to load attack surface data:', err);
      setError('Unable to load attack surface telemetry.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (scanId) {
      fetchData();
    }
  }, [scanId]);

  const filteredAssets = assets.filter((asset) => {
    const matchesSearch =
      asset.url.toLowerCase().includes(searchTerm.toLowerCase()) ||
      asset.path.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesType = selectedType === 'ALL' || asset.asset_type === selectedType;
    const matchesStatus = selectedStatus === 'ALL' || asset.evidence_status === selectedStatus;
    return matchesSearch && matchesType && matchesStatus;
  });

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'VERIFIED':
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase bg-cyber-emerald/20 text-cyber-emerald border border-cyber-emerald/40">
            <CheckCircle2 className="w-3 h-3" />
            <span>VERIFIED</span>
          </span>
        );
      case 'INFERRED':
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase bg-cyber-amber/20 text-cyber-amber border border-cyber-amber/40">
            <HelpCircle className="w-3 h-3" />
            <span>INFERRED</span>
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase bg-cyber-cyan/20 text-cyber-cyan border border-cyber-cyan/40">
            <Eye className="w-3 h-3" />
            <span>OBSERVED</span>
          </span>
        );
    }
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'PAGE':
        return <Globe className="w-4 h-4 text-cyber-cyan" />;
      case 'FORM':
        return <FormInput className="w-4 h-4 text-cyber-emerald" />;
      case 'API':
        return <Network className="w-4 h-4 text-purple-400" />;
      case 'SCRIPT':
        return <FileCode className="w-4 h-4 text-cyber-amber" />;
      case 'WEB_SOCKET':
      case 'GRAPHQL':
        return <Radio className="w-4 h-4 text-pink-400" />;
      default:
        return <Layers className="w-4 h-4 text-slate-400" />;
    }
  };

  if (loading) {
    return (
      <div className="glass-card p-6 rounded-3xl border border-white/10 text-center font-mono text-xs text-slate-400">
        <div className="animate-spin w-6 h-6 border-2 border-cyber-cyan border-t-transparent rounded-full mx-auto mb-2" />
        Loading discovered attack surface inventory...
      </div>
    );
  }

  if (error || !assets || assets.length === 0) {
    return (
      <div className="glass-card p-6 rounded-3xl border border-white/10 text-center font-mono text-xs text-slate-400 space-y-2">
        <Layers className="w-8 h-8 mx-auto text-slate-600 mb-2" />
        <div className="text-slate-300 font-bold">No Attack Surface Assets Discovered Yet</div>
        <p className="text-[11px] text-slate-500">
          Reachable pages, endpoints, forms, APIs, and scripts will appear here once the discovery phase runs.
        </p>
      </div>
    );
  }

  return (
    <div className="glass-card p-6 rounded-3xl border border-white/10 space-y-6 font-sans">
      {/* Header and Summary Cards */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-white/10 pb-4">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-2xl bg-cyber-cyan/10 border border-cyber-cyan/30 text-cyber-cyan">
            <Layers className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base font-bold font-display text-slate-100">
              Discovered Attack Surface ({assets.length})
            </h3>
            <p className="text-xs font-mono text-slate-400">
              Same-origin reachable pages, APIs, forms, and client scripts mapped during Phase 7D
            </p>
          </div>
        </div>

        {summary && (
          <div className="flex items-center space-x-2 font-mono text-[11px]">
            <span className="px-3 py-1 rounded-xl bg-white/[0.03] border border-white/10 text-slate-300">
              In-Scope: <b className="text-cyber-emerald">{summary.in_scope_count}</b>
            </span>
            <span className="px-3 py-1 rounded-xl bg-white/[0.03] border border-white/10 text-slate-300">
              External: <b className="text-slate-400">{summary.external_count}</b>
            </span>
          </div>
        )}
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3 font-mono text-xs">
        <div className="relative flex-1 max-w-md">
          <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
          <input
            type="text"
            placeholder="Search path, URL, or endpoint..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-9 pr-4 py-2 rounded-xl bg-slate-900/60 border border-white/10 focus:border-cyber-cyan/50 text-slate-200 placeholder-slate-500 outline-none transition-all text-xs"
          />
        </div>

        <div className="flex items-center space-x-2 overflow-x-auto pb-1 md:pb-0">
          <select
            value={selectedType}
            onChange={(e) => setSelectedType(e.target.value)}
            className="px-3 py-2 rounded-xl bg-slate-900/80 border border-white/10 text-slate-300 text-xs outline-none cursor-pointer"
          >
            <option value="ALL">All Types</option>
            <option value="PAGE">Pages</option>
            <option value="FORM">Forms</option>
            <option value="API">APIs</option>
            <option value="SCRIPT">Scripts</option>
            <option value="WEB_SOCKET">WebSockets</option>
            <option value="GRAPHQL">GraphQL</option>
            <option value="ROBOTS">Robots</option>
            <option value="SITEMAP">Sitemaps</option>
          </select>

          <select
            value={selectedStatus}
            onChange={(e) => setSelectedStatus(e.target.value)}
            className="px-3 py-2 rounded-xl bg-slate-900/80 border border-white/10 text-slate-300 text-xs outline-none cursor-pointer"
          >
            <option value="ALL">All Statuses</option>
            <option value="VERIFIED">Verified</option>
            <option value="OBSERVED">Observed</option>
            <option value="INFERRED">Inferred</option>
          </select>
        </div>
      </div>

      {/* Assets Table */}
      <div className="overflow-x-auto font-mono text-xs">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-white/10 text-slate-400 uppercase text-[10px]">
              <th className="py-3 px-4">Type</th>
              <th className="py-3 px-4">Method</th>
              <th className="py-3 px-4">Discovered Path / URL</th>
              <th className="py-3 px-4">Scope</th>
              <th className="py-3 px-4">Status</th>
              <th className="py-3 px-4 text-right">Evidence</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {filteredAssets.slice(0, 100).map((asset) => (
              <tr key={asset.id} className="hover:bg-white/[0.02] transition-colors">
                <td className="py-3 px-4">
                  <div className="flex items-center space-x-2">
                    {getTypeIcon(asset.asset_type)}
                    <span className="font-bold text-slate-300">{asset.asset_type}</span>
                  </div>
                </td>
                <td className="py-3 px-4">
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-white/5 border border-white/10 text-slate-200">
                    {asset.http_method}
                  </span>
                </td>
                <td className="py-3 px-4">
                  <div className="truncate max-w-[280px] sm:max-w-[400px] text-slate-200" title={asset.url}>
                    {asset.path || asset.url}
                  </div>
                  {asset.query_parameters && asset.query_parameters.length > 0 && (
                    <div className="text-[10px] text-cyber-cyan/80">
                      Params: {asset.query_parameters.join(', ')}
                    </div>
                  )}
                </td>
                <td className="py-3 px-4">
                  {asset.in_scope ? (
                    <span className="text-cyber-emerald text-[11px]">In-Scope</span>
                  ) : (
                    <span className="text-slate-500 text-[11px]">External</span>
                  )}
                </td>
                <td className="py-3 px-4">{getStatusBadge(asset.evidence_status)}</td>
                <td className="py-3 px-4 text-right">
                  <button
                    onClick={() => setSelectedAsset(asset)}
                    className="p-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-slate-400 hover:text-white transition-all cursor-pointer"
                    title="View Evidence Details"
                  >
                    <Eye className="w-3.5 h-3.5" />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Evidence Viewer Modal */}
      {selectedAsset && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in font-mono">
          <div className="glass-card max-w-xl w-full p-6 rounded-3xl border border-white/20 bg-slate-950/95 space-y-4 max-h-[85vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <div className="flex items-center space-x-2">
                {getTypeIcon(selectedAsset.asset_type)}
                <h4 className="text-sm font-bold text-slate-100">
                  {selectedAsset.asset_type} Evidence Details
                </h4>
              </div>
              <button
                onClick={() => setSelectedAsset(null)}
                className="p-1 rounded-lg text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <span className="text-slate-500 uppercase text-[10px]">URL:</span>
                <div className="text-cyber-cyan break-all">{selectedAsset.url}</div>
              </div>

              <div className="grid grid-cols-2 gap-2">
                <div>
                  <span className="text-slate-500 uppercase text-[10px]">Discovered From:</span>
                  <div className="text-slate-300">{selectedAsset.discovered_from}</div>
                </div>
                <div>
                  <span className="text-slate-500 uppercase text-[10px]">Evidence Status:</span>
                  <div>{getStatusBadge(selectedAsset.evidence_status)}</div>
                </div>
              </div>

              {selectedAsset.source_url && (
                <div>
                  <span className="text-slate-500 uppercase text-[10px]">Source URL:</span>
                  <div className="text-slate-400 break-all">{selectedAsset.source_url}</div>
                </div>
              )}

              <div>
                <span className="text-slate-500 uppercase text-[10px]">Structured Evidence Payload:</span>
                <pre className="mt-1 p-3 rounded-xl bg-slate-900 border border-white/10 text-[11px] text-slate-300 overflow-x-auto whitespace-pre-wrap">
                  {JSON.stringify(selectedAsset.evidence, null, 2)}
                </pre>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
