import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { getScans, deleteScan } from '../services/scanService';
import type { ScanHistoryItem } from '../types/scan';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { DemoDataBanner } from '../components/common/DemoDataBanner';
import { TableSkeleton } from '../components/common/Skeleton';
import { AnimatedCounter } from '../components/common/AnimatedCounter';
import { 
  Search, 
  Filter, 
  Eye, 
  FileText, 
  RotateCcw, 
  Trash2, 
  Terminal, 
  Layers, 
  ArrowUpDown,
  X
} from 'lucide-react';
import { toast } from 'sonner';

export const ScanHistoryPage: React.FC = () => {
  const navigate = useNavigate();

  const [scans, setScans] = useState<ScanHistoryItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [deleteTargetId, setDeleteTargetId] = useState<string | null>(null);

  // Filters
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [languageFilter, setLanguageFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [sortBy, setSortBy] = useState<'date' | 'findings'>('date');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');

  useEffect(() => {
    loadScans();
  }, []);

  const loadScans = async () => {
    setLoading(true);
    try {
      const data = await getScans();
      setScans(data);
    } catch (err) {
      toast.error('Failed to load scan history.');
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await deleteScan(id);
      setScans(prev => prev.filter(s => s.id !== id));
      setDeleteTargetId(null);
      toast.success(`Scan ${id} deleted.`);
    } catch (err) {
      toast.error('Failed to delete scan.');
    }
  };

  // Filter & Sort
  const filteredScans = scans
    .filter(scan => {
      const matchesSearch = 
        scan.projectName.toLowerCase().includes(searchQuery.toLowerCase()) ||
        scan.fileName.toLowerCase().includes(searchQuery.toLowerCase()) ||
        scan.id.toLowerCase().includes(searchQuery.toLowerCase());
      
      const matchesLang = languageFilter === 'ALL' || scan.language.toLowerCase() === languageFilter.toLowerCase();
      const matchesSev = severityFilter === 'ALL' || scan.highestSeverity === severityFilter;
      const matchesStatus = statusFilter === 'ALL' || scan.status === statusFilter;

      return matchesSearch && matchesLang && matchesSev && matchesStatus;
    })
    .sort((a, b) => {
      if (sortBy === 'findings') {
        return sortOrder === 'desc' 
          ? b.totalFindings - a.totalFindings 
          : a.totalFindings - b.totalFindings;
      }
      // Date sort
      const dateA = new Date(a.createdAt).getTime();
      const dateB = new Date(b.createdAt).getTime();
      return sortOrder === 'desc' ? dateB - dateA : dateA - dateB;
    });

  const hasDemoScans = scans.some(s => s.isDemo);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-border">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Security Scan Archive</h1>
          <p className="text-xs text-slate-400 mt-1">
            Historical audit logs, findings timeline, and consolidated scan records.
          </p>
        </div>
        <button
          onClick={() => navigate('/scan')}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-primary hover:bg-primary-hover text-white text-xs font-semibold shadow-sm w-fit"
        >
          <Terminal className="w-4 h-4" />
          <span>Launch New Scan</span>
        </button>
      </div>

      {hasDemoScans && (
        <DemoDataBanner message="Historical log includes sample verification runs." />
      )}

      {/* Filter and Search Bar */}
      <div className="p-4 rounded-xl bg-card border border-border flex flex-wrap items-center justify-between gap-3 text-xs">
        {/* Search */}
        <div className="relative flex-1 min-w-[200px]">
          <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search by project, file, or scan ID..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-[#0B1020] border border-border rounded-lg pl-9 pr-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-primary font-mono"
          />
        </div>

        {/* Language Filter */}
        <select
          value={languageFilter}
          onChange={(e) => setLanguageFilter(e.target.value)}
          className="bg-[#0B1020] border border-border rounded-lg px-3 py-2 text-xs text-slate-200 font-mono focus:outline-none"
        >
          <option value="ALL">All Languages</option>
          <option value="python">Python</option>
          <option value="javascript">JavaScript</option>
          <option value="typescript">TypeScript</option>
        </select>

        {/* Severity Filter */}
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="bg-[#0B1020] border border-border rounded-lg px-3 py-2 text-xs text-slate-200 font-mono focus:outline-none"
        >
          <option value="ALL">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>

        {/* Sort Trigger */}
        <div className="flex items-center gap-1.5 border border-border rounded-lg px-2 py-1 bg-[#0B1020]">
          <span className="text-[11px] text-slate-400">Sort:</span>
          <button
            onClick={() => {
              if (sortBy === 'date') setSortOrder(prev => prev === 'desc' ? 'asc' : 'desc');
              else setSortBy('date');
            }}
            className={`px-2 py-1 rounded text-[11px] font-mono ${sortBy === 'date' ? 'bg-surface text-cyan-400 font-bold' : 'text-slate-400'}`}
          >
            Date {sortBy === 'date' && (sortOrder === 'desc' ? '↓' : '↑')}
          </button>
          <button
            onClick={() => {
              if (sortBy === 'findings') setSortOrder(prev => prev === 'desc' ? 'asc' : 'desc');
              else setSortBy('findings');
            }}
            className={`px-2 py-1 rounded text-[11px] font-mono ${sortBy === 'findings' ? 'bg-surface text-cyan-400 font-bold' : 'text-slate-400'}`}
          >
            Findings {sortBy === 'findings' && (sortOrder === 'desc' ? '↓' : '↑')}
          </button>
        </div>

        {/* Reset */}
        {(searchQuery || languageFilter !== 'ALL' || severityFilter !== 'ALL') && (
          <button
            onClick={() => {
              setSearchQuery('');
              setLanguageFilter('ALL');
              setSeverityFilter('ALL');
            }}
            className="text-[11px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-mono"
          >
            <X className="w-3 h-3" />
            <span>Reset</span>
          </button>
        )}
      </div>

      {/* Historical Scans Table */}
      <div className="rounded-xl bg-card border border-border overflow-hidden shadow-sm animate-fade-in-up">
        {loading ? (
          <div className="p-4">
            <TableSkeleton rows={6} />
          </div>
        ) : filteredScans.length === 0 ? (
          <div className="p-12 text-center space-y-3">
            <Layers className="w-10 h-10 text-slate-500 mx-auto" />
            <h3 className="font-semibold text-sm text-slate-200">No Matching Scans</h3>
            <p className="text-xs text-slate-400">Try adjusting your filters or execute a new scan.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-[#0F172A] text-slate-400 font-mono text-[11px] border-b border-border">
                <tr>
                  <th className="py-3 px-4">Scan ID</th>
                  <th className="py-3 px-4">Project & File</th>
                  <th className="py-3 px-4">Language</th>
                  <th className="py-3 px-4">Timestamp</th>
                  <th className="py-3 px-4">Findings</th>
                  <th className="py-3 px-4">Max Severity</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/60">
                {filteredScans.map((scan) => (
                  <tr key={scan.id} className="hover:bg-surface/40 transition-colors duration-150">
                    <td className="py-3.5 px-4 font-mono text-cyan-400 font-semibold">
                      {scan.id}
                      {scan.isDemo && (
                        <span className="ml-2 text-[9px] text-amber-400 bg-amber-950/60 border border-amber-800/40 px-1 py-0.2 rounded font-sans uppercase">
                          Demo
                        </span>
                      )}
                    </td>
                    <td className="py-3.5 px-4">
                      <div className="font-semibold text-slate-200">{scan.projectName}</div>
                      <div className="text-[11px] text-slate-400 font-mono">{scan.fileName}</div>
                    </td>
                    <td className="py-3.5 px-4 font-mono text-slate-300 uppercase">
                      {scan.language}
                    </td>
                    <td className="py-3.5 px-4 text-slate-400">
                      {new Date(scan.createdAt).toLocaleString()}
                    </td>
                    <td className="py-3.5 px-4 font-mono font-bold text-slate-200">
                      <AnimatedCounter value={scan.totalFindings} />
                    </td>
                    <td className="py-3.5 px-4">
                      <SeverityBadge severity={scan.highestSeverity} size="sm" />
                    </td>
                    <td className="py-3.5 px-4">
                      <span className="px-2 py-0.5 rounded bg-emerald-950/60 text-emerald-400 border border-emerald-800/40 text-[10px] font-mono">
                        {scan.status}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 text-right space-x-2">
                      <button
                        onClick={() => navigate(`/results/${scan.id}`)}
                        className="p-1.5 rounded hover:bg-surface text-slate-300 hover:text-white transition-all duration-200 hover:scale-110 active:scale-95"
                        title="Open Results"
                      >
                        <Eye className="w-3.5 h-3.5" />
                      </button>
                      <button
                        onClick={() => navigate(`/reports/${scan.id}`)}
                        className="p-1.5 rounded hover:bg-surface text-slate-300 hover:text-white transition-all duration-200 hover:scale-110 active:scale-95"
                        title="Download Report"
                      >
                        <FileText className="w-3.5 h-3.5" />
                      </button>
                      <button
                        onClick={() => navigate('/scan')}
                        className="p-1.5 rounded hover:bg-surface text-cyan-400 hover:text-cyan-300 transition-all duration-200 hover:scale-110 active:scale-95"
                        title="Rescan"
                      >
                        <RotateCcw className="w-3.5 h-3.5" />
                      </button>
                      <button
                        onClick={() => setDeleteTargetId(scan.id)}
                        className="p-1.5 rounded hover:bg-surface text-red-400 hover:text-red-300 transition-all duration-200 hover:scale-110 active:scale-95"
                        title="Delete Record"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Delete Confirmation Modal */}
      {deleteTargetId && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <div className="bg-card border border-border rounded-xl p-5 max-w-sm w-full space-y-4 shadow-2xl">
            <h3 className="font-bold text-sm text-white">Delete Scan Record</h3>
            <p className="text-xs text-slate-300">
              Are you sure you want to delete scan <code className="text-cyan-400 font-mono">{deleteTargetId}</code>? This record will be permanently deleted.
            </p>
            <div className="flex items-center justify-end gap-2 pt-2">
              <button
                onClick={() => setDeleteTargetId(null)}
                className="px-3 py-1.5 rounded-lg bg-surface border border-border text-slate-300 text-xs hover:text-white"
              >
                Cancel
              </button>
              <button
                onClick={() => handleDelete(deleteTargetId)}
                className="px-3 py-1.5 rounded-lg bg-red-600 hover:bg-red-700 text-white text-xs font-semibold"
              >
                Delete Scan
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
