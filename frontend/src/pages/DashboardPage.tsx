import React, { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { PlusCircle, Terminal, Sparkles, Brain, FolderGit2 } from 'lucide-react';
import { getScans, deleteScan } from '../services/scanService';
import { ProjectService } from '../services/projectService';
import type { ScanHistoryItem } from '../types/scan';
import { SecurityOverview } from '../components/dashboard/SecurityOverview';
import { SeverityChart } from '../components/dashboard/SeverityChart';
import { ScanActivity } from '../components/dashboard/ScanActivity';
import { RecentScans } from '../components/dashboard/RecentScans';
import { CardSkeleton, TableSkeleton } from '../components/common/Loader';
import { toast } from 'sonner';

export const DashboardPage: React.FC = () => {
  const navigate = useNavigate();
  const [scans, setScans] = useState<ScanHistoryItem[]>([]);
  const [totalProjects, setTotalProjects] = useState<number>(0);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    loadDashboardData();
  }, []);

  const loadDashboardData = async () => {
    setLoading(true);
    try {
      const [scanList, projData] = await Promise.all([
        getScans().catch(() => []),
        ProjectService.listProjects({ limit: 1 }).catch(() => ({ items: [], pagination: { total: 0 } })),
      ]);
      setScans(scanList);
      setTotalProjects(projData.pagination?.total ?? projData.items?.length ?? 0);
    } catch (err) {
      console.error(err);
      toast.error('Failed to load dashboard metrics');
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteScan = async (id: string) => {
    try {
      await deleteScan(id);
      setScans((prev) => prev.filter((s) => s.id !== id));
      toast.success('Scan record removed');
    } catch {
      toast.error('Failed to remove scan record');
    }
  };

  // Derive real statistics from backend data (no fabricated fallback)
  const totalScans = scans.length;
  const totalVulnerabilities = scans.reduce((acc, s) => acc + (s.totalFindings || 0), 0);
  const criticalFindings = scans.reduce((acc, s) => {
    const isCrit = s.highestSeverity === 'CRITICAL';
    return acc + (isCrit ? 1 : 0);
  }, 0);
  const highFindings = scans.reduce((acc, s) => {
    const isHigh = s.highestSeverity === 'HIGH';
    return acc + (isHigh ? 1 : 0);
  }, 0);

  // Derive real severity breakdown
  const critCount = scans.filter((s) => s.highestSeverity === 'CRITICAL').length;
  const highCount = scans.filter((s) => s.highestSeverity === 'HIGH').length;
  const medCount = scans.filter((s) => s.highestSeverity === 'MEDIUM').length;
  const lowCount = scans.filter((s) => s.highestSeverity === 'LOW').length;

  const severityChartData = [
    { name: 'Critical', count: critCount, fill: '#EF4444' },
    { name: 'High', count: highCount, fill: '#F97316' },
    { name: 'Medium', count: medCount, fill: '#F59E0B' },
    { name: 'Low', count: lowCount, fill: '#3B82F6' },
  ];

  // Derive real activity timeline by day
  const dateMap = new Map<string, number>();
  scans.forEach((s) => {
    const dateStr = s.createdAt ? new Date(s.createdAt).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) : 'Today';
    dateMap.set(dateStr, (dateMap.get(dateStr) || 0) + 1);
  });
  const activityData = Array.from(dateMap.entries()).map(([date, count]) => ({
    date,
    scans: count,
  })).slice(-7);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Security Overview</h1>
          <p className="text-xs text-slate-400 mt-1">
            Real-time vulnerability metrics, AST scanning telemetry, and remediation progress.
          </p>
        </div>
        <div className="flex items-center gap-2.5">
          <Link
            to="/projects"
            className="flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold transition border border-slate-700"
          >
            <FolderGit2 className="w-4 h-4 text-cyan-400" />
            <span>Manage Projects</span>
          </Link>
          <button
            onClick={() => navigate('/scan')}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold shadow-lg shadow-indigo-600/20 transition active:scale-95"
          >
            <PlusCircle className="w-4 h-4" />
            <span>Start New Scan</span>
          </button>
        </div>
      </div>

      {loading ? (
        <div className="space-y-6">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <CardSkeleton rows={2} />
            <CardSkeleton rows={2} />
            <CardSkeleton rows={2} />
            <CardSkeleton rows={2} />
          </div>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <CardSkeleton rows={4} />
            <CardSkeleton rows={4} />
          </div>
          <TableSkeleton rows={4} />
        </div>
      ) : scans.length === 0 ? (
        /* Empty State */
        <div className="flex flex-col items-center justify-center rounded-2xl border border-slate-800 bg-[#111827] p-12 text-center shadow-lg">
          <div className="mb-4 rounded-2xl bg-indigo-500/10 p-5 ring-1 ring-indigo-500/30">
            <Terminal className="h-10 w-10 text-indigo-400" />
          </div>
          <h2 className="text-xl font-bold text-white">No Security Scans Recorded Yet</h2>
          <p className="mt-2 max-w-md text-sm text-slate-400">
            Run an AST-driven static analysis, AI taint flow inspection, or OSV dependency scan to detect vulnerabilities in your repository.
          </p>
          <div className="mt-6 flex flex-wrap gap-3 justify-center">
            <button
              onClick={() => navigate('/scan')}
              className="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-5 py-2.5 text-sm font-semibold text-white shadow-lg shadow-indigo-600/30 transition hover:bg-indigo-500"
            >
              <PlusCircle className="h-4 w-4" />
              <span>Launch First Scan</span>
            </button>
            <Link
              to="/projects"
              className="inline-flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-800/80 px-4 py-2.5 text-sm font-semibold text-slate-300 transition hover:bg-slate-700 hover:text-white"
            >
              <FolderGit2 className="h-4 w-4 text-cyan-400" />
              <span>Create Project</span>
            </Link>
          </div>
        </div>
      ) : (
        <>
          {/* Key Metrics */}
          <SecurityOverview
            totalScans={totalScans}
            totalVulnerabilities={totalVulnerabilities}
            criticalFindings={criticalFindings}
            highFindings={highFindings}
            totalProjects={totalProjects}
          />

          {/* AI Model Intelligence Banner */}
          <div className="p-4 rounded-xl border border-purple-500/30 bg-gradient-to-r from-purple-950/30 via-slate-900 to-blue-950/30 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-purple-500/20 border border-purple-500/30 text-purple-300">
                <Brain className="w-5 h-5" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-bold text-white text-sm">Hybrid AI/ML & Static Analysis Engine</span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                    AST + TAINT + OSV.DEV
                  </span>
                </div>
                <p className="text-slate-400 text-xs mt-0.5">
                  Inter-procedural data-flow tracking with multi-step taint verification and automated remediation synthesis.
                </p>
              </div>
            </div>
            <button
              onClick={() => navigate('/model-datasets')}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-purple-600 hover:bg-purple-500 text-white text-xs font-semibold shrink-0 transition"
            >
              <span>Inspect ML Model</span>
              <Sparkles className="w-3.5 h-3.5" />
            </button>
          </div>

          {/* Charts Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <SeverityChart data={severityChartData} />
            <ScanActivity data={activityData} />
          </div>

          {/* Recent Scans Table */}
          <RecentScans scans={scans} onDelete={handleDeleteScan} />
        </>
      )}
    </div>
  );
};

export default DashboardPage;
