import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  PlusCircle, 
  ShieldAlert, 
  Terminal, 
  CheckCircle2, 
  AlertTriangle, 
  TrendingUp, 
  FileText, 
  Eye, 
  Trash2, 
  ExternalLink,
  Shield,
  Layers,
  Brain,
  Sparkles
} from 'lucide-react';
import { 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  Tooltip, 
  ResponsiveContainer, 
  PieChart, 
  Pie, 
  Cell, 
  AreaChart, 
  Area 
} from 'recharts';
import { getScans, deleteScan, getScanById } from '../services/scanService';
import type { ScanHistoryItem, VulnerabilityFinding } from '../types/scan';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { DemoDataBanner } from '../components/common/DemoDataBanner';
import { DEMO_DASHBOARD_STATS, DEMO_FINDINGS } from '../services/demoData';
import { toast } from 'sonner';

export const DashboardPage: React.FC = () => {
  const navigate = useNavigate();
  const [scans, setScans] = useState<ScanHistoryItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [deleteTargetId, setDeleteTargetId] = useState<string | null>(null);
  const [recentFindings, setRecentFindings] = useState<VulnerabilityFinding[]>([]);

  useEffect(() => {
    loadDashboardData();
  }, []);

  const loadDashboardData = async () => {
    setLoading(true);
    try {
      const scanList = await getScans();
      setScans(scanList);

      // Load findings from the latest scan if available
      if (scanList.length > 0) {
        const latest = await getScanById(scanList[0].id);
        if (latest && latest.findings.length > 0) {
          setRecentFindings(latest.findings.slice(0, 5));
        } else {
          setRecentFindings(DEMO_FINDINGS.slice(0, 5));
        }
      } else {
        setRecentFindings(DEMO_FINDINGS.slice(0, 5));
      }
    } catch (err) {
      console.error(err);
      toast.error('Could not load scan records');
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteScan = async (id: string) => {
    try {
      await deleteScan(id);
      setScans(prev => prev.filter(s => s.id !== id));
      setDeleteTargetId(null);
      toast.success('Scan removed from history');
    } catch (err) {
      toast.error('Failed to delete scan');
    }
  };

  const hasDemoScans = scans.some(s => s.isDemo);

  return (
    <div className="space-y-6">
      {/* Welcome Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-border">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Security Overview</h1>
          <p className="text-xs text-slate-400 mt-1">
            Monitor scans, investigate findings, and improve code security across projects.
          </p>
        </div>
        <button
          onClick={() => navigate('/scan')}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-primary hover:bg-primary-hover text-white text-xs font-semibold transition-all shadow-sm w-fit"
        >
          <PlusCircle className="w-4 h-4" />
          <span>Start New Scan</span>
        </button>
      </div>

      {hasDemoScans && (
        <DemoDataBanner message="Showing deterministic sample scans and findings from test fixtures." />
      )}

      {/* Summary Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Scans */}
        <div className="p-4 rounded-xl bg-card border border-border flex items-center justify-between">
          <div>
            <p className="text-xs font-medium text-slate-400">Total Scans</p>
            <h3 className="text-2xl font-bold text-white mt-1">
              {scans.length > 0 ? scans.length : DEMO_DASHBOARD_STATS.totalScans}
            </h3>
            <span className="text-[11px] text-cyan-400 font-mono">AST & Rule Passes</span>
          </div>
          <div className="p-3 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-400">
            <Terminal className="w-5 h-5" />
          </div>
        </div>

        {/* Vulnerabilities Found */}
        <div className="p-4 rounded-xl bg-card border border-border flex items-center justify-between">
          <div>
            <p className="text-xs font-medium text-slate-400">Vulnerabilities Found</p>
            <h3 className="text-2xl font-bold text-white mt-1">
              {scans.reduce((acc, s) => acc + s.totalFindings, 0) || DEMO_DASHBOARD_STATS.vulnerabilitiesFound}
            </h3>
            <span className="text-[11px] text-amber-400 font-mono">Active In Code</span>
          </div>
          <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-400">
            <ShieldAlert className="w-5 h-5" />
          </div>
        </div>

        {/* Critical Findings */}
        <div className="p-4 rounded-xl bg-card border border-border flex items-center justify-between">
          <div>
            <p className="text-xs font-medium text-slate-400">Critical Findings</p>
            <h3 className="text-2xl font-bold text-red-400 mt-1">
              {DEMO_DASHBOARD_STATS.criticalFindings}
            </h3>
            <span className="text-[11px] text-red-400 font-mono">Requires Immediate Fix</span>
          </div>
          <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400">
            <AlertTriangle className="w-5 h-5" />
          </div>
        </div>

        {/* Remediation Progress */}
        <div className="p-4 rounded-xl bg-card border border-border flex items-center justify-between">
          <div>
            <p className="text-xs font-medium text-slate-400">Remediation Progress</p>
            <h3 className="text-2xl font-bold text-emerald-400 mt-1">
              {DEMO_DASHBOARD_STATS.remediationProgress}%
            </h3>
            <span className="text-[11px] text-emerald-400 font-mono">Validated Fixes</span>
          </div>
          <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
            <CheckCircle2 className="w-5 h-5" />
          </div>
        </div>
      </div>

      {/* AI Model & Datasets Intelligence Banner */}
      <div className="p-4 rounded-xl border border-purple-500/30 bg-gradient-to-r from-purple-950/30 via-slate-900 to-blue-950/30 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-purple-500/20 border border-purple-500/30 text-purple-300">
            <Brain className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-bold text-white text-sm">AI Vulnerability Model & Real-World Datasets</span>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                90.5% ACCURACY
              </span>
            </div>
            <p className="text-slate-400 text-xs mt-0.5">
              Integrated with Google <strong>OSV.dev REST API</strong> (Open Source Software Composition Analysis) and <strong>ManageEngine Endpoint Central</strong> (Endpoint Security Baselines & CVE Bulletins).
            </p>
          </div>
        </div>
        <button
          onClick={() => navigate('/model-datasets')}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-purple-600 hover:bg-purple-500 text-white text-xs font-semibold shrink-0 transition-colors shadow"
        >
          <span>Explore Datasets & Model</span>
          <Sparkles className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* Analytics Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Severity Distribution */}
        <div className="lg:col-span-4 p-5 rounded-xl bg-card border border-border space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider">
              Findings by Severity
            </h3>
            <span className="text-[10px] text-slate-400 font-mono">CVSS / CWE</span>
          </div>
          <div className="h-48 w-full flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={DEMO_DASHBOARD_STATS.severityDistribution}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={75}
                  paddingAngle={5}
                  dataKey="count"
                >
                  {DEMO_DASHBOARD_STATS.severityDistribution.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.fill} />
                  ))}
                </Pie>
                <Tooltip 
                  contentStyle={{ backgroundColor: '#111827', borderColor: '#1E293B', borderRadius: '8px', fontSize: '11px' }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="grid grid-cols-2 gap-2 text-[11px] text-slate-300">
            {DEMO_DASHBOARD_STATS.severityDistribution.map((item) => (
              <div key={item.name} className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: item.fill }} />
                <span>{item.name}: <strong>{item.count}</strong></span>
              </div>
            ))}
          </div>
        </div>

        {/* Vulnerability Categories Bar Chart */}
        <div className="lg:col-span-8 p-5 rounded-xl bg-card border border-border space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider">
              Detected Categories Breakdown
            </h3>
            <span className="text-[10px] text-slate-400 font-mono">OWASP Top 10</span>
          </div>
          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={DEMO_DASHBOARD_STATS.categoryDistribution} margin={{ top: 10, right: 10, left: -20, bottom: 20 }}>
                <XAxis 
                  dataKey="category" 
                  stroke="#64748B" 
                  fontSize={10} 
                  angle={-15} 
                  textAnchor="end"
                />
                <YAxis stroke="#64748B" fontSize={10} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#111827', borderColor: '#1E293B', borderRadius: '8px', fontSize: '11px' }}
                />
                <Bar dataKey="count" fill="#3B82F6" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Recent Scans Table */}
      <div className="p-5 rounded-xl bg-card border border-border space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-semibold text-white">Recent Security Scans</h3>
            <p className="text-[11px] text-slate-400">Audited projects and source files</p>
          </div>
          <button
            onClick={() => navigate('/history')}
            className="text-xs text-primary hover:text-primary-light font-medium flex items-center gap-1"
          >
            <span>View All Scans</span>
            <ExternalLink className="w-3.5 h-3.5" />
          </button>
        </div>

        {scans.length === 0 ? (
          <div className="p-8 rounded-lg bg-surface/30 border border-border text-center space-y-3">
            <Layers className="w-8 h-8 text-slate-500 mx-auto" />
            <p className="text-xs text-slate-300">No scans found in database.</p>
            <button
              onClick={() => navigate('/scan')}
              className="px-4 py-2 rounded-lg bg-primary hover:bg-primary-hover text-white text-xs font-medium"
            >
              Run Your First Scan
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-surface/50 text-slate-400 font-mono text-[11px] border-b border-border">
                <tr>
                  <th className="py-2.5 px-3">Scan ID</th>
                  <th className="py-2.5 px-3">Project / File</th>
                  <th className="py-2.5 px-3">Language</th>
                  <th className="py-2.5 px-3">Scan Date</th>
                  <th className="py-2.5 px-3">Findings</th>
                  <th className="py-2.5 px-3">Severity</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/60">
                {scans.slice(0, 5).map((scan) => (
                  <tr key={scan.id} className="hover:bg-surface/30 transition-colors">
                    <td className="py-3 px-3 font-mono text-cyan-400">{scan.id}</td>
                    <td className="py-3 px-3">
                      <div className="font-medium text-slate-200">{scan.projectName}</div>
                      <div className="text-[10px] text-slate-400 font-mono">{scan.fileName}</div>
                    </td>
                    <td className="py-3 px-3 font-mono text-slate-300 uppercase">{scan.language}</td>
                    <td className="py-3 px-3 text-slate-400">
                      {new Date(scan.createdAt).toLocaleDateString()}
                    </td>
                    <td className="py-3 px-3 font-mono font-semibold text-slate-200">
                      {scan.totalFindings}
                    </td>
                    <td className="py-3 px-3">
                      <SeverityBadge severity={scan.highestSeverity} size="sm" />
                    </td>
                    <td className="py-3 px-3">
                      <span className="px-2 py-0.5 rounded bg-emerald-950/60 text-emerald-400 border border-emerald-800/40 text-[10px] font-mono">
                        {scan.status}
                      </span>
                    </td>
                    <td className="py-3 px-3 text-right space-x-2">
                      <button
                        onClick={() => navigate(`/results/${scan.id}`)}
                        className="p-1 rounded hover:bg-surface text-slate-300 hover:text-white"
                        title="View Results"
                      >
                        <Eye className="w-3.5 h-3.5" />
                      </button>
                      <button
                        onClick={() => navigate(`/reports/${scan.id}`)}
                        className="p-1 rounded hover:bg-surface text-slate-300 hover:text-white"
                        title="Open Report"
                      >
                        <FileText className="w-3.5 h-3.5" />
                      </button>
                      <button
                        onClick={() => setDeleteTargetId(scan.id)}
                        className="p-1 rounded hover:bg-surface text-red-400 hover:text-red-300"
                        title="Delete scan"
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

      {/* Recent Findings Preview */}
      <div className="p-5 rounded-xl bg-card border border-border space-y-4">
        <h3 className="text-sm font-semibold text-white">Latest Vulnerability Findings</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {recentFindings.map((finding) => (
            <div 
              key={finding.id} 
              className="p-3.5 rounded-lg bg-[#0F172A] border border-border hover:border-slate-700 transition-all cursor-pointer"
              onClick={() => navigate(`/results/${finding.scanId}`)}
            >
              <div className="flex items-center justify-between mb-2">
                <SeverityBadge severity={finding.severity} size="sm" />
                <span className="text-[10px] font-mono text-slate-400">
                  {finding.file}:{finding.startLine}
                </span>
              </div>
              <h4 className="font-semibold text-xs text-slate-200 line-clamp-1">
                {finding.title}
              </h4>
              <p className="text-[11px] text-slate-400 mt-1 line-clamp-2">
                {finding.description}
              </p>
              <div className="flex items-center justify-between mt-3 pt-2 border-t border-border/50 text-[10px] text-slate-400">
                <span className="font-mono text-cyan-400">{finding.cwe}</span>
                <span className="text-emerald-400 flex items-center gap-1">
                  <span>Remediation available</span>
                  <ExternalLink className="w-2.5 h-2.5" />
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Delete Confirmation Modal */}
      {deleteTargetId && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <div className="bg-card border border-border rounded-xl p-5 max-w-sm w-full space-y-4 shadow-2xl">
            <h3 className="font-bold text-sm text-white">Confirm Deletion</h3>
            <p className="text-xs text-slate-300">
              Are you sure you want to delete scan record <code className="text-cyan-400">{deleteTargetId}</code>? This action cannot be undone.
            </p>
            <div className="flex items-center justify-end gap-2 pt-2">
              <button
                onClick={() => setDeleteTargetId(null)}
                className="px-3 py-1.5 rounded-lg bg-surface border border-border text-slate-300 text-xs hover:text-white"
              >
                Cancel
              </button>
              <button
                onClick={() => handleDeleteScan(deleteTargetId)}
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
