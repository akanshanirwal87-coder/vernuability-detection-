import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { 
  getScanById 
} from '../services/scanService';
import { 
  generatePdfReport, 
  exportJsonReport, 
  exportCsvReport 
} from '../services/reportService';
import type { 
  ScanResult, 
  VulnerabilityFinding, 
  Severity, 
  VulnerabilityCategory 
} from '../types/scan';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { DemoDataBanner } from '../components/common/DemoDataBanner';
import { DataFlowDiagram } from '../components/common/DataFlowDiagram';
import { AnimatedCounter } from '../components/common/AnimatedCounter';
import { Skeleton, FindingsListSkeleton } from '../components/common/Skeleton';
import { 
  ShieldAlert, 
  Search, 
  Filter, 
  Download, 
  ArrowLeft, 
  RotateCcw, 
  FileCode, 
  ExternalLink, 
  X, 
  CheckCircle2, 
  AlertTriangle,
  Code2,
  BookOpen,
  Wrench,
  Layers,
  Brain
} from 'lucide-react';
import { toast } from 'sonner';
import Editor from '@monaco-editor/react';

export const ScanResultsPage: React.FC = () => {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();

  const [scan, setScan] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [selectedFinding, setSelectedFinding] = useState<VulnerabilityFinding | null>(null);
  const [activeViewMode, setActiveViewMode] = useState<'findings' | 'source'>('findings');

  // Filters and search
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');

  useEffect(() => {
    if (scanId) {
      loadScan(scanId);
    }
  }, [scanId]);

  const loadScan = async (id: string) => {
    setLoading(true);
    try {
      const result = await getScanById(id);
      if (result) {
        setScan(result);
        if (result.findings.length > 0) {
          setSelectedFinding(result.findings[0]);
        }
      } else {
        toast.error('Scan not found');
      }
    } catch (err) {
      toast.error('Failed to load scan');
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="space-y-6 animate-fade-in" aria-label="Loading scan results">
        {/* Header Skeleton */}
        <div className="flex flex-wrap items-center justify-between gap-4 pb-2 border-b border-border">
          <div className="flex items-center gap-3">
            <Skeleton className="w-8 h-8" rounded="lg" />
            <div className="space-y-2">
              <Skeleton className="h-6 w-48" />
              <Skeleton className="h-3 w-72" />
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Skeleton className="h-8 w-28" rounded="lg" />
            <Skeleton className="h-8 w-32" rounded="lg" />
          </div>
        </div>

        {/* Severity Summary Bar Skeleton */}
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="p-3.5 rounded-xl bg-card border border-border flex items-center justify-between">
              <div className="space-y-1.5 flex-1 mr-2">
                <Skeleton className="h-3 w-16" />
                <Skeleton className="h-6 w-10" />
              </div>
              <Skeleton className="w-5 h-5" rounded="sm" />
            </div>
          ))}
        </div>

        {/* Findings Grid Skeleton */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          <div className="lg:col-span-5 space-y-3">
            <FindingsListSkeleton count={4} />
          </div>
          <div className="lg:col-span-7">
            <div className="p-6 rounded-xl bg-card border border-border h-96 space-y-4">
              <Skeleton className="h-5 w-48" />
              <Skeleton className="h-3 w-full" />
              <Skeleton className="h-3 w-3/4" />
              <Skeleton className="h-44 w-full" rounded="lg" />
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="p-8 rounded-xl bg-card border border-border text-center space-y-4 animate-scale-in">
        <ShieldAlert className="w-10 h-10 text-slate-500 mx-auto" />
        <h2 className="text-lg font-bold text-white">Scan Not Found</h2>
        <p className="text-xs text-slate-400">The requested scan ID does not exist or has been removed.</p>
        <button
          onClick={() => navigate('/scan')}
          className="px-4 py-2 rounded-lg bg-primary hover:bg-primary-hover active:scale-95 text-white text-xs font-semibold transition-all duration-200 hover:-translate-y-0.5"
        >
          Start New Scan
        </button>
      </div>
    );
  }

  // Filter findings
  const filteredFindings = scan.findings.filter(f => {
    const matchesSearch = 
      f.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.cwe.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.file.toLowerCase().includes(searchQuery.toLowerCase());
    
    const matchesSeverity = severityFilter === 'ALL' || f.severity === severityFilter;
    const matchesCategory = categoryFilter === 'ALL' || f.category === categoryFilter;

    return matchesSearch && matchesSeverity && matchesCategory;
  });

  return (
    <div className="space-y-6">
      {/* Top Banner & Header */}
      <div className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-4 pb-2 border-b border-border">
          <div className="flex items-center gap-3">
            <button
              onClick={() => navigate('/scan')}
              className="p-1.5 rounded-lg bg-surface hover:bg-surface/80 border border-border text-slate-400 hover:text-white transition-all duration-200 hover:-translate-x-0.5 active:scale-95"
              title="Return to editor"
            >
              <ArrowLeft className="w-4 h-4" />
            </button>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-2xl font-bold text-white tracking-tight">
                  {scan.projectName}
                </h1>
                <span className="text-xs font-mono text-cyan-400 bg-cyan-950/60 border border-cyan-800/40 px-2 py-0.5 rounded">
                  {scan.id}
                </span>
                {scan.isDemo && (
                  <span className="text-[10px] font-bold text-amber-400 bg-amber-950/60 border border-amber-800/40 px-1.5 py-0.5 rounded uppercase">
                    Demo Scan
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-400 mt-1 font-mono">
                File: {scan.fileName} • {scan.language.toUpperCase()} • {scan.linesAnalyzed} lines • Completed in {scan.durationMs}ms
              </p>
            </div>
          </div>

          {/* Action CTAs */}
          <div className="flex items-center gap-2">
            <button
              onClick={() => generatePdfReport(scan)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surface hover:bg-surface/80 border border-border text-slate-200 text-xs font-medium transition-all duration-200 hover:-translate-y-0.5 active:scale-95"
              title="Download professional PDF security audit"
            >
              <Download className="w-3.5 h-3.5 text-cyan-400" />
              <span>Download PDF</span>
            </button>
            <button
              onClick={() => navigate(`/remediation/${scan.id}`)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-primary hover:bg-primary-hover active:scale-95 text-white text-xs font-semibold transition-all duration-200 hover:-translate-y-0.5 shadow-sm shadow-blue-500/20"
            >
              <Wrench className="w-3.5 h-3.5" />
              <span>AI Remediation</span>
            </button>
            <button
              onClick={() => navigate('/scan')}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surface hover:bg-surface/80 border border-border text-slate-300 text-xs font-medium transition-all duration-200 hover:-translate-y-0.5 active:scale-95"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>Rescan</span>
            </button>
          </div>
        </div>

        {scan.isDemo && (
          <DemoDataBanner message="Showing deterministic sample findings from PaymentGateway demo suite." />
        )}
      </div>

      {/* Severity Summary Bar */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        <div className="animate-fade-in-up stagger-1 p-3.5 rounded-xl bg-card border border-border flex items-center justify-between transition-all duration-200 hover:-translate-y-0.5 hover:border-slate-700">
          <div>
            <p className="text-[11px] font-medium text-slate-400">Total Findings</p>
            <h3 className="text-xl font-bold text-white mt-0.5">
              <AnimatedCounter value={scan.findingsCount.total} />
            </h3>
          </div>
          <Layers className="w-4 h-4 text-slate-400" />
        </div>

        <div className={`animate-fade-in-up stagger-2 p-3.5 rounded-xl bg-red-950/20 border border-red-900/40 flex items-center justify-between transition-all duration-200 hover:-translate-y-0.5 ${scan.findingsCount.critical > 0 ? 'animate-pulse-critical' : ''}`}>
          <div>
            <p className="text-[11px] font-medium text-red-300">Critical</p>
            <h3 className="text-xl font-bold text-red-400 mt-0.5 flex items-center gap-1">
              <AnimatedCounter value={scan.findingsCount.critical} />
            </h3>
          </div>
          <ShieldAlert className="w-4 h-4 text-red-400" />
        </div>

        <div className="animate-fade-in-up stagger-3 p-3.5 rounded-xl bg-orange-950/20 border border-orange-900/40 flex items-center justify-between transition-all duration-200 hover:-translate-y-0.5">
          <div>
            <p className="text-[11px] font-medium text-orange-300">High</p>
            <h3 className="text-xl font-bold text-orange-400 mt-0.5">
              <AnimatedCounter value={scan.findingsCount.high} />
            </h3>
          </div>
          <AlertTriangle className="w-4 h-4 text-orange-400" />
        </div>

        <div className="animate-fade-in-up stagger-4 p-3.5 rounded-xl bg-amber-950/20 border border-amber-900/40 flex items-center justify-between transition-all duration-200 hover:-translate-y-0.5">
          <div>
            <p className="text-[11px] font-medium text-amber-300">Medium</p>
            <h3 className="text-xl font-bold text-amber-400 mt-0.5">
              <AnimatedCounter value={scan.findingsCount.medium} />
            </h3>
          </div>
          <AlertTriangle className="w-4 h-4 text-amber-400" />
        </div>

        <div className="animate-fade-in-up stagger-5 p-3.5 rounded-xl bg-emerald-950/20 border border-emerald-900/40 flex items-center justify-between transition-all duration-200 hover:-translate-y-0.5">
          <div>
            <p className="text-[11px] font-medium text-emerald-300">Low</p>
            <h3 className="text-xl font-bold text-emerald-400 mt-0.5">
              <AnimatedCounter value={scan.findingsCount.low} />
            </h3>
          </div>
          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
        </div>
      </div>

      {/* AI Model & Dataset Pipeline Verification Banner */}
      {scan.mlAnalysis && (
        <div className="p-3.5 rounded-xl border border-purple-500/30 bg-purple-950/20 flex flex-wrap items-center justify-between gap-3 text-xs">
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 rounded-lg bg-purple-500/20 text-purple-300">
              <Brain className="w-4 h-4" />
            </div>
            <div>
              <span className="text-white font-semibold block">
                AI Vulnerability Model Verification Active
              </span>
              <span className="text-slate-400 text-[11px]">
                {scan.mlAnalysis.modelName} • {scan.mlAnalysis.accuracy}% Accuracy ({scan.mlAnalysis.totalDatasetSamples} dataset samples)
              </span>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-blue-500/20 text-blue-300 border border-blue-500/30">
              Grounded in OSV.dev
            </span>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
              ManageEngine Endpoint Baselines
            </span>
          </div>
        </div>
      )}

      {/* View Switcher: Findings Table vs Full Source Code Viewer */}
      <div className="flex items-center gap-2 border-b border-border pb-3">
        <button
          onClick={() => setActiveViewMode('findings')}
          className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
            activeViewMode === 'findings'
              ? 'bg-primary text-white font-semibold shadow-sm'
              : 'text-slate-400 hover:text-white bg-surface/50 border border-border'
          }`}
        >
          <Layers className="w-3.5 h-3.5" />
          <span>Findings Investigation View</span>
        </button>
        <button
          onClick={() => setActiveViewMode('source')}
          className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
            activeViewMode === 'source'
              ? 'bg-primary text-white font-semibold shadow-sm'
              : 'text-slate-400 hover:text-white bg-surface/50 border border-border'
          }`}
        >
          <Code2 className="w-3.5 h-3.5" />
          <span>Source Code Viewer (Line Highlighting)</span>
        </button>
      </div>

      {activeViewMode === 'source' ? (
        /* Source Code Viewer Mode with Line Highlighting */
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Finding Quick Jumper List */}
          <div className="lg:col-span-4 space-y-3">
            <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider font-mono">
              Vulnerability Markers in File
            </h3>
            <div className="space-y-2">
              {scan.findings.map((finding) => {
                const isSelected = selectedFinding?.id === finding.id;
                return (
                  <div
                    key={finding.id}
                    onClick={() => setSelectedFinding(finding)}
                    className={`p-3 rounded-lg border transition-all cursor-pointer text-xs ${
                      isSelected
                        ? 'bg-[#162032] border-primary shadow-sm'
                        : 'bg-card border-border hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <SeverityBadge severity={finding.severity} size="sm" />
                      <span className="font-mono text-cyan-400 text-[11px] font-semibold">
                        Lines {finding.startLine}–{finding.endLine}
                      </span>
                    </div>
                    <p className="font-medium text-slate-200 line-clamp-1">{finding.title}</p>
                    <span className="text-[10px] text-slate-400 font-mono">{finding.cwe}</span>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Monaco Source Code Viewer */}
          <div className="lg:col-span-8 space-y-3">
            {selectedFinding && (
              <div className="p-3 rounded-lg bg-red-950/40 border border-red-800/60 flex items-center justify-between text-xs">
                <div className="flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-red-400 shrink-0" />
                  <span className="text-red-200">
                    Target Finding: <strong>{selectedFinding.title}</strong> at lines {selectedFinding.startLine}–{selectedFinding.endLine}
                  </span>
                </div>
                <button
                  onClick={() => navigate(`/remediation/${scan.id}`)}
                  className="px-2.5 py-1 rounded bg-primary hover:bg-primary-hover text-white text-[11px] font-semibold"
                >
                  Remediate
                </button>
              </div>
            )}

            <div className="h-[520px] rounded-xl bg-card border border-border overflow-hidden shadow-sm">
              <Editor
                height="100%"
                language={scan.language}
                value={scan.sourceCode}
                theme="vs-dark"
                options={{
                  readOnly: true,
                  minimap: { enabled: true },
                  fontSize: 13,
                  lineNumbers: 'on',
                  scrollBeyondLastLine: false,
                  wordWrap: 'on',
                  automaticLayout: true,
                  padding: { top: 12, bottom: 12 },
                }}
              />
            </div>
          </div>
        </div>
      ) : (
        /* Main Investigation Workspace: Left Table (7 Cols) / Right Detail Panel (5 Cols) */
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Filter Controls and Findings Table */}
        <div className="lg:col-span-7 space-y-4">
          {/* Filters Bar */}
          <div className="p-3 rounded-xl bg-card border border-border flex flex-wrap items-center justify-between gap-3 text-xs">
            {/* Search Input */}
            <div className="relative flex-1 min-w-[180px]">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search CWE, description, title..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full bg-[#0B1020] border border-border rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-primary"
              />
            </div>

            {/* Severity Filter */}
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="bg-[#0B1020] border border-border rounded-lg px-2.5 py-1.5 text-xs text-slate-200 font-mono focus:outline-none"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>

            {/* Clear Filters */}
            {(searchQuery || severityFilter !== 'ALL' || categoryFilter !== 'ALL') && (
              <button
                onClick={() => {
                  setSearchQuery('');
                  setSeverityFilter('ALL');
                  setCategoryFilter('ALL');
                }}
                className="text-[11px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-mono"
              >
                <X className="w-3 h-3" />
                <span>Reset</span>
              </button>
            )}
          </div>

          {/* Findings List */}
          {filteredFindings.length === 0 ? (
            <div className="p-10 rounded-xl bg-card border border-border text-center space-y-3">
              <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto" />
              <h3 className="font-semibold text-sm text-slate-200">No Findings Reported</h3>
              <p className="text-xs text-slate-400 max-w-md mx-auto">
                No vulnerabilities matched the active filter criteria. Note: A clean scan does not prove the application is completely secure.
              </p>
            </div>
          ) : (
            <div className="space-y-2.5">
              {filteredFindings.map((finding) => {
                const isSelected = selectedFinding?.id === finding.id;
                return (
                  <div
                    key={finding.id}
                    onClick={() => setSelectedFinding(finding)}
                    className={`p-3.5 rounded-xl border transition-all duration-200 cursor-pointer ${
                      isSelected
                        ? 'bg-[#162032] border-primary shadow-md shadow-blue-950/40 -translate-y-0.5 ring-1 ring-primary/40'
                        : 'bg-card border-border hover:border-slate-700 hover:bg-[#131B2E] hover:-translate-y-0.5 hover:shadow-md hover:shadow-cyan-950/20'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1.5">
                      <div className="flex flex-wrap items-center gap-2">
                        <SeverityBadge severity={finding.severity} size="sm" />
                        <span className="font-mono text-cyan-400 text-xs font-semibold">
                          {finding.cwe}
                        </span>
                        {finding.cve && (
                          <span className="font-mono text-[10px] text-cyan-300 bg-cyan-950/60 border border-cyan-800/40 px-1.5 py-0.5 rounded">
                            {finding.cve}
                          </span>
                        )}
                        {finding.detectionSource === 'HYBRID_AST_AND_ML' && (
                          <span className="font-mono text-[9px] text-purple-300 bg-purple-950/60 border border-purple-800/40 px-1.5 py-0.5 rounded">
                            AST + AI
                          </span>
                        )}
                        {finding.detectionSource === 'OSV_DATABASE' && (
                          <span className="font-mono text-[9px] text-blue-300 bg-blue-950/60 border border-blue-800/40 px-1.5 py-0.5 rounded">
                            OSV.dev
                          </span>
                        )}
                        {finding.detectionSource === 'MANAGEENGINE_BASELINE' && (
                          <span className="font-mono text-[9px] text-emerald-300 bg-emerald-950/60 border border-emerald-800/40 px-1.5 py-0.5 rounded">
                            ManageEngine
                          </span>
                        )}
                      </div>
                      <span className="text-[11px] font-mono text-slate-400">
                        {finding.file}:{finding.startLine}
                      </span>
                    </div>

                    <h4 className="font-semibold text-xs text-slate-100">
                      {finding.title}
                    </h4>

                    <p className="text-[11px] text-slate-400 mt-1 line-clamp-2">
                      {finding.description}
                    </p>

                    <div className="flex items-center justify-between mt-2.5 pt-2 border-t border-border/40 text-[10px]">
                      <span className="text-slate-500 font-mono">
                        Confidence: {(finding.confidence * 100).toFixed(0)}%
                      </span>
                      <span className="text-emerald-400 font-medium flex items-center gap-1">
                        <span>Fix Ready</span>
                        <Wrench className="w-3 h-3" />
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Right Column: Finding Investigation Details Drawer (5 Cols) */}
        <div className="lg:col-span-5">
          {selectedFinding ? (
            <div className="rounded-xl bg-card border border-border p-5 space-y-5 sticky top-20 shadow-xl">
              {/* Finding Title & Badges */}
              <div className="space-y-2 pb-3 border-b border-border">
                <div className="flex items-center justify-between">
                  <SeverityBadge severity={selectedFinding.severity} size="md" />
                  <span className="text-xs font-mono text-slate-400">
                    Confidence: {(selectedFinding.confidence * 100).toFixed(0)}%
                  </span>
                </div>
                <h3 className="text-sm font-bold text-white leading-snug">
                  {selectedFinding.title}
                </h3>
                <div className="flex flex-wrap items-center gap-2 text-[11px] font-mono text-slate-400">
                  <span className="bg-surface px-2 py-0.5 rounded border border-border text-cyan-400">
                    {selectedFinding.cwe}
                  </span>
                  {selectedFinding.cve && (
                    <span className="bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800/40 text-cyan-300">
                      {selectedFinding.cve}
                    </span>
                  )}
                  {selectedFinding.detectionSource && (
                    <span className="bg-purple-950/60 px-2 py-0.5 rounded border border-purple-800/40 text-purple-300">
                      Provenance: {selectedFinding.detectionSource}
                    </span>
                  )}
                  <span className="bg-surface px-2 py-0.5 rounded border border-border">
                    {selectedFinding.owaspCategory}
                  </span>
                  <span className="text-slate-400">
                    {selectedFinding.file}:{selectedFinding.startLine}
                  </span>
                </div>
              </div>

              {/* Description & Impact */}
              <div className="space-y-2 text-xs">
                <h4 className="font-semibold text-slate-300 uppercase tracking-wider text-[11px]">
                  Vulnerability Description & Root Cause
                </h4>
                <p className="text-slate-300 leading-relaxed bg-[#0B1020] p-3 rounded-lg border border-border">
                  {selectedFinding.description}
                </p>
              </div>

              {/* Supporting Evidence Code Snippet */}
              <div className="space-y-1.5 text-xs">
                <h4 className="font-semibold text-slate-300 uppercase tracking-wider text-[11px]">
                  Analysis Evidence (Affected Lines)
                </h4>
                <div className="p-2.5 rounded-lg bg-red-950/20 border border-red-900/60 font-mono text-[11px] text-red-300 whitespace-pre-wrap overflow-x-auto">
                  {selectedFinding.evidence}
                </div>
              </div>

              {/* Taint Data Flow Path Diagram */}
              {selectedFinding.dataFlow && selectedFinding.dataFlow.length > 0 && (
                <div className="pt-2 border-t border-border">
                  <DataFlowDiagram steps={selectedFinding.dataFlow} />
                </div>
              )}

              {/* Security Impact */}
              <div className="space-y-1 text-xs">
                <h4 className="font-semibold text-amber-400 uppercase tracking-wider text-[11px] flex items-center gap-1.5">
                  <AlertTriangle className="w-3.5 h-3.5" />
                  <span>Exploitability Impact</span>
                </h4>
                <p className="text-slate-300 text-[11px] leading-relaxed">
                  {selectedFinding.impact}
                </p>
              </div>

              {/* Suggested Remediation Box */}
              <div className="p-3.5 rounded-lg bg-emerald-950/20 border border-emerald-900/50 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-emerald-400 flex items-center gap-1.5">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>Recommended Secure Alternative</span>
                  </span>
                </div>
                <div className="bg-[#0B1020] p-2 rounded border border-emerald-800/40 font-mono text-[11px] text-emerald-300 overflow-x-auto">
                  {selectedFinding.remediationCode}
                </div>
                <p className="text-[11px] text-slate-300">
                  {selectedFinding.remediationExplanation}
                </p>
              </div>

              {/* Remediation Action Button */}
              <button
                onClick={() => navigate(`/remediation/${scan.id}`)}
                className="w-full py-2.5 rounded-lg bg-primary hover:bg-primary-hover text-white text-xs font-semibold flex items-center justify-center gap-2 transition-colors shadow-md"
              >
                <Wrench className="w-4 h-4" />
                <span>Open in AI Remediation Workspace</span>
              </button>
            </div>
          ) : (
            <div className="p-8 rounded-xl bg-card border border-border text-center text-xs text-slate-400">
              Select a finding from the table to inspect details.
            </div>
          )}
        </div>
      </div>
      )}
    </div>
  );
};
