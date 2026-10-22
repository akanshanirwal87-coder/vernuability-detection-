import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { getScanById, getScans } from '../services/scanService';
import { 
  generatePdfReport, 
  exportJsonReport, 
  exportCsvReport 
} from '../services/reportService';
import type { ScanResult, VulnerabilityFinding } from '../types/scan';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { DemoDataBanner } from '../components/common/DemoDataBanner';
import { 
  FileText, 
  Download, 
  Printer, 
  FileSpreadsheet, 
  FileJson, 
  ArrowLeft, 
  ShieldCheck, 
  AlertTriangle, 
  Layers, 
  Clock, 
  CheckCircle2, 
  BookOpen,
  Info
} from 'lucide-react';
import { toast } from 'sonner';

export const ReportsPage: React.FC = () => {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();

  const [scan, setScan] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [availableScans, setAvailableScans] = useState<{ id: string; name: string }[]>([]);

  useEffect(() => {
    loadScansList();
  }, [scanId]);

  const loadScansList = async () => {
    setLoading(true);
    try {
      const allScans = await getScans();
      setAvailableScans(allScans.map(s => ({ id: s.id, name: `${s.projectName} (${s.fileName})` })));

      const targetId = scanId || (allScans.length > 0 ? allScans[0].id : 'scan-demo-01');
      const targetScan = await getScanById(targetId);
      setScan(targetScan);
    } catch (e) {
      toast.error('Failed to load report data');
    } finally {
      setLoading(false);
    }
  };

  const handleScanChange = async (id: string) => {
    navigate(`/reports/${id}`);
  };

  if (loading) {
    return (
      <div className="h-96 flex flex-col items-center justify-center space-y-3">
        <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin" />
        <p className="text-xs font-mono text-slate-400">Compiling executive security audit report...</p>
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="p-8 rounded-xl bg-card border border-border text-center space-y-3">
        <FileText className="w-10 h-10 text-slate-500 mx-auto" />
        <h2 className="text-base font-bold text-white">No Report Selected</h2>
        <p className="text-xs text-slate-400">Select an existing scan to view and export its security report.</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Top Header Controls (Hidden on print) */}
      <div className="no-print flex flex-wrap items-center justify-between gap-4 pb-3 border-b border-border">
        <div className="flex items-center gap-3">
          <button
            onClick={() => navigate('/dashboard')}
            className="p-1.5 rounded-lg bg-surface hover:bg-surface/80 border border-border text-slate-400 hover:text-white"
          >
            <ArrowLeft className="w-4 h-4" />
          </button>
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight">Security Audit Report</h1>
            <p className="text-xs text-slate-400 mt-1">
              Consolidated analysis results, risk scoring, vulnerability evidence, and remediation guidelines.
            </p>
          </div>
        </div>

        {/* Export & Actions Toolbar */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Target Scan Selector */}
          <select
            value={scan.id}
            onChange={(e) => handleScanChange(e.target.value)}
            className="bg-[#0B1020] border border-border rounded-lg px-3 py-1.5 text-xs text-slate-200 font-mono focus:outline-none"
          >
            {availableScans.map(s => (
              <option key={s.id} value={s.id}>
                {s.name}
              </option>
            ))}
          </select>

          {/* Download PDF */}
          <button
            onClick={() => {
              generatePdfReport(scan);
              toast.success('Generated PDF report download!');
            }}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-primary hover:bg-primary-hover text-white text-xs font-semibold shadow-sm"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Download PDF</span>
          </button>

          {/* Export JSON */}
          <button
            onClick={() => {
              exportJsonReport(scan);
              toast.success('Downloaded JSON report!');
            }}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surface hover:bg-surface/80 border border-border text-slate-300 text-xs font-medium"
            title="Export machine-readable JSON"
          >
            <FileJson className="w-3.5 h-3.5 text-cyan-400" />
            <span>Export JSON</span>
          </button>

          {/* Export CSV */}
          <button
            onClick={() => {
              exportCsvReport(scan);
              toast.success('Downloaded CSV findings table!');
            }}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surface hover:bg-surface/80 border border-border text-slate-300 text-xs font-medium"
            title="Export findings spreadsheet"
          >
            <FileSpreadsheet className="w-3.5 h-3.5 text-emerald-400" />
            <span>Export CSV</span>
          </button>

          {/* Print */}
          <button
            onClick={() => window.print()}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surface hover:bg-surface/80 border border-border text-slate-300 text-xs font-medium"
          >
            <Printer className="w-3.5 h-3.5" />
            <span>Print</span>
          </button>
        </div>
      </div>

      {scan.isDemo && (
        <DemoDataBanner message="Audit report synthesized from PaymentGateway demonstration fixtures." />
      )}

      {/* Printable Report Document Container */}
      <div className="bg-card border border-border rounded-2xl p-6 sm:p-10 space-y-8 shadow-xl text-slate-100">
        {/* Document Header Banner */}
        <div className="border-b border-border pb-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-primary font-bold text-xs uppercase tracking-wider font-mono">
                SecureCode AI Security Assessment
              </span>
              <span className="text-[10px] text-slate-400 font-mono bg-surface px-2 py-0.5 rounded border border-border">
                Scan ID: {scan.id}
              </span>
            </div>
            <h2 className="text-2xl font-extrabold text-white mt-1">
              {scan.projectName}
            </h2>
            <p className="text-xs text-slate-400 mt-1 font-mono">
              Target File: {scan.fileName} • Language: {scan.language.toUpperCase()} • Generated: {new Date(scan.createdAt).toUTCString()}
            </p>
          </div>

          <div className="p-3 rounded-xl bg-[#0F172A] border border-border text-right space-y-0.5">
            <span className="text-[10px] text-slate-400 font-mono uppercase">Max Severity Level</span>
            <div>
              <SeverityBadge severity={scan.highestSeverity} size="lg" />
            </div>
          </div>
        </div>

        {/* 1. Executive Summary */}
        <div className="space-y-3">
          <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider font-mono flex items-center gap-2">
            <BookOpen className="w-4 h-4 text-cyan-400" />
            <span>1. Executive Summary</span>
          </h3>
          <div className="p-4 rounded-xl bg-[#0B1020] border border-border text-xs text-slate-300 leading-relaxed space-y-2">
            <p>
              An automated hybrid static program analysis (AST parsing, sink identification, and CWE rule heuristics) was performed against <code className="text-cyan-400 font-mono">{scan.fileName}</code>.
            </p>
            <p>
              The scanner identified a total of <strong className="text-white">{scan.findingsCount.total} vulnerability findings</strong>.
              Of these, <strong className="text-red-400">{scan.findingsCount.critical} are classified as Critical</strong> and <strong className="text-orange-400">{scan.findingsCount.high} as High Severity</strong>.
              Immediate remediation is advised before moving this code to production environments.
            </p>
          </div>
        </div>

        {/* 2. Severity Breakdown Table */}
        <div className="space-y-3">
          <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider font-mono flex items-center gap-2">
            <Layers className="w-4 h-4 text-primary" />
            <span>2. Findings Distribution Matrix</span>
          </h3>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
            <div className="p-3 rounded-lg bg-red-950/20 border border-red-900/40">
              <span className="text-[10px] text-red-300 font-mono uppercase">Critical</span>
              <p className="text-2xl font-bold text-red-400 mt-1">{scan.findingsCount.critical}</p>
              <p className="text-[10px] text-slate-400">Direct RCE or Auth Bypass</p>
            </div>
            <div className="p-3 rounded-lg bg-orange-950/20 border border-orange-900/40">
              <span className="text-[10px] text-orange-300 font-mono uppercase">High</span>
              <p className="text-2xl font-bold text-orange-400 mt-1">{scan.findingsCount.high}</p>
              <p className="text-[10px] text-slate-400">Sensitive Data Exfiltration</p>
            </div>
            <div className="p-3 rounded-lg bg-amber-950/20 border border-amber-900/40">
              <span className="text-[10px] text-amber-300 font-mono uppercase">Medium</span>
              <p className="text-2xl font-bold text-amber-400 mt-1">{scan.findingsCount.medium}</p>
              <p className="text-[10px] text-slate-400">Weak Crypto or XSS</p>
            </div>
            <div className="p-3 rounded-lg bg-emerald-950/20 border border-emerald-900/40">
              <span className="text-[10px] text-emerald-300 font-mono uppercase">Low / Info</span>
              <p className="text-2xl font-bold text-emerald-400 mt-1">{scan.findingsCount.low}</p>
              <p className="text-[10px] text-slate-400">Best Practice Warnings</p>
            </div>
          </div>
        </div>

        {/* 3. Detailed Findings List */}
        <div className="space-y-4">
          <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider font-mono flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <span>3. Detailed Vulnerability Findings & Action Plan</span>
          </h3>

          <div className="space-y-4">
            {scan.findings.map((f, idx) => (
              <div key={f.id} className="p-5 rounded-xl bg-[#0F172A] border border-border space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono font-bold text-slate-400">#{idx + 1}</span>
                    <SeverityBadge severity={f.severity} size="sm" />
                    <span className="font-mono text-cyan-400 text-xs font-semibold">{f.cwe}</span>
                    <span className="text-slate-300 font-bold text-xs">{f.title}</span>
                  </div>
                  <span className="text-[11px] font-mono text-slate-400">
                    Location: {f.file}:{f.startLine}
                  </span>
                </div>

                <p className="text-xs text-slate-300 leading-relaxed">
                  {f.description}
                </p>

                {/* Evidence snippet */}
                <div>
                  <span className="text-[10px] font-mono text-red-400 uppercase font-bold block mb-1">
                    Vulnerable Code Region:
                  </span>
                  <div className="p-2.5 rounded bg-[#0B1020] border border-red-950/80 font-mono text-[11px] text-red-300 whitespace-pre-wrap overflow-x-auto">
                    {f.evidence}
                  </div>
                </div>

                {/* Remediation code */}
                <div>
                  <span className="text-[10px] font-mono text-emerald-400 uppercase font-bold block mb-1">
                    Recommended Secure Remediation:
                  </span>
                  <div className="p-2.5 rounded bg-[#0B1020] border border-emerald-950/80 font-mono text-[11px] text-emerald-300 whitespace-pre-wrap overflow-x-auto">
                    {f.remediationCode}
                  </div>
                  <p className="text-[11px] text-slate-400 mt-1">
                    {f.remediationExplanation}
                  </p>
                </div>

                {/* References */}
                <div className="pt-2 border-t border-border/50 flex flex-wrap items-center gap-4 text-[10px] text-slate-400 font-mono">
                  <span>OWASP: {f.owaspCategory}</span>
                  {f.references.map((ref, rIdx) => (
                    <a key={rIdx} href={ref} target="_blank" rel="noreferrer" className="text-cyan-400 hover:underline">
                      MITRE Reference ↗
                    </a>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* 4. Limitations & Disclaimer Footer */}
        <div className="border-t border-border pt-6 text-xs text-slate-400 space-y-1">
          <p className="font-semibold text-slate-300">
            Audit Scope, Limitations & Verification Policy:
          </p>
          <p className="text-[11px] leading-relaxed">
            This security audit report was automatically synthesized by SecureCode AI using AST structural inspection, data-flow taint tracing, and OWASP rule-matching. Automated analysis cannot guarantee the detection of all runtime vulnerabilities. Developers must conduct unit testing, integration verification, and peer code reviews before deploying suggested patches.
          </p>
        </div>
      </div>
    </div>
  );
};
