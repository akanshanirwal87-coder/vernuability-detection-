import React from 'react';
import type { ExecutiveAuditReport } from '../../services/reportService';
import { getSeverityStyle } from '../../utils/formatSeverity';
import { formatDate } from '../../utils/formatDate';
import { ShieldAlert, ShieldCheck, AlertTriangle, CheckCircle2, FileText } from 'lucide-react';

interface ReportSummaryProps {
  report: ExecutiveAuditReport;
}

export const ReportSummary: React.FC<ReportSummaryProps> = ({ report }) => {
  const style = getSeverityStyle(report.highestSeverity);

  return (
    <div className="space-y-6 rounded-2xl border border-slate-800 bg-[#111827] p-6 shadow-xl">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-2">
            <span className="rounded bg-indigo-500/20 px-2 py-0.5 font-mono text-[11px] font-bold text-indigo-400 border border-indigo-500/30">
              AUDIT REPORT
            </span>
            <span className="font-mono text-xs text-slate-400">Scan ID: {report.scanId}</span>
          </div>
          <h2 className="mt-1 text-2xl font-bold text-white">
            {report.projectName} — {report.fileName}
          </h2>
          <p className="mt-1 text-xs text-slate-400">
            Audit compiled at {formatDate(report.generatedAt)} • Target Language: {report.language.toUpperCase()}
          </p>
        </div>

        {/* Risk Score Gauge */}
        <div className="flex items-center gap-4 rounded-xl border border-slate-800 bg-slate-900/60 p-4 shrink-0">
          <div>
            <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
              Aggregated Risk Score
            </span>
            <div className="flex items-baseline gap-1 mt-0.5">
              <span
                className={`text-3xl font-black ${
                  report.riskScore > 60
                    ? 'text-red-400'
                    : report.riskScore > 30
                    ? 'text-amber-400'
                    : 'text-emerald-400'
                }`}
              >
                {report.riskScore}
              </span>
              <span className="text-xs text-slate-500 font-mono">/ 100</span>
            </div>
          </div>
          <div
            className={`h-10 w-10 rounded-full flex items-center justify-center border ${
              report.riskScore > 60
                ? 'border-red-500/30 bg-red-500/10 text-red-400'
                : report.riskScore > 30
                ? 'border-amber-500/30 bg-amber-500/10 text-amber-400'
                : 'border-emerald-500/30 bg-emerald-500/10 text-emerald-400'
            }`}
          >
            {report.riskScore > 60 ? (
              <AlertTriangle className="h-5 w-5" />
            ) : (
              <ShieldCheck className="h-5 w-5" />
            )}
          </div>
        </div>
      </div>

      {/* Metrics Triad */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-4">
          <span className="text-xs font-medium text-slate-400">Total Vulnerabilities</span>
          <h4 className="text-2xl font-bold text-white mt-1">{report.totalFindings}</h4>
          <span className="text-[11px] text-slate-500 font-mono">Identified sinks</span>
        </div>
        <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-4">
          <span className="text-xs font-medium text-red-300">Critical Severity</span>
          <h4 className="text-2xl font-bold text-red-400 mt-1">{report.criticalFindings}</h4>
          <span className="text-[11px] text-red-400/80 font-mono">CVSS 9.0+ equivalent</span>
        </div>
        <div className="rounded-xl border border-amber-500/20 bg-amber-500/5 p-4">
          <span className="text-xs font-medium text-amber-300">High Severity</span>
          <h4 className="text-2xl font-bold text-amber-400 mt-1">{report.highFindings}</h4>
          <span className="text-[11px] text-amber-400/80 font-mono">CVSS 7.0 - 8.9</span>
        </div>
      </div>

      {/* Executive Summary */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-5">
        <h4 className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-slate-300 mb-2">
          <FileText className="h-4 w-4 text-indigo-400" />
          <span>Executive Audit Assessment</span>
        </h4>
        <p className="text-xs text-slate-300 leading-relaxed">{report.executiveSummary}</p>
      </div>

      {/* Recommendations */}
      {report.recommendations && report.recommendations.length > 0 && (
        <div className="rounded-xl border border-indigo-500/20 bg-indigo-950/20 p-5">
          <h4 className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-indigo-300 mb-3">
            <ShieldCheck className="h-4 w-4 text-indigo-400" />
            <span>Remediation & Hardening Recommendations</span>
          </h4>
          <ul className="space-y-2 text-xs text-slate-300">
            {report.recommendations.map((rec, i) => (
              <li key={i} className="flex items-start gap-2.5">
                <CheckCircle2 className="h-4 w-4 text-indigo-400 shrink-0 mt-0.5" />
                <span>{rec}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
};

export default ReportSummary;
