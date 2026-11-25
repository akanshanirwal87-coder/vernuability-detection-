import React from 'react';
import type { VulnerabilityFinding } from '../../types/scan';
import { getSeverityStyle } from '../../utils/formatSeverity';
import {
  ShieldAlert,
  AlertTriangle,
  FileCode,
  ArrowRight,
  ExternalLink,
  BookOpen,
  Wrench,
  CheckCircle2,
} from 'lucide-react';
import { Link } from 'react-router-dom';

interface FindingDetailsProps {
  finding: VulnerabilityFinding;
  scanId: string;
}

export const FindingDetails: React.FC<FindingDetailsProps> = ({ finding, scanId }) => {
  const style = getSeverityStyle(finding.severity);

  return (
    <div className="space-y-5 rounded-2xl border border-slate-800 bg-[#111827] p-6 shadow-xl">
      {/* Title & Metadata Header */}
      <div className="border-b border-slate-800 pb-4">
        <div className="flex flex-wrap items-center gap-2 mb-2">
          <span
            className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-bold border ${style.badgeBg} ${style.badgeText} ${style.badgeBorder}`}
          >
            <span className={`h-1.5 w-1.5 rounded-full ${style.dotColor}`} />
            {finding.severity}
          </span>
          <span className="font-mono text-xs font-bold text-cyan-400 rounded bg-cyan-950/40 border border-cyan-800/50 px-2 py-0.5">
            {finding.cwe}
          </span>
          {finding.owaspCategory && (
            <span className="font-mono text-xs text-slate-300 rounded bg-slate-800 px-2 py-0.5">
              {finding.owaspCategory}
            </span>
          )}
          <span className="rounded bg-slate-800 px-2 py-0.5 font-mono text-xs text-indigo-300 border border-indigo-500/30">
            {Math.round(finding.confidence * 100)}% Confidence
          </span>
        </div>

        <h3 className="text-xl font-bold text-white leading-snug">{finding.title}</h3>
        <p className="mt-1 font-mono text-xs text-slate-400">
          Target: {finding.file}:{finding.startLine}
        </p>
      </div>

      {/* Description & Impact */}
      <div className="space-y-3">
        <div>
          <h5 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            Vulnerability Description
          </h5>
          <p className="mt-1 text-sm text-slate-300 leading-relaxed">{finding.description}</p>
        </div>

        {finding.impact && (
          <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-3.5">
            <h5 className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-red-400">
              <AlertTriangle className="h-4 w-4" />
              <span>Exploitation Impact</span>
            </h5>
            <p className="mt-1 text-xs text-slate-300 leading-relaxed">{finding.impact}</p>
          </div>
        )}
      </div>

      {/* 3-Step Taint Flow Trace */}
      {finding.dataFlow && finding.dataFlow.length > 0 && (
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
          <h5 className="text-xs font-semibold uppercase tracking-wider text-cyan-400 mb-3">
            Taint Analysis Propagation Trace
          </h5>
          <div className="space-y-3">
            {finding.dataFlow.map((step, idx) => (
              <div key={idx} className="flex items-start gap-3 text-xs">
                <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-slate-800 font-mono text-[10px] font-bold text-slate-300 border border-slate-700">
                  {step.step || idx + 1}
                </span>
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-white">{step.label}</span>
                    <span className="rounded bg-slate-800 px-1.5 py-0.2 font-mono text-[10px] text-slate-400">
                      Line {step.line}
                    </span>
                    <span className="text-[10px] font-mono text-cyan-400 uppercase">
                      [{step.type}]
                    </span>
                  </div>
                  {step.codeSnippet && (
                    <pre className="mt-1 rounded bg-[#0B1020] p-2 font-mono text-[11px] text-amber-300 border border-slate-800 overflow-x-auto">
                      {step.codeSnippet}
                    </pre>
                  )}
                  {step.description && (
                    <p className="mt-1 text-[11px] text-slate-400">{step.description}</p>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Vulnerable Code Snippet */}
      {finding.vulnerableCode && (
        <div>
          <h5 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
            Detected Code Snippet
          </h5>
          <pre className="rounded-xl border border-red-500/30 bg-slate-950 p-3.5 font-mono text-xs text-red-300 overflow-x-auto">
            {finding.vulnerableCode}
          </pre>
        </div>
      )}

      {/* Remediation Quick Link */}
      <div className="pt-2 flex justify-end">
        <Link
          to={`/remediation/${scanId}`}
          className="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-xs font-semibold text-white hover:bg-indigo-500 transition shadow-lg shadow-indigo-600/20"
        >
          <Wrench className="h-4 w-4" />
          <span>Open AI Remediation Workspace →</span>
        </Link>
      </div>
    </div>
  );
};

export default FindingDetails;
