import React from 'react';
import type { VulnerabilityFinding } from '../../types/scan';
import { BookOpen, CheckCircle2, ShieldCheck, ExternalLink } from 'lucide-react';

interface FixExplanationProps {
  finding: VulnerabilityFinding;
}

export const FixExplanation: React.FC<FixExplanationProps> = ({ finding }) => {
  return (
    <div className="space-y-4 rounded-xl border border-slate-800 bg-[#111827] p-5">
      <div>
        <h4 className="flex items-center gap-2 text-sm font-bold text-white">
          <ShieldCheck className="h-4 w-4 text-emerald-400" />
          <span>Remediation Rationale & Technical Explanation</span>
        </h4>
        <p className="mt-1.5 text-xs text-slate-300 leading-relaxed">
          {finding.remediationExplanation ||
            'This remediation neutralizes the vulnerability by eliminating untrusted input injection into the target sink and using parameterized APIs.'}
        </p>
      </div>

      {finding.bestPractices && finding.bestPractices.length > 0 && (
        <div className="rounded-lg bg-slate-900/60 border border-slate-800 p-3.5">
          <h5 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
            Secure Coding Best Practices
          </h5>
          <ul className="space-y-1.5 text-xs text-slate-300">
            {finding.bestPractices.map((bp, i) => (
              <li key={i} className="flex items-start gap-2">
                <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400 mt-0.5 shrink-0" />
                <span>{bp}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {finding.references && finding.references.length > 0 && (
        <div>
          <h5 className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 mb-1">
            Authoritative Security References
          </h5>
          <div className="flex flex-wrap gap-2">
            {finding.references.map((ref, i) => (
              <a
                key={i}
                href={ref}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1 rounded bg-slate-800 px-2 py-1 text-[11px] text-cyan-400 hover:underline border border-slate-700"
              >
                <ExternalLink className="h-3 w-3" />
                <span className="truncate max-w-[280px]">{ref}</span>
              </a>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default FixExplanation;
