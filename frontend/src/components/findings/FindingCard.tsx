import React from 'react';
import type { VulnerabilityFinding } from '../../types/scan';
import { getSeverityStyle } from '../../utils/formatSeverity';
import { ShieldAlert, ExternalLink, ChevronRight, CheckCircle2, AlertCircle } from 'lucide-react';

interface FindingCardProps {
  finding: VulnerabilityFinding;
  isSelected?: boolean;
  onClick?: () => void;
  onStatusChange?: (status: string) => void;
}

export const FindingCard: React.FC<FindingCardProps> = ({
  finding,
  isSelected = false,
  onClick,
  onStatusChange,
}) => {
  const style = getSeverityStyle(finding.severity);

  return (
    <div
      onClick={onClick}
      className={`group relative rounded-xl border p-4 transition-all cursor-pointer ${
        isSelected
          ? 'border-indigo-500 bg-indigo-950/20 shadow-lg shadow-indigo-950/30'
          : 'border-slate-800 bg-[#111827] hover:border-slate-700 hover:bg-[#111827]/80'
      }`}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-2">
          <span
            className={`inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[10px] font-bold border ${style.badgeBg} ${style.badgeText} ${style.badgeBorder}`}
          >
            <span className={`h-1.5 w-1.5 rounded-full ${style.dotColor}`} />
            {finding.severity}
          </span>
          <span className="font-mono text-xs font-semibold text-cyan-400">
            {finding.cwe}
          </span>
          {finding.owaspCategory && (
            <span className="text-[10px] text-slate-500 font-mono hidden sm:inline">
              {finding.owaspCategory.slice(0, 8)}
            </span>
          )}
        </div>

        {/* Confidence pill */}
        <span className="rounded bg-slate-800 px-2 py-0.5 font-mono text-[10px] text-slate-400 border border-slate-700">
          {Math.round(finding.confidence * 100)}% Conf.
        </span>
      </div>

      <h4 className="mt-2 text-sm font-semibold text-white group-hover:text-indigo-300 transition-colors line-clamp-1">
        {finding.title}
      </h4>

      <p className="mt-1 text-xs text-slate-400 line-clamp-2 leading-relaxed">
        {finding.description}
      </p>

      <div className="mt-3 flex items-center justify-between text-[11px] text-slate-500 pt-2 border-t border-slate-800/80">
        <span className="font-mono truncate max-w-[200px]">
          {finding.file}:{finding.startLine}
        </span>
        <div className="flex items-center gap-1 text-indigo-400 group-hover:translate-x-0.5 transition-transform">
          <span>Inspect</span>
          <ChevronRight className="h-3.5 w-3.5" />
        </div>
      </div>
    </div>
  );
};

export default FindingCard;
