import React from 'react';
import { DataFlowStep } from '../../types/scan';
import { ArrowRight, UserCheck, Shuffle, AlertOctagon } from 'lucide-react';

interface DataFlowDiagramProps {
  steps: DataFlowStep[];
}

export const DataFlowDiagram: React.FC<DataFlowDiagramProps> = ({ steps }) => {
  if (!steps || steps.length === 0) {
    return (
      <div className="p-4 rounded-lg bg-surface/30 border border-border text-center text-xs text-slate-400">
        No dynamic data-flow path detected for this finding (pattern-matched rule).
      </div>
    );
  }

  const getStepIcon = (type: string) => {
    switch (type) {
      case 'SOURCE':
        return <UserCheck className="w-4 h-4 text-emerald-400" />;
      case 'TRANSFORM':
        return <Shuffle className="w-4 h-4 text-amber-400" />;
      case 'SINK':
        return <AlertOctagon className="w-4 h-4 text-red-400" />;
      default:
        return null;
    }
  };

  const getStepBadgeColor = (type: string) => {
    switch (type) {
      case 'SOURCE':
        return 'border-emerald-500/40 bg-emerald-950/40 text-emerald-300';
      case 'TRANSFORM':
        return 'border-amber-500/40 bg-amber-950/40 text-amber-300';
      case 'SINK':
        return 'border-red-500/40 bg-red-950/40 text-red-300';
      default:
        return 'border-border bg-surface text-slate-300';
    }
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h4 className="text-xs font-semibold text-slate-300 tracking-wider uppercase">
          Taint Data-Flow Analysis Path
        </h4>
        <span className="text-[11px] text-cyan-400 font-mono">
          {steps.length} Trace Hop{steps.length > 1 ? 's' : ''} (Source → Sink)
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        {steps.map((step, idx) => (
          <div key={idx} className="relative flex flex-col justify-between p-3.5 rounded-lg bg-[#0F172A] border border-border-light/70 shadow-sm">
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${getStepBadgeColor(step.type)} flex items-center gap-1.5`}>
                  {getStepIcon(step.type)}
                  {step.type}
                </span>
                <span className="text-[11px] font-mono text-slate-400">
                  Line {step.line}
                </span>
              </div>
              <p className="text-xs font-medium text-slate-200 mb-2">
                {step.label}
              </p>
              <div className="bg-[#0B1020] border border-border p-2 rounded text-[11px] font-mono text-cyan-300 overflow-x-auto whitespace-pre-wrap">
                {step.codeSnippet}
              </div>
            </div>
            <p className="text-[11px] text-slate-400 mt-2.5">
              {step.description}
            </p>

            {idx < steps.length - 1 && (
              <div className="hidden md:block absolute -right-3 top-1/2 -translate-y-1/2 z-10 bg-surface border border-border p-1 rounded-full text-slate-400">
                <ArrowRight className="w-3.5 h-3.5" />
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};

