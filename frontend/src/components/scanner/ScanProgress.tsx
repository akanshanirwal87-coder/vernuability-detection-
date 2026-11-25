import React from 'react';
import { Loader2, CheckCircle2, Circle } from 'lucide-react';

export interface ScanStage {
  label: string;
  description: string;
}

interface ScanProgressProps {
  stages: ScanStage[];
  currentStageIndex: number;
}

export const ScanProgress: React.FC<ScanProgressProps> = ({ stages, currentStageIndex }) => {
  return (
    <div className="rounded-2xl border border-slate-800 bg-[#111827] p-6 shadow-2xl backdrop-blur-xl">
      <div className="flex items-center justify-between border-b border-slate-800 pb-4 mb-5">
        <div>
          <h3 className="text-sm font-bold text-white">AI Security Analysis in Progress</h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Running hybrid static inspection, taint propagation, and ML classification
          </p>
        </div>
        <Loader2 className="h-5 w-5 animate-spin text-indigo-400" />
      </div>

      <div className="space-y-4">
        {stages.map((stage, idx) => {
          const isDone = idx < currentStageIndex;
          const isCurrent = idx === currentStageIndex;

          return (
            <div
              key={idx}
              className={`flex items-start gap-3.5 rounded-xl p-3 transition-colors ${
                isCurrent
                  ? 'bg-indigo-500/10 border border-indigo-500/30'
                  : isDone
                  ? 'bg-slate-900/40 text-slate-300'
                  : 'opacity-40 text-slate-500'
              }`}
            >
              <div className="mt-0.5">
                {isDone ? (
                  <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                ) : isCurrent ? (
                  <Loader2 className="h-4 w-4 animate-spin text-indigo-400" />
                ) : (
                  <Circle className="h-4 w-4 text-slate-600" />
                )}
              </div>
              <div className="flex-1">
                <div className="flex items-center justify-between">
                  <span
                    className={`text-xs font-semibold ${
                      isCurrent ? 'text-indigo-300' : isDone ? 'text-white' : 'text-slate-400'
                    }`}
                  >
                    {stage.label}
                  </span>
                  {isCurrent && (
                    <span className="text-[10px] font-mono text-indigo-400 uppercase tracking-wider">
                      Processing...
                    </span>
                  )}
                  {isDone && (
                    <span className="text-[10px] font-mono text-emerald-400 uppercase tracking-wider">
                      Done
                    </span>
                  )}
                </div>
                <p className="text-[11px] text-slate-400 mt-0.5">{stage.description}</p>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default ScanProgress;
