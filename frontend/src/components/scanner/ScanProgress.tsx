import React from 'react';
import { Loader2, CheckCircle2, Circle, AlertCircle, XCircle, StopCircle } from 'lucide-react';
import type { ScanJobStatusResponse } from '../../services/scanService';

export interface ScanStage {
  label: string;
  description: string;
}

interface ScanProgressProps {
  stages?: ScanStage[];
  currentStageIndex?: number;
  activeJob?: ScanJobStatusResponse | null;
  repositoryName?: string;
  onCancel?: () => void;
}

export const ScanProgress: React.FC<ScanProgressProps> = ({
  stages,
  currentStageIndex = 0,
  activeJob,
  repositoryName,
  onCancel,
}) => {
  // If active background Celery job is present, show real-time telemetry
  if (activeJob) {
    const isRunning = activeJob.status === 'RUNNING';
    const isFailed = activeJob.status === 'FAILED';
    const isCompleted = activeJob.status === 'COMPLETED';

    return (
      <div className="rounded-2xl border border-slate-800 bg-[#111827] p-6 shadow-2xl backdrop-blur-xl space-y-5">
        <div className="flex items-center justify-between border-b border-slate-800 pb-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="rounded bg-indigo-500/20 px-2 py-0.5 font-mono text-[10px] text-indigo-400 border border-indigo-500/30">
                JOB ID: {activeJob.jobId}
              </span>
              <span
                className={`rounded px-2 py-0.5 font-mono text-[10px] font-bold uppercase border ${
                  isRunning
                    ? 'border-indigo-500/40 bg-indigo-500/20 text-indigo-300'
                    : isCompleted
                    ? 'border-emerald-500/40 bg-emerald-500/20 text-emerald-400'
                    : isFailed
                    ? 'border-red-500/40 bg-red-500/20 text-red-400'
                    : 'border-slate-700 bg-slate-800 text-slate-400'
                }`}
              >
                {activeJob.status}
              </span>
            </div>
            <h3 className="text-base font-bold text-white mt-1">
              {repositoryName ? `Scanning ${repositoryName}` : 'Background Repository Scan'}
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Celery Distributed Worker executing AST and taint analysis
            </p>
          </div>

          <div className="flex items-center gap-2">
            {isRunning && onCancel && (
              <button
                onClick={onCancel}
                className="flex items-center gap-1 px-3 py-1.5 rounded-lg border border-red-500/30 bg-red-500/10 text-red-300 text-xs font-semibold hover:bg-red-500/20 transition"
              >
                <StopCircle className="h-3.5 w-3.5" />
                <span>Cancel Scan</span>
              </button>
            )}
            {isRunning && <Loader2 className="h-5 w-5 animate-spin text-indigo-400" />}
            {isCompleted && <CheckCircle2 className="h-5 w-5 text-emerald-400" />}
            {isFailed && <XCircle className="h-5 w-5 text-red-400" />}
          </div>
        </div>

        {/* Real Progress Bar */}
        <div>
          <div className="flex justify-between text-xs text-slate-300 mb-1.5">
            <span className="font-semibold">Analysis Progress</span>
            <span className="font-mono text-cyan-400 font-bold">{activeJob.progress}%</span>
          </div>
          <div className="h-2 w-full rounded-full bg-slate-800 overflow-hidden">
            <div
              className="h-full bg-gradient-to-r from-indigo-500 to-cyan-400 transition-all duration-300"
              style={{ width: `${Math.max(5, Math.min(100, activeJob.progress))}%` }}
            />
          </div>
        </div>

        {/* Real File & Finding Metrics */}
        <div className="grid grid-cols-3 gap-3">
          <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-3 text-center">
            <span className="text-[11px] text-slate-400">Processed Files</span>
            <div className="font-mono text-lg font-bold text-white mt-0.5">
              {activeJob.processedFiles}
              {activeJob.totalFiles > 0 && <span className="text-xs text-slate-500 font-normal"> / {activeJob.totalFiles}</span>}
            </div>
          </div>
          <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-3 text-center">
            <span className="text-[11px] text-slate-400">Findings Discovered</span>
            <div className="font-mono text-lg font-bold text-amber-400 mt-0.5">
              {activeJob.findingsDiscovered}
            </div>
          </div>
          <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-3 text-center">
            <span className="text-[11px] text-slate-400">Highest Severity</span>
            <div className="font-mono text-lg font-bold text-indigo-300 mt-0.5">
              {activeJob.highestSeverity}
            </div>
          </div>
        </div>

        {/* Failure message if any */}
        {activeJob.errorMessage && (
          <div className="flex items-start gap-2.5 rounded-xl border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-300">
            <AlertCircle className="h-4 w-4 shrink-0 mt-0.5 text-red-400" />
            <span>{activeJob.errorMessage}</span>
          </div>
        )}
      </div>
    );
  }

  // Fallback to sequential stages stepper
  const activeStages = stages || [
    { label: 'Input Validation', description: 'Checking file size and UTF-8 encoding integrity' },
    { label: 'Language Detection', description: 'Validating syntax boundaries' },
    { label: 'Code Parsing & AST Analysis', description: 'Constructing Abstract Syntax Tree nodes' },
    { label: 'Static & Data-Flow Analysis', description: 'Tracing source-to-sink taint flows' },
    { label: 'AI/ML Pattern Classification', description: 'Contextual neural security heuristics' },
    { label: 'Result Generation', description: 'Compiling findings and remediation guidelines' }
  ];

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
        {activeStages.map((stage, idx) => {
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
