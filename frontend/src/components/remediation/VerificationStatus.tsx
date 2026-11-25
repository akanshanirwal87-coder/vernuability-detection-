import React from 'react';
import type { ValidationStatus } from '../../types/scan';
import { CheckCircle2, AlertTriangle, Loader2, ShieldCheck, XCircle } from 'lucide-react';

interface VerificationStatusProps {
  status: ValidationStatus | string;
  notes?: string;
}

export const VerificationStatus: React.FC<VerificationStatusProps> = ({ status, notes }) => {
  const isPassed =
    status === 'VALIDATION_PASSED' ||
    status === 'REGRESSION_TESTS_PASSED' ||
    status === 'SECURITY_CHECK_PASSED';
  const isFailed = status === 'VALIDATION_FAILED';
  const isRunning = status === 'VALIDATION_RUNNING';

  return (
    <div
      className={`flex items-start gap-3 rounded-xl border p-4 ${
        isPassed
          ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
          : isFailed
          ? 'border-red-500/30 bg-red-500/10 text-red-300'
          : isRunning
          ? 'border-indigo-500/30 bg-indigo-500/10 text-indigo-300'
          : 'border-slate-800 bg-slate-900/60 text-slate-400'
      }`}
    >
      <div className="mt-0.5 shrink-0">
        {isPassed && <CheckCircle2 className="h-5 w-5 text-emerald-400" />}
        {isFailed && <XCircle className="h-5 w-5 text-red-400" />}
        {isRunning && <Loader2 className="h-5 w-5 animate-spin text-indigo-400" />}
        {!isPassed && !isFailed && !isRunning && <AlertTriangle className="h-5 w-5 text-slate-500" />}
      </div>

      <div>
        <div className="flex items-center gap-2">
          <span className="text-xs font-bold uppercase tracking-wider">
            {status.replace(/_/g, ' ')}
          </span>
          {isPassed && (
            <span className="rounded bg-emerald-500/20 px-2 py-0.2 font-mono text-[10px] text-emerald-300 border border-emerald-500/30">
              3-Stage AST Validated
            </span>
          )}
        </div>
        <p className="mt-1 text-xs leading-relaxed text-slate-300">
          {notes ||
            (isPassed
              ? 'Proposed remediation passed AST recompilation, elimination of target taint sink, and regression verification.'
              : isFailed
              ? 'Verification failed: Vulnerability pattern or syntax error still detected in proposed fix.'
              : 'Proposed code fix has not yet been verified in the AST sandbox.')}
        </p>
      </div>
    </div>
  );
};

export default VerificationStatus;
