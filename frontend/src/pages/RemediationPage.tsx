import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { getScanById, validateFix } from '../services/scanService';
import type { ScanResult, VulnerabilityFinding, ValidationStatus } from '../types/scan';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { DemoDataBanner } from '../components/common/DemoDataBanner';
import { 
  Wrench, 
  Copy, 
  Check, 
  CheckCircle2, 
  AlertTriangle, 
  ArrowLeft, 
  FileCode2, 
  ShieldCheck, 
  ShieldAlert, 
  Play, 
  Loader2, 
  ChevronRight,
  BookOpen,
  Info
} from 'lucide-react';
import { toast } from 'sonner';
import { DiffEditor } from '@monaco-editor/react';

export const RemediationPage: React.FC = () => {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();

  const [scan, setScan] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [activeFindingIndex, setActiveFindingIndex] = useState<number>(0);
  const [copied, setCopied] = useState<boolean>(false);
  const [diffViewMode, setDiffViewMode] = useState<'cards' | 'diff'>('cards');

  // Proposed code editing in remediation workspace
  const [editableProposedCode, setEditableProposedCode] = useState<string>('');

  // Validation state
  const [validating, setValidating] = useState<boolean>(false);
  const [validationResult, setValidationResult] = useState<{
    status: ValidationStatus;
    message: string;
    passed?: boolean;
  } | null>(null);

  // Apply fix confirmation dialog
  const [showApplyDialog, setShowApplyDialog] = useState<boolean>(false);

  useEffect(() => {
    if (scanId) {
      loadScan(scanId);
    }
  }, [scanId]);

  const loadScan = async (id: string) => {
    setLoading(true);
    try {
      const res = await getScanById(id);
      if (res && res.findings.length > 0) {
        setScan(res);
        setActiveFindingIndex(0);
        setEditableProposedCode(res.findings[0].remediationCode);
      } else {
        toast.error('No findings found to remediate.');
      }
    } catch (e) {
      toast.error('Failed to load scan');
    } finally {
      setLoading(false);
    }
  };

  const currentFinding: VulnerabilityFinding | undefined = scan?.findings[activeFindingIndex];

  const handleSelectFinding = (index: number) => {
    if (!scan) return;
    setActiveFindingIndex(index);
    setEditableProposedCode(scan.findings[index].remediationCode);
    setValidationResult(null);
  };

  const handleCopyFix = () => {
    if (!editableProposedCode) return;
    navigator.clipboard.writeText(editableProposedCode);
    setCopied(true);
    toast.success('Suggested fix copied to clipboard!');
    setTimeout(() => setCopied(false), 2000);
  };

  const handleRunValidation = async () => {
    if (!scan || !currentFinding) return;

    setValidating(true);
    setValidationResult({
      status: 'VALIDATION_RUNNING',
      message: 'Executing AST syntax tree compilation and static security rule pass...'
    });

    try {
      const res = await validateFix(scan.id, currentFinding.id, editableProposedCode);
      setValidationResult({
        status: res.status,
        message: res.message,
        passed: res.passed
      });

      if (res.passed) {
        toast.success('Fix verification passed!');
      } else {
        toast.error('Fix verification failed.');
      }
    } catch (err) {
      setValidationResult({
        status: 'VALIDATION_UNAVAILABLE',
        message: 'Validation engine temporarily unavailable. Verify code manually.'
      });
    } finally {
      setValidating(false);
    }
  };

  const handleApplyFixConfirmed = () => {
    setShowApplyDialog(false);
    toast.success('Patch applied to workspace file context.');
  };

  if (loading) {
    return (
      <div className="h-96 flex flex-col items-center justify-center space-y-3">
        <Loader2 className="w-8 h-8 text-primary animate-spin" />
        <p className="text-xs font-mono text-slate-400">Loading remediation workspace...</p>
      </div>
    );
  }

  if (!scan || !currentFinding) {
    return (
      <div className="p-8 rounded-xl bg-card border border-border text-center space-y-3">
        <ShieldCheck className="w-10 h-10 text-emerald-400 mx-auto" />
        <h2 className="text-base font-bold text-white">No Vulnerabilities to Remediate</h2>
        <p className="text-xs text-slate-400">All findings have been resolved or scan is clean.</p>
        <button
          onClick={() => navigate('/dashboard')}
          className="px-4 py-2 rounded-lg bg-primary text-white text-xs font-semibold"
        >
          Return to Dashboard
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 pb-3 border-b border-border">
        <div className="flex items-center gap-3">
          <button
            onClick={() => navigate(`/results/${scan.id}`)}
            className="p-1.5 rounded-lg bg-surface hover:bg-surface/80 border border-border text-slate-400 hover:text-white transition-colors"
            title="Return to findings results"
          >
            <ArrowLeft className="w-4 h-4" />
          </button>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-2xl font-bold text-white tracking-tight">AI-Assisted Remediation</h1>
              <span className="text-xs font-mono text-cyan-400 bg-cyan-950/60 border border-cyan-800/40 px-2 py-0.5 rounded">
                Finding {activeFindingIndex + 1} of {scan.findings.length}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Side-by-side comparative patch analysis, secure code synthesis, and AST fix verification.
            </p>
          </div>
        </div>

        {/* Global Finding Switcher Tabs */}
        <div className="flex items-center gap-1.5 overflow-x-auto max-w-md">
          {scan.findings.map((f, idx) => (
            <button
              key={f.id}
              onClick={() => handleSelectFinding(idx)}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono transition-all flex items-center gap-1.5 ${
                idx === activeFindingIndex
                  ? 'bg-primary text-white font-bold border border-primary-light shadow-sm'
                  : 'bg-surface/60 border border-border text-slate-400 hover:text-white'
              }`}
            >
              <span>#{idx + 1}</span>
              <span className="hidden sm:inline">{f.cwe}</span>
            </button>
          ))}
        </div>
      </div>

      {scan.isDemo && (
        <DemoDataBanner message="Remediation demonstrated on PaymentGateway sample repository." />
      )}

      {/* Finding Overview Banner */}
      <div className="p-4 rounded-xl bg-card border border-border flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1.5">
            <SeverityBadge severity={currentFinding.severity} size="md" />
            <span className="text-xs font-mono text-cyan-400 font-semibold">{currentFinding.cwe}</span>
            <span className="text-xs text-slate-400 font-mono">• {currentFinding.file}:{currentFinding.startLine}</span>
          </div>
          <h2 className="text-base font-bold text-white">{currentFinding.title}</h2>
          <p className="text-xs text-slate-400 mt-1">{currentFinding.description}</p>
        </div>

        {/* Validation Status Indicator Pill */}
        <div className="flex flex-col items-end gap-1.5 shrink-0">
          <span className="text-[10px] uppercase font-mono text-slate-400 font-semibold">
            Validation Status
          </span>
          {validationResult ? (
            <span className={`px-2.5 py-1 rounded-md text-xs font-mono font-semibold border flex items-center gap-1.5 ${
              validationResult.passed
                ? 'bg-emerald-950/60 border-emerald-700/60 text-emerald-400'
                : 'bg-red-950/60 border-red-700/60 text-red-400'
            }`}>
              {validationResult.passed ? <CheckCircle2 className="w-3.5 h-3.5" /> : <AlertTriangle className="w-3.5 h-3.5" />}
              <span>{validationResult.status}</span>
            </span>
          ) : (
            <span className="px-2.5 py-1 rounded-md bg-surface border border-border text-slate-400 text-xs font-mono">
              NOT_VALIDATED
            </span>
          )}
        </div>
      </div>

      {/* Diff View Mode Switcher */}
      <div className="flex items-center justify-between border-b border-border pb-2 text-xs">
        <div className="flex items-center gap-2">
          <button
            onClick={() => setDiffViewMode('cards')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
              diffViewMode === 'cards'
                ? 'bg-primary text-white font-semibold'
                : 'text-slate-400 hover:text-white bg-surface/50 border border-border'
            }`}
          >
            Side-by-Side Comparison Cards
          </button>
          <button
            onClick={() => setDiffViewMode('diff')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
              diffViewMode === 'diff'
                ? 'bg-primary text-white font-semibold'
                : 'text-slate-400 hover:text-white bg-surface/50 border border-border'
            }`}
          >
            Monaco Visual Diff Editor (VS Code)
          </button>
        </div>
        <span className="text-[11px] font-mono text-cyan-400 hidden sm:inline">
          {diffViewMode === 'cards' ? 'Root Cause & Impact Context' : 'Inline Character Diff'}
        </span>
      </div>

      {diffViewMode === 'diff' ? (
        /* Monaco Visual Diff Editor */
        <div className="space-y-3">
          <div className="h-[360px] rounded-xl bg-card border border-border overflow-hidden shadow-sm">
            <DiffEditor
              height="100%"
              language={scan.language}
              original={currentFinding.vulnerableCode}
              modified={editableProposedCode}
              theme="vs-dark"
              options={{
                readOnly: false,
                renderSideBySide: true,
                fontSize: 13,
                minimap: { enabled: false },
                lineNumbers: 'on',
                wordWrap: 'on',
                automaticLayout: true,
                padding: { top: 12, bottom: 12 }
              }}
            />
          </div>
          <div className="p-3 bg-[#0F172A] rounded-xl border border-border flex items-center justify-between text-xs">
            <span className="text-slate-300">
              Left: Original Vulnerable Code • Right: Proposed Secure Patch (Interactive Diff)
            </span>
            <button
              onClick={handleCopyFix}
              className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-surface border border-border text-[11px] text-slate-200 hover:text-white"
            >
              {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              <span>{copied ? 'Copied' : 'Copy Patch'}</span>
            </button>
          </div>
        </div>
      ) : (
        /* Side-by-Side Diff Comparison View Cards */
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* LEFT: Original Vulnerable Implementation */}
          <div className="rounded-xl bg-card border border-red-950/80 overflow-hidden shadow-sm flex flex-col">
            <div className="px-4 py-2.5 bg-red-950/40 border-b border-red-900/40 flex items-center justify-between">
              <span className="text-xs font-bold text-red-400 font-mono flex items-center gap-1.5">
                <ShieldAlert className="w-4 h-4" />
                <span>ORIGINAL VULNERABLE CODE</span>
              </span>
              <span className="text-[11px] font-mono text-red-400/80">
                Lines {currentFinding.startLine}–{currentFinding.endLine}
              </span>
            </div>
            <div className="p-4 bg-[#0B1020] text-red-300 font-mono text-xs overflow-x-auto min-h-[180px] whitespace-pre-wrap leading-relaxed">
              {currentFinding.vulnerableCode}
            </div>
            <div className="p-3 bg-[#0F172A] border-t border-border text-xs text-slate-400 space-y-1">
              <p className="font-semibold text-slate-300">Why this code is vulnerable:</p>
              <p className="text-[11px] text-slate-400 leading-relaxed">
                {currentFinding.impact}
              </p>
            </div>
          </div>

          {/* RIGHT: Suggested Secure Code (Remediation) */}
          <div className="rounded-xl bg-card border border-emerald-950/80 overflow-hidden shadow-sm flex flex-col">
            <div className="px-4 py-2.5 bg-emerald-950/40 border-b border-emerald-900/40 flex items-center justify-between">
              <span className="text-xs font-bold text-emerald-400 font-mono flex items-center gap-1.5">
                <ShieldCheck className="w-4 h-4" />
                <span>SUGGESTED SECURE IMPLEMENTATION</span>
              </span>
              <div className="flex items-center gap-2">
                <button
                  onClick={handleCopyFix}
                  className="flex items-center gap-1 px-2.5 py-1 rounded bg-surface border border-border text-[11px] text-slate-300 hover:text-white transition-colors"
                  title="Copy secure snippet"
                >
                  {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>{copied ? 'Copied' : 'Copy'}</span>
                </button>
              </div>
            </div>
            {/* Editable Proposed Code */}
            <textarea
              value={editableProposedCode}
              onChange={(e) => setEditableProposedCode(e.target.value)}
              className="p-4 bg-[#0B1020] text-emerald-300 font-mono text-xs overflow-x-auto min-h-[180px] w-full focus:outline-none focus:ring-1 focus:ring-emerald-500/40 leading-relaxed resize-none"
              spellCheck={false}
            />
            <div className="p-3 bg-[#0F172A] border-t border-border text-xs text-slate-400 space-y-1">
              <p className="font-semibold text-emerald-400">Explanation of Secure Changes:</p>
              <p className="text-[11px] text-slate-300 leading-relaxed">
                {currentFinding.remediationExplanation}
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Validation Feedback & Action Triggers */}
      {validationResult && (
        <div className={`p-4 rounded-xl border text-xs space-y-1.5 ${
          validationResult.passed
            ? 'bg-emerald-950/30 border-emerald-800/60 text-emerald-300'
            : 'bg-red-950/30 border-red-800/60 text-red-300'
        }`}>
          <div className="flex items-center gap-2 font-semibold">
            {validationResult.passed ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <AlertTriangle className="w-4 h-4 text-red-400" />}
            <span>Validation Result: {validationResult.status}</span>
          </div>
          <p className="text-slate-300">{validationResult.message}</p>
        </div>
      )}

      {/* Remediation Action Buttons Bar */}
      <div className="p-4 rounded-xl bg-card border border-border flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-2 text-xs text-slate-400">
          <Info className="w-4 h-4 text-cyan-400" />
          <span>Notice: AI-generated fixes must be reviewed and tested by engineers prior to deployment.</span>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleRunValidation}
            disabled={validating}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-surface hover:bg-surface/80 border border-border text-cyan-400 text-xs font-semibold transition-colors"
          >
            {validating ? (
              <>
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                <span>Validating with AST...</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>Validate Fix with AST</span>
              </>
            )}
          </button>

          <button
            onClick={() => setShowApplyDialog(true)}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-semibold transition-colors shadow-sm"
          >
            <CheckCircle2 className="w-3.5 h-3.5" />
            <span>Apply Fix (with Confirmation)</span>
          </button>
        </div>
      </div>

      {/* Security Best Practices Checklist */}
      <div className="p-5 rounded-xl bg-card border border-border space-y-3">
        <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider flex items-center gap-1.5">
          <BookOpen className="w-4 h-4 text-primary" />
          <span>Security Best Practices for {currentFinding.category}</span>
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-1">
          {currentFinding.bestPractices.map((bp, idx) => (
            <div key={idx} className="p-3 rounded-lg bg-[#0F172A] border border-border text-xs text-slate-300 space-y-1">
              <span className="text-[10px] text-cyan-400 font-mono font-bold">Rule 0{idx + 1}</span>
              <p className="text-[11px] text-slate-300 leading-snug">{bp}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Apply Confirmation Modal */}
      {showApplyDialog && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <div className="bg-card border border-border rounded-xl p-6 max-w-md w-full space-y-4 shadow-2xl">
            <h3 className="font-bold text-sm text-white flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-amber-400" />
              <span>Confirm Patch Application</span>
            </h3>
            <p className="text-xs text-slate-300 leading-relaxed">
              Are you sure you want to apply this suggested remediation to <code className="text-cyan-400 font-mono">{currentFinding.file}</code>? 
              This will update the affected line range with the secure construct.
            </p>
            <div className="p-2.5 rounded bg-[#0B1020] border border-border font-mono text-[11px] text-emerald-300 whitespace-pre-wrap">
              {editableProposedCode}
            </div>
            <div className="flex items-center justify-end gap-2 pt-2">
              <button
                onClick={() => setShowApplyDialog(false)}
                className="px-3 py-1.5 rounded-lg bg-surface border border-border text-slate-300 text-xs hover:text-white"
              >
                Cancel
              </button>
              <button
                onClick={handleApplyFixConfirmed}
                className="px-4 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-semibold"
              >
                Confirm & Apply
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
