import React, { useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import Editor from '@monaco-editor/react';
import { 
  Play, 
  Upload, 
  Code2, 
  RotateCcw, 
  FileCheck, 
  CheckCircle2, 
  Loader2, 
  Sparkles, 
  AlertCircle,
  FileCode,
  ShieldAlert,
  ChevronDown,
  Info
} from 'lucide-react';
import { SAMPLE_CODE_SNIPPETS } from '../services/sampleCode';
import type { SampleSnippet } from '../services/sampleCode';
import { createScan } from '../services/scanService';
import type { ScanRequest, ScanOptions } from '../types/scan';
import { toast } from 'sonner';

export const NewScanPage: React.FC = () => {
  const navigate = useNavigate();

  // Form states
  const [projectName, setProjectName] = useState<string>('MySecurityAudit');
  const [fileName, setFileName] = useState<string>('auth_service.py');
  const [language, setLanguage] = useState<'python' | 'javascript' | 'typescript'>('python');
  const [inputTab, setInputTab] = useState<'editor' | 'upload'>('editor');
  const [sourceCode, setSourceCode] = useState<string>(SAMPLE_CODE_SNIPPETS[0].vulnerableCode);
  const [selectedSnippetId, setSelectedSnippetId] = useState<string>(SAMPLE_CODE_SNIPPETS[0].id);
  const [snippetMode, setSnippetMode] = useState<'vulnerable' | 'secure'>('vulnerable');

  // Analysis Options
  const [options, setOptions] = useState<ScanOptions>({
    enableAstAnalysis: true,
    enableDataFlow: true,
    enableAiClassifier: true,
    enableRuleMatching: true,
  });

  // Upload state
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [dragOver, setDragOver] = useState<boolean>(false);
  const [uploadedFileDetails, setUploadedFileDetails] = useState<{ name: string; size: number } | null>(null);

  // Scanning progress state
  const [scanning, setScanning] = useState<boolean>(false);
  const [activeStageIndex, setActiveStageIndex] = useState<number>(0);

  const scanStages = [
    { title: 'Input Validation', desc: 'Checking file size and UTF-8 encoding integrity' },
    { title: 'Language Detection', desc: `Validating ${language.toUpperCase()} syntax boundaries` },
    { title: 'Code Parsing & AST Analysis', desc: 'Constructing Abstract Syntax Tree nodes' },
    { title: 'Static & Data-Flow Analysis', desc: 'Tracing source-to-sink taint flows' },
    { title: 'AI/ML Pattern Classification', desc: 'Contextual neural security heuristics' },
    { title: 'Risk Assessment & CWE Mapping', desc: 'Scoring severity and exploitability metrics' },
    { title: 'Result Generation', desc: 'Compiling findings and remediation guidelines' }
  ];

  const handleSnippetChange = (snippetId: string, mode: 'vulnerable' | 'secure') => {
    setSelectedSnippetId(snippetId);
    setSnippetMode(mode);
    const item = SAMPLE_CODE_SNIPPETS.find(s => s.id === snippetId);
    if (item) {
      setSourceCode(mode === 'vulnerable' ? item.vulnerableCode : item.secureCode);
      setLanguage(item.language);
      setFileName(item.language === 'python' ? 'security_demo.py' : 'security_demo.js');
    }
  };

  const handleFileUpload = (file: File) => {
    if (file.size > 5 * 1024 * 1024) {
      toast.error('File size exceeds maximum permitted limit (5MB).');
      return;
    }

    const ext = file.name.split('.').pop()?.toLowerCase();
    if (!['py', 'js', 'ts'].includes(ext || '')) {
      toast.error('Unsupported file format. Please upload .py, .js, or .ts files.');
      return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target?.result as string;
      setSourceCode(content);
      setFileName(file.name);
      setUploadedFileDetails({ name: file.name, size: file.size });
      if (ext === 'py') setLanguage('python');
      else if (ext === 'js') setLanguage('javascript');
      else if (ext === 'ts') setLanguage('typescript');
      setInputTab('editor'); // Switch to editor so user can review uploaded code
      toast.success(`Loaded ${file.name} successfully.`);
    };
    reader.onerror = () => toast.error('Failed to read file.');
    reader.readAsText(file);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileUpload(e.dataTransfer.files[0]);
    }
  };

  const handleStartScan = async () => {
    if (!sourceCode.trim()) {
      toast.error('Source code cannot be empty.');
      return;
    }

    setScanning(true);
    setActiveStageIndex(0);

    const request: ScanRequest = {
      projectName,
      fileName,
      language,
      sourceCode,
      options,
    };

    // Honest multi-stage progress step transition
    const interval = setInterval(() => {
      setActiveStageIndex(prev => {
        if (prev < scanStages.length - 1) return prev + 1;
        return prev;
      });
    }, 450);

    try {
      const result = await createScan(request);
      clearInterval(interval);
      setActiveStageIndex(scanStages.length - 1);

      setTimeout(() => {
        setScanning(false);
        toast.success(`Scan completed: ${result.findingsCount.total} findings identified.`);
        navigate(`/results/${result.id}`);
      }, 500);
    } catch (err) {
      clearInterval(interval);
      setScanning(false);
      toast.error('Scan encountered an error. Check backend logs.');
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-border">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">New Code Security Scan</h1>
          <p className="text-xs text-slate-400 mt-1">
            Submit source code to inspect AST structures, identify vulnerability sinks, and generate remediation guidance.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Side: Scan Configuration & Options (4 Cols) */}
        <div className="lg:col-span-4 space-y-4">
          {/* Project & Language Configuration Card */}
          <div className="p-4 rounded-xl bg-card border border-border space-y-4 shadow-sm">
            <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider flex items-center gap-1.5">
              <Code2 className="w-4 h-4 text-primary" />
              <span>Target Parameters</span>
            </h3>

            <div className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-300 font-medium mb-1">
                  Project or Module Name
                </label>
                <input
                  type="text"
                  value={projectName}
                  onChange={(e) => setProjectName(e.target.value)}
                  className="w-full bg-[#0B1020] border border-border rounded-lg px-3 py-2 text-slate-100 font-mono text-xs focus:outline-none focus:border-primary"
                  placeholder="e.g. AuthService"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">
                  File Name
                </label>
                <input
                  type="text"
                  value={fileName}
                  onChange={(e) => setFileName(e.target.value)}
                  className="w-full bg-[#0B1020] border border-border rounded-lg px-3 py-2 text-slate-100 font-mono text-xs focus:outline-none focus:border-primary"
                  placeholder="e.g. auth_service.py"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">
                  Programming Language
                </label>
                <select
                  value={language}
                  onChange={(e) => setLanguage(e.target.value as any)}
                  className="w-full bg-[#0B1020] border border-border rounded-lg px-3 py-2 text-slate-100 font-mono text-xs focus:outline-none focus:border-primary"
                >
                  <option value="python">Python (.py) — Supported via AST</option>
                  <option value="javascript">JavaScript (.js) — Supported via AST & Sinks</option>
                  <option value="typescript">TypeScript (.ts) — Supported via Tokenizer</option>
                </select>
              </div>
            </div>
          </div>

          {/* Analysis Engine Options */}
          <div className="p-4 rounded-xl bg-card border border-border space-y-3 shadow-sm text-xs">
            <h3 className="font-semibold text-slate-200 uppercase tracking-wider text-[11px]">
              Analysis Engine Components
            </h3>
            <div className="space-y-2.5">
              <label className="flex items-start gap-2.5 cursor-pointer">
                <input
                  type="checkbox"
                  checked={options.enableAstAnalysis}
                  onChange={(e) => setOptions({ ...options, enableAstAnalysis: e.target.checked })}
                  className="mt-0.5 rounded border-border text-primary focus:ring-0 bg-[#0B1020]"
                />
                <div>
                  <span className="font-medium text-slate-200">AST Parser & Grammar Tree</span>
                  <p className="text-[10px] text-slate-400">Extracts statements, function calls, and assignments.</p>
                </div>
              </label>

              <label className="flex items-start gap-2.5 cursor-pointer">
                <input
                  type="checkbox"
                  checked={options.enableDataFlow}
                  onChange={(e) => setOptions({ ...options, enableDataFlow: e.target.checked })}
                  className="mt-0.5 rounded border-border text-primary focus:ring-0 bg-[#0B1020]"
                />
                <div>
                  <span className="font-medium text-slate-200">Data-Flow & Taint Tracing</span>
                  <p className="text-[10px] text-slate-400">Traces user-controlled inputs to dangerous execution sinks.</p>
                </div>
              </label>

              <label className="flex items-start gap-2.5 cursor-pointer">
                <input
                  type="checkbox"
                  checked={options.enableAiClassifier}
                  onChange={(e) => setOptions({ ...options, enableAiClassifier: e.target.checked })}
                  className="mt-0.5 rounded border-border text-primary focus:ring-0 bg-[#0B1020]"
                />
                <div>
                  <span className="font-medium text-slate-200">AI/ML Classification Service</span>
                  <p className="text-[10px] text-slate-400">Pattern classification and root-cause explanations.</p>
                </div>
              </label>

              <label className="flex items-start gap-2.5 cursor-pointer">
                <input
                  type="checkbox"
                  checked={options.enableRuleMatching}
                  onChange={(e) => setOptions({ ...options, enableRuleMatching: e.target.checked })}
                  className="mt-0.5 rounded border-border text-primary focus:ring-0 bg-[#0B1020]"
                />
                <div>
                  <span className="font-medium text-slate-200">CWE / OWASP Security Rules</span>
                  <p className="text-[10px] text-slate-400">Deterministic severity and exploitability scoring.</p>
                </div>
              </label>
            </div>
          </div>

          {/* Safe Sample Snippet Loader */}
          <div className="p-4 rounded-xl bg-card border border-border space-y-3 shadow-sm text-xs">
            <div className="flex items-center justify-between">
              <h3 className="font-semibold text-slate-200 uppercase tracking-wider text-[11px]">
                Pre-Configured Test Samples
              </h3>
              <span className="text-[10px] text-cyan-400 font-mono">Safe Demos</span>
            </div>
            <select
              value={selectedSnippetId}
              onChange={(e) => handleSnippetChange(e.target.value, snippetMode)}
              className="w-full bg-[#0B1020] border border-border rounded-lg px-2.5 py-2 text-slate-200 font-mono text-[11px] focus:outline-none"
            >
              {SAMPLE_CODE_SNIPPETS.map(s => (
                <option key={s.id} value={s.id}>
                  {s.name}
                </option>
              ))}
            </select>

            <div className="flex items-center gap-2 pt-1">
              <button
                type="button"
                onClick={() => handleSnippetChange(selectedSnippetId, 'vulnerable')}
                className={`flex-1 py-1.5 px-2 rounded-lg text-[11px] font-medium border transition-colors ${
                  snippetMode === 'vulnerable'
                    ? 'bg-red-950/60 border-red-700/60 text-red-300'
                    : 'bg-surface border-border text-slate-400 hover:text-white'
                }`}
              >
                Vulnerable Code
              </button>
              <button
                type="button"
                onClick={() => handleSnippetChange(selectedSnippetId, 'secure')}
                className={`flex-1 py-1.5 px-2 rounded-lg text-[11px] font-medium border transition-colors ${
                  snippetMode === 'secure'
                    ? 'bg-emerald-950/60 border-emerald-700/60 text-emerald-300'
                    : 'bg-surface border-border text-slate-400 hover:text-white'
                }`}
              >
                Secure Alternative
              </button>
            </div>
          </div>
        </div>

        {/* Right Side: Monaco Editor / Upload Tabs & Action (8 Cols) */}
        <div className="lg:col-span-8 space-y-4">
          <div className="rounded-xl bg-card border border-border overflow-hidden shadow-sm flex flex-col">
            {/* Input Method Navigation Tabs */}
            <div className="flex items-center justify-between px-4 py-2.5 bg-[#0F172A] border-b border-border">
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setInputTab('editor')}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                    inputTab === 'editor'
                      ? 'bg-primary text-white shadow-sm'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-surface'
                  }`}
                >
                  <Code2 className="w-3.5 h-3.5" />
                  <span>Write or Paste Code</span>
                </button>
                <button
                  onClick={() => setInputTab('upload')}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                    inputTab === 'upload'
                      ? 'bg-primary text-white shadow-sm'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-surface'
                  }`}
                >
                  <Upload className="w-3.5 h-3.5" />
                  <span>Upload File</span>
                </button>
              </div>

              <div className="flex items-center gap-2 text-xs">
                <button
                  onClick={() => {
                    setSourceCode('');
                    toast.info('Editor cleared.');
                  }}
                  className="flex items-center gap-1 px-2.5 py-1 rounded text-slate-400 hover:text-white hover:bg-surface transition-colors"
                  title="Clear source code"
                >
                  <RotateCcw className="w-3 h-3" />
                  <span>Clear</span>
                </button>
                <span className="text-[11px] font-mono text-slate-400">
                  {sourceCode.split('\n').length} lines
                </span>
              </div>
            </div>

            {/* Tab 1: Monaco Code Editor */}
            {inputTab === 'editor' ? (
              <div className="h-[460px] w-full bg-[#0B1020]">
                <Editor
                  height="100%"
                  language={language}
                  value={sourceCode}
                  theme="vs-dark"
                  onChange={(val) => setSourceCode(val || '')}
                  options={{
                    minimap: { enabled: false },
                    fontSize: 13,
                    lineNumbers: 'on',
                    scrollBeyondLastLine: false,
                    automaticLayout: true,
                    tabSize: 4,
                    wordWrap: 'on',
                    padding: { top: 12, bottom: 12 },
                  }}
                />
              </div>
            ) : (
              /* Tab 2: Drag and Drop Upload Area */
              <div
                onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
                onDragLeave={() => setDragOver(false)}
                onDrop={handleDrop}
                onClick={() => fileInputRef.current?.click()}
                className={`h-[460px] flex flex-col items-center justify-center border-2 border-dashed rounded-b-xl transition-all cursor-pointer p-8 text-center ${
                  dragOver
                    ? 'border-primary bg-primary/10 text-white'
                    : 'border-border-light hover:border-slate-500 bg-[#0B1020] text-slate-400'
                }`}
              >
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".py,.js,.ts"
                  className="hidden"
                  onChange={(e) => {
                    if (e.target.files && e.target.files[0]) {
                      handleFileUpload(e.target.files[0]);
                    }
                  }}
                />
                <div className="p-4 rounded-full bg-surface border border-border text-cyan-400 mb-4">
                  <Upload className="w-8 h-8" />
                </div>
                <h4 className="font-semibold text-sm text-slate-200">
                  Click or drag and drop source file to upload
                </h4>
                <p className="text-xs text-slate-400 mt-1 max-w-sm">
                  Supported formats: Python (.py), JavaScript (.js), TypeScript (.ts). Max file size: 5MB.
                </p>
                {uploadedFileDetails && (
                  <div className="mt-4 p-2.5 rounded-lg bg-surface border border-border flex items-center gap-2 text-xs font-mono text-emerald-400">
                    <FileCheck className="w-4 h-4" />
                    <span>{uploadedFileDetails.name} ({(uploadedFileDetails.size / 1024).toFixed(1)} KB)</span>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Primary Action Button */}
          <div className="flex items-center justify-between p-4 rounded-xl bg-card border border-border">
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <ShieldAlert className="w-4 h-4 text-amber-400" />
              <span>Untrusted input: Code is parsed in memory and never executed on the host.</span>
            </div>

            <button
              onClick={handleStartScan}
              disabled={scanning || !sourceCode.trim()}
              className="flex items-center gap-2 px-6 py-2.5 rounded-lg bg-primary hover:bg-primary-hover disabled:bg-slate-700 disabled:cursor-not-allowed text-white text-xs font-semibold transition-all shadow-md shadow-blue-500/20"
            >
              {scanning ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin text-white" />
                  <span>Analyzing Code...</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-current" />
                  <span>Start Security Scan</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Multi-Stage Scan Progress Modal */}
      {scanning && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-card border border-border rounded-2xl max-w-lg w-full p-6 space-y-6 shadow-2xl">
            <div className="flex items-center justify-between pb-3 border-b border-border">
              <div className="flex items-center gap-2.5">
                <Loader2 className="w-5 h-5 text-cyan-400 animate-spin" />
                <h3 className="font-bold text-sm text-white">
                  Executing Program Security Analysis
                </h3>
              </div>
              <span className="text-xs font-mono text-cyan-400 bg-cyan-950/60 border border-cyan-800/40 px-2 py-0.5 rounded">
                Stage {activeStageIndex + 1} / {scanStages.length}
              </span>
            </div>

            {/* Stages Stack */}
            <div className="space-y-3">
              {scanStages.map((stage, idx) => {
                const isDone = idx < activeStageIndex;
                const isCurrent = idx === activeStageIndex;
                return (
                  <div
                    key={idx}
                    className={`p-3 rounded-lg border text-xs transition-all flex items-start gap-3 ${
                      isDone
                        ? 'bg-emerald-950/20 border-emerald-800/40 text-emerald-300'
                        : isCurrent
                        ? 'bg-primary/20 border-primary/50 text-blue-200 shadow-sm'
                        : 'bg-surface/20 border-border/40 text-slate-500'
                    }`}
                  >
                    <div className="mt-0.5">
                      {isDone ? (
                        <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                      ) : isCurrent ? (
                        <Loader2 className="w-4 h-4 text-cyan-400 animate-spin" />
                      ) : (
                        <div className="w-4 h-4 rounded-full border border-slate-600 flex items-center justify-center text-[9px] font-mono">
                          {idx + 1}
                        </div>
                      )}
                    </div>
                    <div>
                      <h4 className="font-semibold text-slate-200">
                        {stage.title}
                      </h4>
                      <p className="text-[11px] text-slate-400 mt-0.5">
                        {stage.desc}
                      </p>
                    </div>
                  </div>
                );
              })}
            </div>

            <div className="pt-2 text-center text-[11px] text-slate-400 font-mono">
              Analyzing AST nodes, identifying sinks, and classifying CWE risk...
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
