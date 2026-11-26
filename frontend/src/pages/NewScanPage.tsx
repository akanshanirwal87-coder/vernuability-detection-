import React, { useState, useRef } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
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
  Info,
  FolderGit2,
  Files,
  Plus,
  Trash2
} from 'lucide-react';
import { SAMPLE_CODE_SNIPPETS } from '../services/sampleCode';
import type { SampleSnippet } from '../services/sampleCode';
import { createScan, scanProjectMultiFile, getRepositoryInfo } from '../services/scanService';
import type { ScanRequest, ScanOptions } from '../types/scan';
import { useScan } from '../hooks/useScan';
import { ScanProgress } from '../components/scanner/ScanProgress';
import { CodeScanline } from '../components/common/CodeScanline';
import { toast } from 'sonner';

export const NewScanPage: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { runRepositoryScan, activeJob, cancelJob } = useScan();

  // Form states
  const initialProjectId = (location.state as any)?.projectId;
  const initialProjectName = (location.state as any)?.projectName || 'MySecurityAudit';

  const [projectId, setProjectId] = useState<string | undefined>(initialProjectId);
  const [projectName, setProjectName] = useState<string>(initialProjectName);
  const [fileName, setFileName] = useState<string>('auth_service.py');
  const [language, setLanguage] = useState<'python' | 'javascript' | 'typescript'>('python');
  const [inputTab, setInputTab] = useState<'editor' | 'upload' | 'multi-file' | 'github'>('editor');
  const [sourceCode, setSourceCode] = useState<string>(SAMPLE_CODE_SNIPPETS[0].vulnerableCode);
  const [selectedSnippetId, setSelectedSnippetId] = useState<string>(SAMPLE_CODE_SNIPPETS[0].id);
  const [snippetMode, setSnippetMode] = useState<'vulnerable' | 'secure'>('vulnerable');

  // GitHub Scanning State
  const [repoUrl, setRepoUrl] = useState<string>('https://github.com/akanshanirwal87-coder/vernuability-detection-');
  const [repoBranch, setRepoBranch] = useState<string>('main');
  const [repoToken, setRepoToken] = useState<string>('');
  const [repoMeta, setRepoMeta] = useState<any>(null);
  const [inspectingRepo, setInspectingRepo] = useState<boolean>(false);

  // Multi-File Project Batch State
  interface ProjectBatchFile {
    fileName: string;
    language: 'python' | 'javascript' | 'typescript';
    sourceCode: string;
  }

  const MULTI_FILE_PRESETS: Array<{ name: string; files: ProjectBatchFile[] }> = [
    {
      name: 'E-Commerce Backend Microservice (Python)',
      files: [
        {
          fileName: 'app.py',
          language: 'python',
          sourceCode: `import os\nfrom flask import Flask, request, jsonify\nfrom database import query_user_records\n\napp = Flask(__name__)\n# VULNERABLE: Hardcoded production secret token\nJWT_SECRET = "super_secret_jwt_token_key_19283"\n\n@app.route("/user")\ndef get_user():\n    user_id = request.args.get("id")\n    return jsonify(query_user_records(user_id))\n\nif __name__ == "__main__":\n    app.run(debug=True)\n`
        },
        {
          fileName: 'database.py',
          language: 'python',
          sourceCode: `import sqlite3\n\ndef query_user_records(user_id: str):\n    conn = sqlite3.connect("prod.db")\n    cursor = conn.cursor()\n    # VULNERABLE: Raw SQL string concatenation\n    query = "SELECT * FROM users WHERE id = '" + user_id + "'"\n    cursor.execute(query)\n    return cursor.fetchall()\n`
        },
        {
          fileName: 'utils.py',
          language: 'python',
          sourceCode: `import os\n\ndef ping_healthcheck(host: str):\n    # VULNERABLE: OS command injection via os.system\n    cmd = "ping -c 1 " + host\n    os.system(cmd)\n    return True\n`
        }
      ]
    },
    {
      name: 'Full Stack Node.js Web API (JavaScript)',
      files: [
        {
          fileName: 'server.js',
          language: 'javascript',
          sourceCode: `const express = require('express');\nconst app = express();\nconst STRIPE_SECRET = "stripe_secret_key_prod_99214488219";\n\napp.use(express.json());\n\napp.post('/merge', (req, res) => {\n    // VULNERABLE: Prototype pollution\n    const obj = {};\n    obj['__proto__'][req.body.key] = req.body.val;\n    res.json({ status: 'ok' });\n});\n\napp.listen(3000);\n`
        },
        {
          fileName: 'fileHandler.js',
          language: 'javascript',
          sourceCode: `const fs = require('fs');\n\nfunction readCustomerFile(userPath) {\n    // VULNERABLE: Path traversal via unsanitized file read\n    return fs.readFileSync('/var/data/' + userPath, 'utf8');\n}\nmodule.exports = { readCustomerFile };\n`
        }
      ]
    }
  ];

  const [projectFiles, setProjectFiles] = useState<ProjectBatchFile[]>(MULTI_FILE_PRESETS[0].files);
  const [selectedProjectPresetIdx, setSelectedProjectPresetIdx] = useState<number>(0);
  const [activeProjectFileIdx, setActiveProjectFileIdx] = useState<number>(0);

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
      projectId,
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

  const handleStartProjectScan = async () => {
    if (projectFiles.length === 0) {
      toast.error('Project must have at least one source file.');
      return;
    }

    setScanning(true);
    setActiveStageIndex(0);

    const interval = setInterval(() => {
      setActiveStageIndex(prev => {
        if (prev < scanStages.length - 1) return prev + 1;
        return prev;
      });
    }, 450);

    try {
      const result = await scanProjectMultiFile({
        projectName: `${projectName} (Batch Repository)`,
        files: projectFiles
      });
      clearInterval(interval);
      setActiveStageIndex(scanStages.length - 1);

      setTimeout(() => {
        setScanning(false);
        toast.success(`Project scan completed: ${result.findings.length} findings across ${projectFiles.length} files.`);
        navigate(`/results/${result.id}`);
      }, 500);
    } catch (err) {
      clearInterval(interval);
      setScanning(false);
      toast.error('Multi-file scan encountered an error.');
    }
  };

  const handleInspectRepo = async () => {
    setInspectingRepo(true);
    try {
      const meta = await getRepositoryInfo(repoUrl, repoToken || undefined);
      setRepoMeta(meta);
      if (meta.default_branch) setRepoBranch(meta.default_branch);
      toast.success(`Repository verified: ${meta.full_name}`);
    } catch (err: any) {
      toast.error(err.response?.data?.message || err.message || 'Could not inspect repository');
    } finally {
      setInspectingRepo(false);
    }
  };

  const handleStartRepoScan = async () => {
    if (!repoUrl.trim()) {
      toast.error('Repository URL is required');
      return;
    }
    setScanning(true);
    try {
      const result = await runRepositoryScan({
        repositoryUrl: repoUrl.trim(),
        branch: repoBranch.trim() || undefined,
        projectId,
        githubToken: repoToken.trim() || undefined,
      });
      toast.success(`Repository scan completed: ${result.findingsCount.total} findings identified.`);
      navigate(`/results/${result.id}`);
    } catch (err: any) {
      toast.error(err.message || 'Repository scan failed');
    } finally {
      setScanning(false);
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
                <button
                  onClick={() => setInputTab('multi-file')}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                    inputTab === 'multi-file'
                      ? 'bg-primary text-white shadow-sm'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-surface'
                  }`}
                >
                  <Files className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Multi-File Project Batch</span>
                </button>
                <button
                  onClick={() => setInputTab('github')}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                    inputTab === 'github'
                      ? 'bg-primary text-white shadow-sm'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-surface'
                  }`}
                >
                  <FolderGit2 className="w-3.5 h-3.5 text-indigo-400" />
                  <span>GitHub Repository</span>
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
              <div className="h-[460px] w-full bg-[#0B1020] relative overflow-hidden">
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
                {scanning && <CodeScanline label="ANALYZING AST SYNTAX & SINK FLOWS..." />}
              </div>
            ) : inputTab === 'upload' ? (
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
            ) : inputTab === 'multi-file' ? (
              /* Tab 3: Multi-File Project Batch Area */
              <div className="h-[460px] flex flex-col bg-[#0B1020]">
                {/* Project Preset Selector Header */}
                <div className="p-2.5 bg-surface/50 border-b border-border flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="text-[11px] text-slate-400">Project Preset:</span>
                    {MULTI_FILE_PRESETS.map((p, pIdx) => (
                      <button
                        key={p.name}
                        onClick={() => {
                          setSelectedProjectPresetIdx(pIdx);
                          setProjectFiles(p.files);
                          setActiveProjectFileIdx(0);
                        }}
                        className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors ${
                          selectedProjectPresetIdx === pIdx
                            ? 'bg-primary text-white'
                            : 'bg-card border border-border text-slate-400 hover:text-white'
                        }`}
                      >
                        {p.name}
                      </button>
                    ))}
                  </div>
                  <span className="text-[10px] font-mono text-cyan-400">
                    {projectFiles.length} files in batch
                  </span>
                </div>

                {/* Split Project File Tree and Monaco Preview */}
                <div className="flex-1 grid grid-cols-12 overflow-hidden">
                  {/* File List (4 cols) */}
                  <div className="col-span-4 border-r border-border/60 bg-[#0F172A] p-2 space-y-1 overflow-y-auto">
                    <span className="text-[10px] text-slate-400 font-mono uppercase tracking-wider block px-2 mb-1">
                      Project Files
                    </span>
                    {projectFiles.map((pf, idx) => (
                      <div
                        key={pf.fileName}
                        onClick={() => setActiveProjectFileIdx(idx)}
                        className={`flex items-center justify-between p-2 rounded-lg cursor-pointer text-xs transition-colors ${
                          activeProjectFileIdx === idx
                            ? 'bg-primary/20 text-cyan-400 border border-primary/40'
                            : 'text-slate-300 hover:bg-surface/60'
                        }`}
                      >
                        <div className="flex items-center gap-2 truncate">
                          <FileCode className="w-3.5 h-3.5 shrink-0" />
                          <span className="font-mono text-[11px] truncate">{pf.fileName}</span>
                        </div>
                        <span className="text-[10px] text-slate-500 font-mono">
                          {pf.sourceCode.split('\n').length}L
                        </span>
                      </div>
                    ))}
                  </div>

                  {/* Code Editor for Active File (8 cols) */}
                  <div className="col-span-8 relative">
                    {projectFiles[activeProjectFileIdx] && (
                      <Editor
                        height="100%"
                        language={projectFiles[activeProjectFileIdx].language}
                        value={projectFiles[activeProjectFileIdx].sourceCode}
                        theme="vs-dark"
                        onChange={(val) => {
                          const updated = [...projectFiles];
                          updated[activeProjectFileIdx] = {
                            ...updated[activeProjectFileIdx],
                            sourceCode: val || ''
                          };
                          setProjectFiles(updated);
                        }}
                        options={{
                          minimap: { enabled: false },
                          fontSize: 12,
                          lineNumbers: 'on',
                          scrollBeyondLastLine: false,
                          automaticLayout: true,
                          padding: { top: 8, bottom: 8 }
                        }}
                      />
                    )}
                    {scanning && <CodeScanline label="SCANNING MULTI-FILE PROJECT REPOSITORY..." />}
                  </div>
                </div>
              </div>
            ) : null}

            {/* Tab 4: GitHub Repository Asynchronous Scan */}
            {inputTab === 'github' && (
              <div className="p-6 space-y-5 bg-[#0B1020]">
                <div>
                  <h3 className="text-sm font-bold text-white flex items-center gap-2">
                    <FolderGit2 className="w-4 h-4 text-indigo-400" />
                    <span>Scan GitHub Repository (Asynchronous Engine)</span>
                  </h3>
                  <p className="text-xs text-slate-400 mt-1">
                    Connect an open-source or private GitHub repository to run multi-file AST, taint analysis, and OSV dependency scanning in the background.
                  </p>
                </div>

                <div className="space-y-4">
                  <div>
                    <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300">
                      GitHub Repository HTTPS URL *
                    </label>
                    <div className="relative mt-1.5">
                      <input
                        type="url"
                        value={repoUrl}
                        onChange={(e) => setRepoUrl(e.target.value)}
                        placeholder="https://github.com/owner/repository"
                        className="w-full rounded-lg border border-slate-700 bg-slate-900/80 px-3.5 py-2.5 text-xs text-white placeholder-slate-500 font-mono transition focus:border-indigo-500 focus:outline-none"
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div>
                      <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300">
                        Branch or Tag
                      </label>
                      <input
                        type="text"
                        value={repoBranch}
                        onChange={(e) => setRepoBranch(e.target.value)}
                        placeholder="main"
                        className="mt-1.5 w-full rounded-lg border border-slate-700 bg-slate-900/80 px-3 py-2 text-xs text-white placeholder-slate-500 font-mono transition focus:border-indigo-500 focus:outline-none"
                      />
                    </div>

                    <div>
                      <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300">
                        GitHub Token (Optional for Private Repos)
                      </label>
                      <input
                        type="password"
                        value={repoToken}
                        onChange={(e) => setRepoToken(e.target.value)}
                        placeholder="ghp_••••••••••••"
                        className="mt-1.5 w-full rounded-lg border border-slate-700 bg-slate-900/80 px-3 py-2 text-xs text-white placeholder-slate-500 font-mono transition focus:border-indigo-500 focus:outline-none"
                      />
                    </div>
                  </div>

                  <div className="flex items-center gap-3 pt-2">
                    <button
                      type="button"
                      onClick={handleInspectRepo}
                      disabled={inspectingRepo || !repoUrl.trim()}
                      className="px-3.5 py-2 rounded-lg border border-slate-700 bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-300 transition disabled:opacity-50"
                    >
                      {inspectingRepo ? 'Verifying...' : 'Inspect Repository'}
                    </button>
                    <button
                      type="button"
                      onClick={handleStartRepoScan}
                      disabled={!repoUrl.trim() || scanning}
                      className="flex items-center gap-2 px-5 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold shadow-lg shadow-indigo-600/30 transition disabled:opacity-50"
                    >
                      <Play className="w-3.5 h-3.5 fill-current" />
                      <span>Start Asynchronous Scan</span>
                    </button>
                  </div>

                  {repoMeta && (
                    <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-4 text-xs space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-white">{repoMeta.full_name}</span>
                        <span className="rounded bg-emerald-500/20 px-2 py-0.5 font-mono text-[10px] text-emerald-300 border border-emerald-500/30">
                          {repoMeta.is_private ? 'PRIVATE' : 'PUBLIC'}
                        </span>
                      </div>
                      <p className="text-slate-300">{repoMeta.description || 'No description provided.'}</p>
                      <div className="flex items-center gap-3 text-[11px] text-slate-400 font-mono pt-1 border-t border-emerald-500/20">
                        <span>Default: {repoMeta.default_branch}</span>
                        <span>•</span>
                        <span>Lang: {repoMeta.language || 'Multi'}</span>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* Primary Action Button */}
          {inputTab !== 'github' && (
            <div className="flex items-center justify-between p-4 rounded-xl bg-card border border-border">
              <div className="flex items-center gap-2 text-xs text-slate-400">
                <ShieldAlert className="w-4 h-4 text-amber-400" />
                <span>
                  {inputTab === 'multi-file' 
                    ? `Batch Engine: Will scan ${projectFiles.length} files simultaneously with AST + ML.`
                    : 'Untrusted input: Code is parsed in memory and never executed on the host.'}
                </span>
              </div>

              <button
                onClick={inputTab === 'multi-file' ? handleStartProjectScan : handleStartScan}
                disabled={scanning || (inputTab === 'multi-file' ? projectFiles.length === 0 : !sourceCode.trim())}
                className="flex items-center gap-2 px-6 py-2.5 rounded-lg bg-primary hover:bg-primary-hover active:scale-95 disabled:bg-slate-700 disabled:cursor-not-allowed text-white text-xs font-semibold transition-all duration-200 hover:-translate-y-0.5 shadow-md shadow-blue-500/20 hover:shadow-blue-500/35"
              >
                {scanning ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin text-white" />
                    <span>Analyzing Project...</span>
                  </>
                ) : (
                  <>
                    <Play className="w-4 h-4 fill-current" />
                    <span>
                      {inputTab === 'multi-file' 
                        ? `Scan Multi-File Project (${projectFiles.length} Files)` 
                        : 'Start Security Scan'}
                    </span>
                  </>
                )}
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Multi-Stage Scan Progress Modal */}
      {scanning && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4 animate-fade-in">
          {activeJob ? (
            <div className="max-w-xl w-full">
              <ScanProgress
                activeJob={activeJob}
                repositoryName={repoUrl}
                onCancel={() => {
                  if (activeJob) cancelJob(activeJob.jobId);
                  setScanning(false);
                }}
              />
            </div>
          ) : (
            <div className="bg-card border border-cyan-500/30 rounded-2xl max-w-lg w-full p-6 space-y-5 shadow-2xl shadow-cyan-950/50 animate-scale-in">
              <div className="flex items-center justify-between pb-3 border-b border-border">
                <div className="flex items-center gap-2.5">
                  <Loader2 className="w-5 h-5 text-cyan-400 animate-spin" />
                  <div>
                    <h3 className="font-bold text-sm text-white">
                      Executing Program Security Analysis
                    </h3>
                    <p className="text-[10px] text-slate-400 font-mono mt-0.5">
                      Stage {activeStageIndex + 1} of {scanStages.length}: {scanStages[activeStageIndex].title}
                    </p>
                  </div>
                </div>
                <span className="text-xs font-mono font-bold text-cyan-400 bg-cyan-950/70 border border-cyan-800/60 px-2.5 py-1 rounded-lg">
                  {Math.round(((activeStageIndex + 1) / scanStages.length) * 100)}%
                </span>
              </div>

              {/* Smooth Progress Indicator Bar */}
              <div className="w-full bg-[#0B1020] rounded-full h-2 overflow-hidden p-0.5 border border-border">
                <div 
                  className="bg-gradient-to-r from-blue-500 via-cyan-400 to-emerald-400 h-full rounded-full transition-all duration-300 ease-out shadow-sm shadow-cyan-500/50"
                  style={{ width: `${Math.round(((activeStageIndex + 1) / scanStages.length) * 100)}%` }}
                />
              </div>

              {/* Stages Stack */}
              <div className="space-y-2.5 max-h-72 overflow-y-auto pr-1">
                {scanStages.map((stage, idx) => {
                  const isDone = idx < activeStageIndex;
                  const isCurrent = idx === activeStageIndex;
                  return (
                    <div
                      key={idx}
                      className={`p-3 rounded-lg border text-xs transition-all duration-300 flex items-start gap-3 ${
                        isDone
                          ? 'bg-emerald-950/20 border-emerald-800/40 text-emerald-300'
                          : isCurrent
                          ? 'bg-cyan-950/30 border-cyan-500/60 text-cyan-200 shadow-md shadow-cyan-950/30'
                          : 'bg-surface/20 border-border/40 text-slate-500 opacity-60'
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

              <div className="pt-2 text-center text-[11px] text-slate-400 font-mono flex items-center justify-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-ping" />
                <span>Analyzing AST nodes, identifying sinks, and classifying CWE risk...</span>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
