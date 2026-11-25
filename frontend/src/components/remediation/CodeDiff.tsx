import React from 'react';
import { DiffEditor } from '@monaco-editor/react';
import { Download, Copy, Check } from 'lucide-react';
import { useState } from 'react';
import { downloadUnifiedPatch } from '../../utils/downloadReport';

interface CodeDiffProps {
  originalCode: string;
  remediatedCode: string;
  language: 'python' | 'javascript' | 'typescript';
  fileName?: string;
  height?: string;
}

export const CodeDiff: React.FC<CodeDiffProps> = ({
  originalCode,
  remediatedCode,
  language,
  fileName = 'source_code.py',
  height = '420px',
}) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(remediatedCode);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    downloadUnifiedPatch(fileName, originalCode, remediatedCode);
  };

  return (
    <div className="rounded-xl border border-slate-800 bg-[#0F172A] overflow-hidden shadow-xl">
      {/* Top Header */}
      <div className="flex items-center justify-between border-b border-slate-800 bg-[#0B1020] px-4 py-2.5 text-xs text-slate-400">
        <div className="flex items-center gap-3">
          <span className="font-semibold text-slate-200">Monaco Unified Diff Comparison</span>
          <span className="text-[11px] text-red-400 font-mono">Original (Vulnerable)</span>
          <span className="text-slate-600">vs</span>
          <span className="text-[11px] text-emerald-400 font-mono">Proposed Fix</span>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleCopy}
            className="flex items-center gap-1 rounded bg-slate-800 px-2.5 py-1 text-[11px] text-slate-300 hover:bg-slate-700 hover:text-white transition"
          >
            {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
            <span>{copied ? 'Copied' : 'Copy Fix'}</span>
          </button>
          <button
            onClick={handleDownload}
            className="flex items-center gap-1 rounded bg-indigo-600/30 px-2.5 py-1 text-[11px] font-semibold text-indigo-300 border border-indigo-500/40 hover:bg-indigo-600/50 hover:text-white transition"
          >
            <Download className="h-3.5 w-3.5" />
            <span>Download .patch</span>
          </button>
        </div>
      </div>

      {/* Monaco Diff Editor */}
      <DiffEditor
        height={height}
        language={language}
        original={originalCode}
        modified={remediatedCode}
        theme="vs-dark"
        options={{
          readOnly: true,
          renderSideBySide: true,
          fontSize: 13,
          minimap: { enabled: false },
          scrollBeyondLastLine: false,
          fontFamily: 'JetBrains Mono, Fira Code, monospace',
        }}
      />
    </div>
  );
};

export default CodeDiff;
