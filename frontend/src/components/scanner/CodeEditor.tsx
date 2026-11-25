import React from 'react';
import Editor from '@monaco-editor/react';
import { Code2, RotateCcw, Copy, Check } from 'lucide-react';
import { useState } from 'react';

interface CodeEditorProps {
  value: string;
  onChange: (value: string) => void;
  language: 'python' | 'javascript' | 'typescript';
  height?: string;
  readOnly?: boolean;
}

export const CodeEditor: React.FC<CodeEditorProps> = ({
  value,
  onChange,
  language,
  height = '460px',
  readOnly = false,
}) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const lineCount = value.split('\n').length;

  return (
    <div className="rounded-xl border border-slate-800 bg-[#0F172A] overflow-hidden shadow-xl">
      {/* Editor Top Bar */}
      <div className="flex items-center justify-between border-b border-slate-800 bg-[#0B1020] px-4 py-2.5 text-xs text-slate-400">
        <div className="flex items-center gap-2">
          <Code2 className="h-4 w-4 text-cyan-400" />
          <span className="font-semibold text-slate-200">Monaco IDE Sandbox</span>
          <span className="rounded bg-slate-800 px-2 py-0.5 font-mono text-[10px] text-cyan-400 border border-slate-700">
            {language.toUpperCase()}
          </span>
          <span className="text-[11px] text-slate-500 font-mono">
            {lineCount} lines
          </span>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleCopy}
            className="flex items-center gap-1 rounded bg-slate-800/80 px-2.5 py-1 text-[11px] text-slate-300 hover:bg-slate-700 hover:text-white transition"
            title="Copy source code"
          >
            {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
            <span>{copied ? 'Copied' : 'Copy'}</span>
          </button>
        </div>
      </div>

      {/* Monaco Container */}
      <Editor
        height={height}
        language={language}
        value={value}
        theme="vs-dark"
        onChange={(val) => onChange(val || '')}
        options={{
          minimap: { enabled: false },
          fontSize: 13,
          lineNumbers: 'on',
          scrollBeyondLastLine: false,
          automaticLayout: true,
          readOnly,
          tabSize: 4,
          fontFamily: 'JetBrains Mono, Fira Code, monospace',
        }}
      />
    </div>
  );
};

export default CodeEditor;
