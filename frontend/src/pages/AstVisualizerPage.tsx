import React, { useState, useEffect } from 'react';
import { 
  FileCode2, 
  Play, 
  RotateCcw, 
  ChevronRight, 
  ChevronDown, 
  ShieldAlert, 
  ShieldCheck, 
  Sparkles, 
  Layers, 
  Terminal, 
  HelpCircle,
  Copy,
  Check,
  Code2
} from 'lucide-react';
import Editor from '@monaco-editor/react';
import { parseAstTree } from '../services/scanService';
import type { AstParseResponse, AstTreeNode } from '../types/scan';
import { toast } from 'sonner';

const SAMPLE_AST_SNIPPETS = [
  {
    id: 'sqli',
    title: 'SQL Injection AST Sink (Python)',
    language: 'python',
    code: `import sqlite3

def query_user(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # Dynamic string concatenation to raw SQL sink
    query = "SELECT * FROM accounts WHERE id = '" + user_id + "'"
    cursor.execute(query)
    return cursor.fetchone()`
  },
  {
    id: 'cmd-injection',
    title: 'Command Injection AST Sink (Python)',
    language: 'python',
    code: `import os

def ping_server(target_host):
    # Untrusted input concatenated to system shell sink
    command = "ping -c 1 " + target_host
    os.system(command)
    return True`
  },
  {
    id: 'secure-param',
    title: 'Secure Parameterized Query AST (Python)',
    language: 'python',
    code: `import sqlite3

def query_user_safe(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # Secure parameterized query with placeholder tuple
    query = "SELECT * FROM accounts WHERE id = ?"
    cursor.execute(query, (user_id,))
    return cursor.fetchone()`
  },
  {
    id: 'xss-dom',
    title: 'DOM XSS Sink (JavaScript)',
    language: 'javascript',
    code: `function renderGreeting(userInput) {
    const banner = document.getElementById("welcome");
    // Direct assignment to innerHTML sink
    banner.innerHTML = "<h1>Welcome, " + userInput + "</h1>";
}`
  }
];

export const AstVisualizerPage: React.FC = () => {
  const [selectedSnippet, setSelectedSnippet] = useState(SAMPLE_AST_SNIPPETS[0]);
  const [sourceCode, setSourceCode] = useState(SAMPLE_AST_SNIPPETS[0].code);
  const [language, setLanguage] = useState<'python' | 'javascript'>('python');
  const [loading, setLoading] = useState<boolean>(false);
  const [astData, setAstData] = useState<AstParseResponse | null>(null);
  const [selectedNode, setSelectedNode] = useState<AstTreeNode | null>(null);
  const [copied, setCopied] = useState<boolean>(false);

  useEffect(() => {
    handleParseAst(sourceCode, language);
  }, []);

  const handleSnippetChange = (snippet: typeof SAMPLE_AST_SNIPPETS[0]) => {
    setSelectedSnippet(snippet);
    setSourceCode(snippet.code);
    setLanguage(snippet.language as any);
    handleParseAst(snippet.code, snippet.language);
  };

  const handleParseAst = async (codeToParse: string, lang: string) => {
    setLoading(true);
    try {
      const data = await parseAstTree(codeToParse, lang, lang === 'python' ? 'script.py' : 'script.js');
      setAstData(data);
      if (data && data.tree) {
        setSelectedNode(data.tree);
      }
    } catch (e) {
      toast.error('Failed to parse Abstract Syntax Tree');
    } finally {
      setLoading(false);
    }
  };

  const handleCopyCode = () => {
    navigator.clipboard.writeText(sourceCode);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
    toast.success('Code copied to clipboard');
  };

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Top Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-border">
        <div>
          <div className="flex items-center gap-2 text-cyan-400 font-mono text-xs uppercase tracking-wider mb-1">
            <Layers className="w-4 h-4" />
            <span>Compiler Theory & Static Program Analysis</span>
          </div>
          <h1 className="text-xl sm:text-2xl font-bold text-white tracking-tight flex items-center gap-2">
            Abstract Syntax Tree (AST) Explorer
          </h1>
          <p className="text-xs text-slate-400 mt-1 max-w-3xl">
            Inspect how source code is parsed into compiler syntax trees. Visualize execution sinks, taint sources, and string concatenation nodes in real-time.
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2">
          <button
            onClick={() => handleParseAst(sourceCode, language)}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-primary hover:bg-primary-hover text-white text-xs font-semibold shadow-md shadow-blue-900/30 transition-all duration-200 active:scale-95"
          >
            <Play className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>{loading ? 'Compiling AST...' : 'Parse AST Tree'}</span>
          </button>
        </div>
      </div>

      {/* Preset Selector */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs text-slate-400 font-medium mr-1">Preloaded Snippets:</span>
        {SAMPLE_AST_SNIPPETS.map((snip) => (
          <button
            key={snip.id}
            onClick={() => handleSnippetChange(snip)}
            className={`px-2.5 py-1 rounded-md text-xs font-medium transition-all duration-150 ${
              selectedSnippet.id === snip.id
                ? 'bg-primary/20 text-cyan-400 border border-primary/40'
                : 'bg-card border border-border text-slate-400 hover:text-white hover:bg-surface'
            }`}
          >
            {snip.title}
          </button>
        ))}
      </div>

      {/* AST Summary Metrics Bar */}
      {astData && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <div className="p-3 rounded-lg bg-card border border-border">
            <span className="text-[11px] text-slate-400 uppercase font-mono">AST Total Nodes</span>
            <p className="text-xl font-bold text-white mt-0.5">{astData.summary.nodesCount}</p>
          </div>
          <div className="p-3 rounded-lg bg-card border border-border">
            <span className="text-[11px] text-slate-400 uppercase font-mono">Identified Sinks</span>
            <p className="text-xl font-bold text-rose-400 mt-0.5 flex items-center gap-1.5">
              <span>{astData.summary.sinksIdentified}</span>
              {astData.summary.sinksIdentified > 0 && <ShieldAlert className="w-4 h-4 text-rose-500" />}
            </p>
          </div>
          <div className="p-3 rounded-lg bg-card border border-border">
            <span className="text-[11px] text-slate-400 uppercase font-mono">Functions Defined</span>
            <p className="text-xl font-bold text-cyan-400 mt-0.5">{astData.summary.functionsFound}</p>
          </div>
          <div className="p-3 rounded-lg bg-card border border-border">
            <span className="text-[11px] text-slate-400 uppercase font-mono">Vulnerabilities Flagged</span>
            <p className={`text-xl font-bold mt-0.5 ${astData.findingsCount > 0 ? 'text-amber-400' : 'text-emerald-400'}`}>
              {astData.findingsCount} {astData.findingsCount === 0 && '✓ Clean'}
            </p>
          </div>
        </div>
      )}

      {/* Main Dual Workspace: Editor vs AST Tree */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Code Editor (5 columns) */}
        <div className="lg:col-span-5 space-y-3">
          <div className="p-3 rounded-xl bg-card border border-border">
            <div className="flex items-center justify-between pb-2 mb-2 border-b border-border/60">
              <div className="flex items-center gap-2">
                <Code2 className="w-4 h-4 text-cyan-400" />
                <span className="text-xs font-semibold text-white">Source Code Input</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-mono px-1.5 py-0.5 bg-surface text-slate-400 rounded uppercase">
                  {language}
                </span>
                <button
                  onClick={handleCopyCode}
                  className="p-1 rounded text-slate-400 hover:text-white hover:bg-surface"
                  title="Copy code"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              </div>
            </div>

            <div className="h-[420px] rounded-lg overflow-hidden border border-border/60">
              <Editor
                height="100%"
                language={language}
                value={sourceCode}
                theme="vs-dark"
                onChange={(val) => setSourceCode(val || '')}
                options={{
                  fontSize: 12,
                  fontFamily: 'JetBrains Mono, Menlo, monospace',
                  minimap: { enabled: false },
                  scrollBeyondLastLine: false,
                  lineNumbers: 'on',
                  padding: { top: 8 }
                }}
              />
            </div>
            <p className="text-[11px] text-slate-400 mt-2">
              Tip: Edit the code and click <strong>Parse AST Tree</strong> to recompile the AST live.
            </p>
          </div>

          {/* Node Inspector Card */}
          {selectedNode && (
            <div className="p-3.5 rounded-xl bg-surface border border-border space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-white flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                  Selected AST Node Properties
                </span>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-semibold ${
                  selectedNode.role === 'SINK'
                    ? 'bg-rose-950/80 text-rose-400 border border-rose-800'
                    : selectedNode.role === 'TRANSFORM'
                    ? 'bg-amber-950/80 text-amber-400 border border-amber-800'
                    : selectedNode.role === 'SOURCE'
                    ? 'bg-blue-950/80 text-blue-400 border border-blue-800'
                    : 'bg-slate-800 text-slate-300'
                }`}>
                  ROLE: {selectedNode.role}
                </span>
              </div>
              <div className="text-xs text-slate-300 space-y-1 font-mono bg-card/60 p-2.5 rounded border border-border/50">
                <div className="flex justify-between">
                  <span className="text-slate-400">Node Type:</span>
                  <span className="text-cyan-300">{selectedNode.type}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Node Label:</span>
                  <span className="text-white truncate max-w-[200px]">{selectedNode.name}</span>
                </div>
                {selectedNode.lineno && (
                  <div className="flex justify-between">
                    <span className="text-slate-400">Source Line:</span>
                    <span className="text-amber-400">Line {selectedNode.lineno}</span>
                  </div>
                )}
                <div className="pt-1 border-t border-border/40 text-[11px] text-slate-400 font-sans">
                  {selectedNode.description}
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Right: AST Tree Visualizer (7 columns) */}
        <div className="lg:col-span-7">
          <div className="p-4 rounded-xl bg-card border border-border space-y-3">
            <div className="flex items-center justify-between pb-2 border-b border-border/60">
              <div className="flex items-center gap-2">
                <Layers className="w-4 h-4 text-cyan-400" />
                <span className="text-xs font-semibold text-white">Hierarchical Syntax Tree</span>
              </div>
              {/* Legend */}
              <div className="flex items-center gap-2 text-[10px] font-mono">
                <span className="flex items-center gap-1 text-rose-400">
                  <span className="w-2 h-2 rounded-full bg-rose-500"></span> SINK
                </span>
                <span className="flex items-center gap-1 text-amber-400">
                  <span className="w-2 h-2 rounded-full bg-amber-500"></span> TRANSFORM
                </span>
                <span className="flex items-center gap-1 text-blue-400">
                  <span className="w-2 h-2 rounded-full bg-blue-500"></span> SOURCE
                </span>
                <span className="flex items-center gap-1 text-slate-400">
                  <span className="w-2 h-2 rounded-full bg-slate-500"></span> SAFE
                </span>
              </div>
            </div>

            {/* Tree View Canvas */}
            <div className="h-[540px] overflow-y-auto p-3 rounded-lg bg-[#0B1020] border border-border/60 font-mono text-xs space-y-1">
              {astData && astData.tree ? (
                <TreeNodeItem 
                  node={astData.tree} 
                  depth={0} 
                  selectedNode={selectedNode}
                  onSelectNode={setSelectedNode} 
                />
              ) : (
                <div className="flex flex-col items-center justify-center h-full text-slate-500 text-xs">
                  <Layers className="w-8 h-8 mb-2 opacity-50" />
                  <span>Click "Parse AST Tree" to generate the syntax hierarchy</span>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

interface TreeNodeItemProps {
  node: AstTreeNode;
  depth: number;
  selectedNode: AstTreeNode | null;
  onSelectNode: (node: AstTreeNode) => void;
}

const TreeNodeItem: React.FC<TreeNodeItemProps> = ({ node, depth, selectedNode, onSelectNode }) => {
  const [expanded, setExpanded] = useState<boolean>(depth < 3);
  const hasChildren = node.children && node.children.length > 0;
  const isSelected = selectedNode === node;

  const getRoleBadgeColor = (role: string) => {
    switch (role) {
      case 'SINK':
        return 'bg-rose-950/80 text-rose-300 border-rose-700/80 hover:bg-rose-900/60';
      case 'TRANSFORM':
        return 'bg-amber-950/80 text-amber-300 border-amber-700/80 hover:bg-amber-900/60';
      case 'SOURCE':
        return 'bg-blue-950/80 text-blue-300 border-blue-700/80 hover:bg-blue-900/60';
      default:
        return 'bg-surface/80 text-slate-300 border-border/80 hover:bg-surface';
    }
  };

  return (
    <div className="select-none">
      <div 
        onClick={() => onSelectNode(node)}
        style={{ paddingLeft: `${depth * 18}px` }}
        className={`flex items-center gap-1.5 py-1 px-2 rounded cursor-pointer transition-colors ${
          isSelected 
            ? 'bg-primary/25 border border-primary/50 text-white' 
            : 'hover:bg-surface/60'
        }`}
      >
        {hasChildren ? (
          <button 
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              setExpanded(!expanded);
            }}
            className="p-0.5 text-slate-400 hover:text-white"
          >
            {expanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
          </button>
        ) : (
          <span className="w-3.5 h-3.5 inline-block text-slate-600 text-center leading-none">•</span>
        )}

        <span className={`text-[10px] px-1.5 py-0.2 rounded border font-mono ${getRoleBadgeColor(node.role)}`}>
          {node.type}
        </span>

        <span className="text-xs text-slate-200 truncate font-mono">
          {node.name}
        </span>

        {node.lineno && (
          <span className="ml-auto text-[10px] text-slate-500 font-mono">
            L{node.lineno}
          </span>
        )}
      </div>

      {hasChildren && expanded && (
        <div className="border-l border-border/30 ml-3">
          {node.children!.map((child, idx) => (
            <TreeNodeItem
              key={`${child.name}-${idx}`}
              node={child}
              depth={depth + 1}
              selectedNode={selectedNode}
              onSelectNode={onSelectNode}
            />
          ))}
        </div>
      )}
    </div>
  );
};
