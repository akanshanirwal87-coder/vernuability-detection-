import React from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  ShieldCheck, 
  Terminal, 
  LayoutDashboard, 
  Cpu, 
  SearchCode, 
  Wrench, 
  FileCheck2, 
  ArrowRight,
  ShieldAlert,
  GitBranch,
  Lock,
  GraduationCap
} from 'lucide-react';

export const LandingPage: React.FC = () => {
  const navigate = useNavigate();

  const workflowSteps = [
    { label: 'Source Code', desc: 'Python, JS, TS input' },
    { label: 'AST & Static Analysis', desc: 'Syntax tree & sink parsing' },
    { label: 'AI/ML Classification', desc: 'Pattern recognition' },
    { label: 'Risk Assessment', desc: 'CWE / OWASP scoring' },
    { label: 'Remediation', desc: 'Secure code diff & validation' },
    { label: 'Security Report', desc: 'Downloadable PDF / JSON' },
  ];

  return (
    <div className="space-y-16 py-6 max-w-6xl mx-auto">
      {/* Hero Section */}
      <div className="text-center space-y-6 pt-4">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-primary/10 border border-primary/30 text-blue-400 text-xs font-mono">
          <GraduationCap className="w-3.5 h-3.5" />
          <span>Academic B.Tech CSE (AI & ML) Research Project</span>
        </div>

        <h1 className="text-4xl sm:text-5xl lg:text-6xl font-extrabold text-white tracking-tight leading-tight max-w-4xl mx-auto">
          Find Vulnerabilities <br />
          <span className="text-transparent bg-clip-text bg-gradient-to-r from-blue-400 via-cyan-400 to-indigo-400">
            Before Attackers Do.
          </span>
        </h1>

        <p className="text-base sm:text-lg text-slate-300 max-w-2xl mx-auto leading-relaxed">
          Analyze source code, understand security risks, and get actionable remediation guidance with a hybrid static-analysis and AI-assisted security workflow.
        </p>

        <div className="flex flex-wrap items-center justify-center gap-4 pt-2">
          <button
            onClick={() => navigate('/scan')}
            className="flex items-center gap-2 px-6 py-3 rounded-lg bg-primary hover:bg-primary-hover text-white text-sm font-semibold transition-all shadow-lg shadow-blue-500/20"
          >
            <Terminal className="w-4 h-4" />
            <span>Start Secure Scan</span>
          </button>
          <button
            onClick={() => navigate('/dashboard')}
            className="flex items-center gap-2 px-6 py-3 rounded-lg bg-surface hover:bg-surface/80 border border-border text-slate-200 text-sm font-medium transition-all"
          >
            <LayoutDashboard className="w-4 h-4" />
            <span>Explore Dashboard</span>
          </button>
        </div>
      </div>

      {/* Visual Workspace Preview */}
      <div className="relative rounded-2xl border border-border bg-[#0B1020] p-4 shadow-2xl overflow-hidden">
        <div className="flex items-center justify-between pb-3 border-b border-border/80 px-2">
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-red-500/80" />
            <div className="w-3 h-3 rounded-full bg-amber-500/80" />
            <div className="w-3 h-3 rounded-full bg-emerald-500/80" />
            <span className="text-xs font-mono text-slate-400 ml-2">SecureCode AI — Live Analysis Preview</span>
          </div>
          <span className="text-xs font-mono text-cyan-400 bg-cyan-950/60 border border-cyan-800/40 px-2 py-0.5 rounded">
            AST Engine Active
          </span>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 mt-4 font-mono text-xs">
          {/* Left: Code Viewer Preview */}
          <div className="lg:col-span-7 bg-[#070B14] p-4 rounded-xl border border-border space-y-2 text-slate-300 overflow-x-auto">
            <div className="text-[11px] text-slate-500 pb-2 border-b border-border/40 flex justify-between">
              <span>auth_service.py</span>
              <span className="text-red-400 font-bold">1 Finding Detected</span>
            </div>
            <p><span className="text-slate-600 select-none mr-3">1</span><span className="text-blue-400">def</span> <span className="text-yellow-300">get_user</span>(username):</p>
            <p><span className="text-slate-600 select-none mr-3">2</span>    conn = sqlite3.connect(<span className="text-emerald-300">"app.db"</span>)</p>
            <p className="bg-red-950/40 border border-red-800/60 p-1 rounded text-red-200">
              <span className="text-red-400 font-bold select-none mr-2">3 !</span>
              query = <span className="text-emerald-300">"SELECT * FROM users WHERE name = '"</span> + username + <span className="text-emerald-300">"'"</span>
            </p>
            <p><span className="text-slate-600 select-none mr-3">4</span>    conn.cursor().execute(query)</p>
            <p><span className="text-slate-600 select-none mr-3">5</span>    <span className="text-blue-400">return</span> cursor.fetchone()</p>
          </div>

          {/* Right: Remediation Preview */}
          <div className="lg:col-span-5 bg-card p-4 rounded-xl border border-border space-y-3">
            <div className="flex items-center justify-between">
              <span className="px-2 py-0.5 rounded bg-red-950/60 text-red-400 border border-red-800/60 font-bold text-[10px]">
                CRITICAL • CWE-89
              </span>
              <span className="text-[10px] text-slate-400">96% Confidence</span>
            </div>
            <p className="font-semibold text-slate-100 text-xs font-sans">
              SQL Injection via Dynamic String Concatenation
            </p>
            <div className="p-2.5 rounded bg-[#070B14] border border-emerald-900/40 text-emerald-300 font-mono text-[11px]">
              <span className="text-[10px] text-emerald-400 block mb-1 font-sans font-semibold">Suggested Secure Fix:</span>
              cursor.execute("SELECT * FROM users WHERE name = ?", (username,))
            </div>
            <div className="flex items-center justify-between pt-1 text-[11px] text-slate-400 font-sans">
              <span>Status: <strong className="text-emerald-400">Remediated & Verified</strong></span>
              <span className="text-cyan-400 font-mono">AST Match Passed</span>
            </div>
          </div>
        </div>
      </div>

      {/* Simplified End-to-End Workflow Diagram */}
      <div className="space-y-6">
        <div className="text-center">
          <h2 className="text-2xl font-bold text-white tracking-tight">End-to-End Security Architecture</h2>
          <p className="text-xs text-slate-400 mt-1">Multi-stage pipeline combining program analysis with AI classification</p>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
          {workflowSteps.map((step, idx) => (
            <div key={idx} className="relative p-3 rounded-xl bg-card border border-border text-center flex flex-col justify-between">
              <div>
                <span className="text-[10px] font-mono text-cyan-400 font-bold block mb-1">
                  0{idx + 1}
                </span>
                <h3 className="font-semibold text-slate-200 text-xs mb-1">
                  {step.label}
                </h3>
                <p className="text-[10px] text-slate-400">
                  {step.desc}
                </p>
              </div>
              {idx < workflowSteps.length - 1 && (
                <div className="hidden lg:block absolute -right-2 top-1/2 -translate-y-1/2 z-10 text-slate-500">
                  →
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Four Core Feature Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-5 rounded-xl bg-card border border-border space-y-3">
          <div className="p-2 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-400 w-fit">
            <Cpu className="w-5 h-5" />
          </div>
          <h3 className="font-semibold text-white text-sm">Intelligent Code Analysis</h3>
          <p className="text-xs text-slate-400 leading-relaxed">
            Constructs Abstract Syntax Trees (AST) and traces control flow to locate sensitive operation sinks across Python and JavaScript code.
          </p>
        </div>

        <div className="p-5 rounded-xl bg-card border border-border space-y-3">
          <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 w-fit">
            <SearchCode className="w-5 h-5" />
          </div>
          <h3 className="font-semibold text-white text-sm">Context-Aware Detection</h3>
          <p className="text-xs text-slate-400 leading-relaxed">
            Identifies SQL injection, command execution, hardcoded credentials, and path traversal with exact line numbers and supporting evidence.
          </p>
        </div>

        <div className="p-5 rounded-xl bg-card border border-border space-y-3">
          <div className="p-2 rounded-lg bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 w-fit">
            <Wrench className="w-5 h-5" />
          </div>
          <h3 className="font-semibold text-white text-sm">AI-Assisted Remediation</h3>
          <p className="text-xs text-slate-400 leading-relaxed">
            Provides side-by-side secure alternatives, explanations of root causes, and automated validation tests against proposed patches.
          </p>
        </div>

        <div className="p-5 rounded-xl bg-card border border-border space-y-3">
          <div className="p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 w-fit">
            <FileCheck2 className="w-5 h-5" />
          </div>
          <h3 className="font-semibold text-white text-sm">Developer-Friendly Reports</h3>
          <p className="text-xs text-slate-400 leading-relaxed">
            Exports audit-ready PDF, JSON, and CSV reports containing executive summaries, CWE citations, and actionable fix instructions.
          </p>
        </div>
      </div>

      {/* Disclaimer / Academic Integrity Notice */}
      <div className="p-4 rounded-xl bg-surface/40 border border-border text-center text-xs text-slate-400 max-w-3xl mx-auto space-y-1">
        <p className="font-semibold text-slate-300">
          Academic Research & Verification Notice
        </p>
        <p>
          SecureCode AI is designed to assist software developers in discovering code vulnerabilities. Scan findings, AI explanations, and suggested remediations are advisory and require engineering validation prior to production deployment.
        </p>
      </div>
    </div>
  );
};

