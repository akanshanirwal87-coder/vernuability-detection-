import React from 'react';
import { 
  BookOpen, 
  ShieldCheck, 
  Cpu, 
  GitBranch, 
  Layers, 
  GraduationCap, 
  ExternalLink,
  AlertTriangle,
  Code2,
  Brain,
  Database
} from 'lucide-react';

export const DocsPage: React.FC = () => {
  return (
    <div className="space-y-8 max-w-4xl mx-auto py-2">
      {/* Header */}
      <div className="space-y-2 border-b border-border pb-4">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-primary/10 border border-primary/30 text-blue-400 text-xs font-mono">
          <GraduationCap className="w-3.5 h-3.5" />
          <span>B.Tech Minor Project • Academic Documentation</span>
        </div>
        <h1 className="text-3xl font-bold text-white tracking-tight">
          System Documentation & Theoretical Foundation
        </h1>
        <p className="text-xs text-slate-400 leading-relaxed">
          AI-Driven Code Security Vulnerability Detection and Remediation — Architectural specification and analysis principles.
        </p>
      </div>

      {/* Academic Project Credentials */}
      <div className="p-4 rounded-xl bg-card border border-border text-xs space-y-2">
        <h3 className="font-semibold text-slate-200 uppercase tracking-wider text-[11px] text-cyan-400">
          Project Credentials & Team
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-slate-300">
          <div>
            <p className="text-slate-400">Institution:</p>
            <p className="font-medium text-white">Panipat Institute of Engineering & Technology (PIET)</p>
            <p className="text-slate-400 text-[11px]">Affiliated to Kurukshetra University, Kurukshetra</p>
          </div>
          <div>
            <p className="text-slate-400">Supervision:</p>
            <p className="font-medium text-white">Prof. (Dr.) Devendra Parsad / Ms. Taruna Chawla</p>
            <p className="text-slate-400 text-[11px]">Department of CSE (AI & ML)</p>
          </div>
          <div>
            <p className="text-slate-400">Group Members:</p>
            <p className="font-medium text-white">1. Akansha (Roll: 28240546)</p>
            <p className="font-medium text-white">2. Vanshika (Roll: 28240554)</p>
          </div>
          <div>
            <p className="text-slate-400">Domain Area:</p>
            <p className="font-medium text-white">AI/ML-Based Software Security & Vulnerability Remediation</p>
          </div>
        </div>
      </div>

      {/* 1. Core Methodology */}
      <div className="space-y-4">
        <h2 className="text-base font-bold text-white flex items-center gap-2">
          <Layers className="w-4 h-4 text-primary" />
          <span>1. Program Analysis Pipeline</span>
        </h2>
        <div className="p-5 rounded-xl bg-card border border-border text-xs text-slate-300 leading-relaxed space-y-3">
          <p>
            SecureCode AI follows a hybrid static-analysis paradigm that combines deterministic compiler techniques with AI/ML pattern understanding:
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-1">
            <div className="p-3 rounded-lg bg-[#0F172A] border border-border space-y-1">
              <span className="font-mono text-cyan-400 font-bold text-[11px]">Stage A: AST Parsing</span>
              <p className="text-[11px] text-slate-400">
                Transforms plain text code into structured syntax trees to inspect calls, arguments, variable bindings, and dangerous sinks.
              </p>
            </div>
            <div className="p-3 rounded-lg bg-[#0F172A] border border-border space-y-1">
              <span className="font-mono text-cyan-400 font-bold text-[11px]">Stage B: Taint Analysis</span>
              <p className="text-[11px] text-slate-400">
                Tracks user-controlled input sources across variable assignments to ensure untrusted input cannot reach sensitive execution functions.
              </p>
            </div>
            <div className="p-3 rounded-lg bg-[#0F172A] border border-border space-y-1">
              <span className="font-mono text-cyan-400 font-bold text-[11px]">Stage C: Remediation</span>
              <p className="text-[11px] text-slate-400">
                Synthesizes secure alternatives (e.g. prepared statements, safe subprocess calls) and re-evaluates them using AST verification.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* 2. Supported Vulnerability Classes */}
      <div className="space-y-4">
        <h2 className="text-base font-bold text-white flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-emerald-400" />
          <span>2. Target Vulnerability Classes & CWE Mappings</span>
        </h2>
        <div className="p-5 rounded-xl bg-card border border-border space-y-3 text-xs">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-[#0F172A] text-slate-400 font-mono text-[11px] border-b border-border">
                <tr>
                  <th className="py-2.5 px-3">CWE ID</th>
                  <th className="py-2.5 px-3">Weakness Class</th>
                  <th className="py-2.5 px-3">OWASP Category</th>
                  <th className="py-2.5 px-3">Default Risk</th>
                  <th className="py-2.5 px-3">Remediation Pattern</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/60 text-[11px]">
                <tr>
                  <td className="py-2.5 px-3 font-mono text-cyan-400">CWE-89</td>
                  <td className="py-2.5 px-3 font-semibold text-white">SQL Injection</td>
                  <td className="py-2.5 px-3 text-slate-400">A03:2021-Injection</td>
                  <td className="py-2.5 px-3 text-red-400 font-bold">Critical</td>
                  <td className="py-2.5 px-3 text-emerald-400">Parameterized Prepared Statements</td>
                </tr>
                <tr>
                  <td className="py-2.5 px-3 font-mono text-cyan-400">CWE-78</td>
                  <td className="py-2.5 px-3 font-semibold text-white">Command Injection</td>
                  <td className="py-2.5 px-3 text-slate-400">A03:2021-Injection</td>
                  <td className="py-2.5 px-3 text-red-400 font-bold">Critical</td>
                  <td className="py-2.5 px-3 text-emerald-400">subprocess.run(shell=False, args=[])</td>
                </tr>
                <tr>
                  <td className="py-2.5 px-3 font-mono text-cyan-400">CWE-798</td>
                  <td className="py-2.5 px-3 font-semibold text-white">Hardcoded Secrets</td>
                  <td className="py-2.5 px-3 text-slate-400">A07:2021-Auth Failures</td>
                  <td className="py-2.5 px-3 text-orange-400 font-bold">High</td>
                  <td className="py-2.5 px-3 text-emerald-400">Environment Variables / Secrets Vault</td>
                </tr>
                <tr>
                  <td className="py-2.5 px-3 font-mono text-cyan-400">CWE-22</td>
                  <td className="py-2.5 px-3 font-semibold text-white">Path Traversal</td>
                  <td className="py-2.5 px-3 text-slate-400">A01:2021-Broken Access</td>
                  <td className="py-2.5 px-3 text-orange-400 font-bold">High</td>
                  <td className="py-2.5 px-3 text-emerald-400">os.path.basename & abspath containment</td>
                </tr>
                <tr>
                  <td className="py-2.5 px-3 font-mono text-cyan-400">CWE-79</td>
                  <td className="py-2.5 px-3 font-semibold text-white">Cross-Site Scripting (XSS)</td>
                  <td className="py-2.5 px-3 text-slate-400">A03:2021-Injection</td>
                  <td className="py-2.5 px-3 text-orange-400 font-bold">High</td>
                  <td className="py-2.5 px-3 text-emerald-400">DOMPurify / Context-aware HTML Encoding</td>
                </tr>
                <tr>
                  <td className="py-2.5 px-3 font-mono text-cyan-400">CWE-327</td>
                  <td className="py-2.5 px-3 font-semibold text-white">Insecure Cryptography</td>
                  <td className="py-2.5 px-3 text-slate-400">A02:2021-Crypto Failures</td>
                  <td className="py-2.5 px-3 text-amber-400 font-bold">Medium</td>
                  <td className="py-2.5 px-3 text-emerald-400">Upgrade to SHA-256 or Argon2id</td>
                </tr>
                <tr>
                  <td className="py-2.5 px-3 font-mono text-cyan-400">CWE-502</td>
                  <td className="py-2.5 px-3 font-semibold text-white">Unsafe Deserialization</td>
                  <td className="py-2.5 px-3 text-slate-400">A08:2021-Integrity Failures</td>
                  <td className="py-2.5 px-3 text-red-400 font-bold">Critical</td>
                  <td className="py-2.5 px-3 text-emerald-400">Safe JSON format (json.loads)</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* 3. AI/ML Training Pipeline & External Real-World Datasets */}
      <div className="space-y-4">
        <h2 className="text-base font-bold text-white flex items-center gap-2">
          <Brain className="w-4 h-4 text-purple-400" />
          <span>3. AI/ML Training Pipeline & Real-World Datasets</span>
        </h2>
        <div className="p-5 rounded-xl bg-card border border-border text-xs text-slate-300 leading-relaxed space-y-4">
          <p>
            SecureCode AI incorporates an intelligent machine learning classification engine (<strong>SecureCode-VulnNet v2.0</strong>) trained on real-world vulnerability repositories and security bulletins from two primary sources:
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 rounded-lg bg-[#0F172A] border border-border space-y-2">
              <div className="flex items-center gap-2 text-blue-400 font-semibold font-mono text-xs">
                <Database className="w-3.5 h-3.5" />
                <span>OSV.dev (Google / OpenSSF)</span>
              </div>
              <p className="text-[11px] text-slate-400 leading-relaxed">
                Connects directly to the Open Source Vulnerabilities REST API (<code>https://api.osv.dev/v1/query</code>) and ingests thousands of CVE records across PyPI and npm ecosystems, enabling automated Software Composition Analysis (SCA) for imported packages.
              </p>
            </div>

            <div className="p-4 rounded-lg bg-[#0F172A] border border-border space-y-2">
              <div className="flex items-center gap-2 text-purple-300 font-semibold font-mono text-xs">
                <ShieldCheck className="w-3.5 h-3.5" />
                <span>ManageEngine Endpoint Central</span>
              </div>
              <p className="text-[11px] text-slate-400 leading-relaxed">
                Extracts free public CVE advisories (e.g. CVE-2021-44515 unauthenticated RCE, CVE-2020-10189 deserialization, CVE-2021-44077 upload path traversal) and endpoint security baseline rules to train detection of system execution flaws and unquoted paths.
              </p>
            </div>
          </div>

          <div className="p-3.5 rounded-lg bg-purple-950/20 border border-purple-500/30 flex flex-wrap items-center justify-between gap-3 text-xs">
            <div>
              <span className="font-semibold text-white">Hybrid Ensemble Architecture:</span>
              <span className="text-slate-400 ml-1">Sublinear TF-IDF (n-grams 1-3) + 17 Semantic Sinks Vectorizer + RandomForest & LogisticRegression Ensemble.</span>
            </div>
            <div className="flex items-center gap-2 font-mono text-[11px]">
              <span className="text-emerald-400">90.5% Accuracy</span>
              <span className="text-slate-500">•</span>
              <span className="text-cyan-400">96.3% Precision</span>
              <span className="text-slate-500">•</span>
              <span className="text-purple-300">313+ Dataset Samples</span>
            </div>
          </div>
        </div>
      </div>

      {/* 4. Limitations & Future Scope */}
      <div className="space-y-4">
        <h2 className="text-base font-bold text-white flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-amber-400" />
          <span>4. Limitations & Future Scope</span>
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="p-4 rounded-xl bg-card border border-border space-y-2">
            <h4 className="font-semibold text-slate-200">Current Scope & Limitations</h4>
            <ul className="list-disc list-inside text-slate-400 space-y-1 leading-relaxed text-[11px]">
              <li>Analysis focuses on intra-file patterns; complex cross-repository dependencies are out of scope.</li>
              <li>Dynamic runtime reflection may escape pure static AST analysis.</li>
              <li>Automated fix verification requires engineering review before production deployment.</li>
            </ul>
          </div>
          <div className="p-4 rounded-xl bg-card border border-border space-y-2">
            <h4 className="font-semibold text-slate-200">Planned Future Extensions</h4>
            <ul className="list-disc list-inside text-slate-400 space-y-1 leading-relaxed text-[11px]">
              <li>Fine-tuned CodeLlama or StarCoder LLM integration for complex code repairs.</li>
              <li>GitHub Action CI/CD pre-commit hooks for automated pipeline gating.</li>
              <li>Support for compiled languages like C/C++, Java, and Go via tree-sitter.</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
};

