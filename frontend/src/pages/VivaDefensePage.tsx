import React, { useState, useEffect } from 'react';
import { 
  GraduationCap, 
  Award, 
  Play, 
  CheckCircle2, 
  AlertTriangle, 
  Layers, 
  Brain, 
  ShieldCheck, 
  Activity, 
  FileCheck2, 
  HelpCircle, 
  ChevronRight, 
  ChevronLeft, 
  Maximize2, 
  BookOpen, 
  Terminal, 
  Calculator, 
  RotateCcw,
  Sparkles,
  ExternalLink,
  Copy,
  Check
} from 'lucide-react';
import { runAcademicBenchmark, calculateCvss, getVivaBank, getMlModelInfo } from '../services/scanService';
import type { BenchmarkRunResponse, CvssCalculationRequest, CvssCalculationResponse, VivaBankResponse, ModelMetricsResponse } from '../types/scan';
import { toast } from 'sonner';

export const VivaDefensePage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'benchmark' | 'viva' | 'presentation' | 'cvss'>('benchmark');

  // Benchmark state
  const [benchmarkLoading, setBenchmarkLoading] = useState<boolean>(false);
  const [benchmarkData, setBenchmarkData] = useState<BenchmarkRunResponse | null>(null);

  // Viva bank & live ML metadata state
  const [vivaData, setVivaData] = useState<VivaBankResponse | null>(null);
  const [modelInfo, setModelInfo] = useState<ModelMetricsResponse | null>(null);
  const [expandedQuestion, setExpandedQuestion] = useState<string>('q1');

  // Presentation Deck state
  const [currentSlide, setCurrentSlide] = useState<number>(0);

  // CVSS Calculator state
  const [cvssRequest, setCvssRequest] = useState<CvssCalculationRequest>({
    attackVector: 'N',
    attackComplexity: 'L',
    privilegesRequired: 'N',
    userInteraction: 'N',
    scope: 'U',
    confidentiality: 'H',
    integrity: 'H',
    availability: 'H'
  });
  const [cvssResult, setCvssResult] = useState<CvssCalculationResponse | null>(null);
  const [copiedVector, setCopiedVector] = useState<boolean>(false);

  useEffect(() => {
    loadInitialData();
  }, []);

  const loadInitialData = async () => {
    try {
      const [viva, cvss, ml] = await Promise.all([
        getVivaBank(),
        calculateCvss(cvssRequest),
        getMlModelInfo().catch(() => null),
      ]);
      setVivaData(viva);
      setCvssResult(cvss);
      if (ml) setModelInfo(ml);
    } catch (e) {
      console.warn('Initial viva load error', e);
    }
  };

  const handleRunBenchmark = async () => {
    setBenchmarkLoading(true);
    toast.info('Executing live Hybrid Engine benchmark suite across 16 CWE samples...');
    try {
      const res = await runAcademicBenchmark();
      setBenchmarkData(res);
      toast.success(
        `Benchmark finished: ${res.accuracy}% accuracy (${res.truePositives + res.trueNegatives}/${res.totalTests}), avg latency ${res.averageLatencyMs}ms`
      );
    } catch (e: any) {
      toast.error(e?.message || 'Failed to execute live benchmark');
    } finally {
      setBenchmarkLoading(false);
    }
  };

  const handleCvssChange = async (metric: keyof CvssCalculationRequest, value: string) => {
    const updated = { ...cvssRequest, [metric]: value };
    setCvssRequest(updated);
    try {
      const res = await calculateCvss(updated);
      setCvssResult(res);
    } catch (e) {
      console.error('CVSS calculation failed', e);
    }
  };

  const copyCvssVector = () => {
    if (cvssResult?.vectorString) {
      navigator.clipboard.writeText(cvssResult.vectorString);
      setCopiedVector(true);
      setTimeout(() => setCopiedVector(false), 2000);
      toast.success('CVSS v3.1 vector copied to clipboard');
    }
  };

  const SLIDES = [
    {
      title: "1. Project Overview & Student Identification",
      tagline: "Academic Defense • B.Tech CSE (Artificial Intelligence & Machine Learning)",
      content: (
        <div className="space-y-4">
          <div className="p-4 rounded-xl bg-surface/80 border border-border space-y-2">
            <h3 className="text-sm font-bold text-cyan-400 uppercase tracking-wider">Project Title</h3>
            <p className="text-base text-white font-semibold">
              SecureCode AI — AI-Driven Code Security Vulnerability Detection and Remediation
            </p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-3.5 rounded-lg bg-card border border-border space-y-1">
              <span className="text-[11px] text-slate-400 uppercase font-mono">Presenting Students</span>
              <p className="text-xs text-white font-medium">• Akansha (Roll: 28240546)</p>
              <p className="text-xs text-white font-medium">• Vanshika (Roll: 28240554)</p>
            </div>
            <div className="p-3.5 rounded-lg bg-card border border-border space-y-1">
              <span className="text-[11px] text-slate-400 uppercase font-mono">Faculty Supervisors</span>
              <p className="text-xs text-white font-medium">• Prof. (Dr.) Devendra Parsad</p>
              <p className="text-xs text-white font-medium">• Ms. Taruna Chawla</p>
            </div>
          </div>
          <div className="p-3 rounded-lg bg-[#0B1020] border border-border/60 text-xs text-slate-300">
            <strong>Institution:</strong> Panipat Institute of Engineering & Technology (PIET), affiliated to Kurukshetra University, Kurukshetra.
          </div>
        </div>
      )
    },
    {
      title: "2. Problem Statement & Motivation",
      tagline: "Bridging the Gap Between Alert Noise and Automated Remediation",
      content: (
        <div className="space-y-3 text-xs text-slate-300">
          <div className="p-3 rounded-lg bg-rose-950/30 border border-rose-800/40 text-rose-300">
            <strong>The Core Dilemma:</strong> Traditional static analysis tools (SonarQube, Bandit, ESLint) suffer from excessive False Positive rates (alert fatigue) and provide static warnings without verified, contextual secure code fixes.
          </div>
          <ul className="space-y-2 pl-4 list-disc text-slate-300">
            <li><strong>Data Privacy Hazard:</strong> Sending proprietary software to third-party cloud LLMs violates corporate intellectual property and privacy mandates.</li>
            <li><strong>AI Hallucination:</strong> Unconstrained LLMs frequently propose hallucinated, syntactically broken, or insecure fix suggestions.</li>
            <li><strong>Research Objective:</strong> Engineer a hybrid SAST platform combining compiler AST structural inspection, calibrated machine learning ({modelInfo?.accuracy !== undefined ? `${modelInfo.accuracy}%` : 'verified'} holdout test accuracy), and compile-time AST fix verification with zero external code transmission.</li>
          </ul>
        </div>
      )
    },
    {
      title: "3. System Architecture & Dual-Engine Pipeline",
      tagline: "Compiler AST + Calibrated Machine Learning Ensemble",
      content: (
        <div className="space-y-3">
          <div className="p-3 rounded-lg bg-[#0B1020] border border-cyan-800/40 font-mono text-[11px] text-cyan-300 leading-relaxed overflow-x-auto">
            {"Source Code"} ➔ {"[AST Structural Parser]"} ➔ {"[Data-Flow Taint Tracker]"} ➔ {`[${modelInfo?.selectedBinaryModel ?? 'Calibrated'} ML Classifier]`} ➔ {"[Google OSV.dev & ManageEngine Grounding]"} ➔ {"[AST Fix Verification]"}
          </div>
          <div className="grid grid-cols-2 gap-3 text-xs">
            <div className="p-3 rounded-lg bg-card border border-border">
              <span className="font-semibold text-white">Engine 1: AST Parser</span>
              <p className="text-slate-400 text-[11px] mt-1">Extracts Call, BinOp, and JoinedStr nodes to identify unescaped dynamic parameters flowing into sinks.</p>
            </div>
            <div className="p-3 rounded-lg bg-card border border-border">
              <span className="font-semibold text-white">Engine 2: ML Classifier</span>
              <p className="text-slate-400 text-[11px] mt-1">
                {modelInfo
                  ? `${modelInfo.featuresCount.toLocaleString()}-feature hybrid model (TF-IDF + 22 domain sinks) trained across ${modelInfo.totalSamples} samples with ${modelInfo.accuracy}% untouched test accuracy.`
                  : 'Hybrid TF-IDF + domain security sink classifier evaluated on strictly group-disjoint holdout partitions.'}
              </p>
            </div>
          </div>
        </div>
      )
    },
    {
      title: "4. Data-Flow & Taint Propagation Analysis",
      tagline: "Formal Verification of Source ➔ Transform ➔ Sink",
      content: (
        <div className="space-y-3 text-xs text-slate-300">
          <p>
            A security vulnerability exists if and only if untrusted user input reaches a sensitive execution sink without passing through a recognized sanitizer:
          </p>
          <div className="grid grid-cols-3 gap-2 text-center font-mono">
            <div className="p-2.5 rounded bg-blue-950/50 border border-blue-800 text-blue-300">
              <div className="font-bold">1. SOURCE</div>
              <div className="text-[10px] text-slate-400 mt-1">request.args, sys.argv</div>
            </div>
            <div className="p-2.5 rounded bg-amber-950/50 border border-amber-800 text-amber-300">
              <div className="font-bold">2. TRANSFORM</div>
              <div className="text-[10px] text-slate-400 mt-1">String concat (+, f"")</div>
            </div>
            <div className="p-2.5 rounded bg-rose-950/50 border border-rose-800 text-rose-300">
              <div className="font-bold">3. SINK</div>
              <div className="text-[10px] text-slate-400 mt-1">execute(), os.system()</div>
            </div>
          </div>
          <p className="text-[11px] text-slate-400">
            Our AST walker builds the explicit Abstract Syntax Graph and traces variable assignment definitions across lexical scopes.
          </p>
        </div>
      )
    },
    {
      title: "5. Dataset Grounding: OSV.dev & ManageEngine",
      tagline: "Real-World Threat Intelligence Integration",
      content: (
        <div className="space-y-3 text-xs text-slate-300">
          <div className="grid grid-cols-2 gap-3">
            <div className="p-3 rounded-lg bg-card border border-border space-y-1">
              <div className="font-bold text-white flex items-center gap-1.5">
                <ExternalLink className="w-3.5 h-3.5 text-cyan-400" />
                Google OSV.dev
              </div>
              <p className="text-[11px] text-slate-400">
                Direct REST connector against open-source vulnerability feeds. Performs automated Software Composition Analysis (SCA) on all imported packages.
              </p>
            </div>
            <div className="p-3 rounded-lg bg-card border border-border space-y-1">
              <div className="font-bold text-white flex items-center gap-1.5">
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                ManageEngine Security
              </div>
              <p className="text-[11px] text-slate-400">
                Enterprise endpoint threat definitions (CVE-2021-44515, unquoted service paths) to align code quality with enterprise hardening baselines.
              </p>
            </div>
          </div>
        </div>
      )
    },
    {
      title: "6. Compile-Time AST Fix Verification",
      tagline: "Eliminating Hallucinations with Mathematical Certainty",
      content: (
        <div className="space-y-3 text-xs text-slate-300">
          <p>
            Unlike naive chatbots, SecureCode AI verifies proposed remediations through our <code>FixValidator</code> engine:
          </p>
          <div className="p-3 rounded-lg bg-card border border-border space-y-2">
            <div className="flex items-center gap-2 text-emerald-400 font-semibold">
              <CheckCircle2 className="w-4 h-4" />
              <span>Two-Stage Verification Guarantee</span>
            </div>
            <ol className="list-decimal pl-4 space-y-1 text-slate-300 text-[11px]">
              <li><strong>Target Sink Elimination:</strong> Recompiles the proposed fix into an AST tree and verifies the vulnerable execution sink is completely eliminated.</li>
              <li><strong>Zero Regression:</strong> Validates that no new compilation errors, syntax defects, or un-sanitized sinks are introduced.</li>
            </ol>
          </div>
        </div>
      )
    },
    {
      title: "7. Conclusion & Research Contributions",
      tagline: "Academic Milestones Achieved",
      content: (
        <div className="space-y-3 text-xs text-slate-300">
          <div className="grid grid-cols-2 gap-3">
            <div className="p-3 rounded-lg bg-surface border border-border">
              <div className="font-bold text-cyan-400">
                {modelInfo ? `${modelInfo.accuracy}% Test Accuracy` : 'Live Holdout Accuracy'}
              </div>
              <div className="text-[11px] text-slate-400 mt-1">
                {modelInfo
                  ? `${modelInfo.selectedBinaryModel || 'ML'} model with ${modelInfo.precision}% precision, ${modelInfo.recall}% recall, and ${modelInfo.falsePositiveRate ?? 0}% FPR (n=${modelInfo.testSamples} untouched test).`
                  : 'Group-disjoint supervised evaluation balancing precision and recall without leakage.'}
              </div>
            </div>
            <div className="p-3 rounded-lg bg-surface border border-border">
              <div className="font-bold text-emerald-400">
                {benchmarkData ? `${benchmarkData.averageLatencyMs}ms Avg Latency` : 'Sub-Millisecond AST + Fast ML'}
              </div>
              <div className="text-[11px] text-slate-400 mt-1">Near-instant local inference suitable for automated CI/CD pipeline integration.</div>
            </div>
          </div>
          <div className="p-3 rounded-lg bg-[#0B1020] border border-border text-[11px] text-slate-300">
            <strong>Future Scope:</strong> Extending taint tracking to multi-threaded async frameworks, inter-procedural call graphs, and expanding to Rust and Go codebases.
          </div>
        </div>
      )
    }
  ];

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header Banner */}
      <div className="p-5 rounded-2xl bg-gradient-to-r from-blue-950/60 via-card to-cyan-950/40 border border-primary/30 shadow-lg shadow-blue-950/20">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2 text-cyan-400 text-xs font-semibold uppercase tracking-wider">
              <GraduationCap className="w-4 h-4" />
              <span>Kurukshetra University • PIET Dept. of CSE (AI & ML)</span>
            </div>
            <h1 className="text-xl sm:text-2xl font-bold text-white tracking-tight flex items-center gap-2">
              Examiner Defense & Viva Presentation Center
            </h1>
            <p className="text-xs text-slate-300 max-w-3xl">
              Academic evaluation workspace for external examiners: live benchmark suite execution, theoretical viva voce question bank, presentation slides, and CVSS v3.1 calculator.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <div className="px-3 py-1.5 rounded-lg bg-surface border border-border text-right text-[11px]">
              <span className="text-slate-400 block">Candidate Students</span>
              <span className="text-white font-semibold">Akansha & Vanshika</span>
            </div>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex flex-wrap gap-2 mt-5 pt-3 border-t border-border/50">
          <button
            onClick={() => setActiveTab('benchmark')}
            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all duration-150 ${
              activeTab === 'benchmark'
                ? 'bg-primary text-white shadow-md shadow-blue-900/30'
                : 'bg-surface/60 text-slate-400 hover:text-white hover:bg-surface'
            }`}
          >
            <Activity className="w-3.5 h-3.5" />
            <span>1-Click Examiner Benchmark</span>
          </button>
          <button
            onClick={() => setActiveTab('viva')}
            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all duration-150 ${
              activeTab === 'viva'
                ? 'bg-primary text-white shadow-md shadow-blue-900/30'
                : 'bg-surface/60 text-slate-400 hover:text-white hover:bg-surface'
            }`}
          >
            <HelpCircle className="w-3.5 h-3.5" />
            <span>Viva Voce Defense Q&A</span>
          </button>
          <button
            onClick={() => setActiveTab('presentation')}
            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all duration-150 ${
              activeTab === 'presentation'
                ? 'bg-primary text-white shadow-md shadow-blue-900/30'
                : 'bg-surface/60 text-slate-400 hover:text-white hover:bg-surface'
            }`}
          >
            <Maximize2 className="w-3.5 h-3.5" />
            <span>Examiner Slide Deck</span>
          </button>
          <button
            onClick={() => setActiveTab('cvss')}
            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all duration-150 ${
              activeTab === 'cvss'
                ? 'bg-primary text-white shadow-md shadow-blue-900/30'
                : 'bg-surface/60 text-slate-400 hover:text-white hover:bg-surface'
            }`}
          >
            <Calculator className="w-3.5 h-3.5" />
            <span>CVSS v3.1 Calculator</span>
          </button>
        </div>
      </div>

      {/* TAB 1: ACADEMIC BENCHMARK */}
      {activeTab === 'benchmark' && (
        <div className="space-y-6">
          {/* Action Card */}
          <div className="p-4 rounded-xl bg-card border border-border flex flex-wrap items-center justify-between gap-4">
            <div>
              <h2 className="text-sm font-bold text-white flex items-center gap-2">
                <Activity className="w-4 h-4 text-cyan-400" />
                Empirical Evaluation Benchmark Suite
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Runs 16 standardized vulnerable/secure unit test cases (8 pairs) across SQLi, Command Injection, Path Traversal, Deserialization, Crypto, Secrets, XSS, and Prototype Pollution.
              </p>
            </div>
            <button
              onClick={handleRunBenchmark}
              disabled={benchmarkLoading}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold shadow-lg shadow-emerald-900/30 transition-all duration-200 active:scale-95"
            >
              <Play className={`w-4 h-4 ${benchmarkLoading ? 'animate-spin' : ''}`} />
              <span>{benchmarkLoading ? 'Running Test Suite...' : 'Execute Live Benchmark'}</span>
            </button>
          </div>

          {/* Benchmark Results */}
          {benchmarkData ? (
            <div className="space-y-6">
              {/* Metric Cards */}
              <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
                <div className="p-3.5 rounded-xl bg-card border border-border">
                  <span className="text-[11px] text-slate-400 uppercase font-mono">Benchmark Accuracy</span>
                  <p className="text-2xl font-bold text-emerald-400 mt-1">{benchmarkData.accuracy}%</p>
                  <span className="text-[10px] text-slate-500">
                    {benchmarkData.truePositives + benchmarkData.trueNegatives} of {benchmarkData.totalTests} Cases Correct
                  </span>
                </div>
                <div className="p-3.5 rounded-xl bg-card border border-border">
                  <span className="text-[11px] text-slate-400 uppercase font-mono">Precision</span>
                  <p className="text-2xl font-bold text-cyan-400 mt-1">{benchmarkData.precision}%</p>
                  <span className="text-[10px] text-slate-500">
                    {benchmarkData.falsePositives === 0
                      ? 'Zero False Positives'
                      : `${benchmarkData.falsePositives} False Positive${benchmarkData.falsePositives === 1 ? '' : 's'}`}
                  </span>
                </div>
                <div className="p-3.5 rounded-xl bg-card border border-border">
                  <span className="text-[11px] text-slate-400 uppercase font-mono">Recall</span>
                  <p className="text-2xl font-bold text-blue-400 mt-1">{benchmarkData.recall}%</p>
                  <span className="text-[10px] text-slate-500">
                    {benchmarkData.falseNegatives === 0
                      ? 'Zero False Negatives'
                      : `${benchmarkData.falseNegatives} False Negative${benchmarkData.falseNegatives === 1 ? '' : 's'}`}
                  </span>
                </div>
                <div className="p-3.5 rounded-xl bg-card border border-border">
                  <span className="text-[11px] text-slate-400 uppercase font-mono">F1-Score</span>
                  <p className="text-2xl font-bold text-amber-400 mt-1">{benchmarkData.f1Score}%</p>
                  <span className="text-[10px] text-slate-500">Harmonic Mean</span>
                </div>
                <div className="p-3.5 rounded-xl bg-card border border-border">
                  <span className="text-[11px] text-slate-400 uppercase font-mono">Avg Latency</span>
                  <p className="text-2xl font-bold text-purple-400 mt-1">{benchmarkData.averageLatencyMs} ms</p>
                  <span className="text-[10px] text-slate-500">Per Test Case</span>
                </div>
              </div>

              {/* Confusion Matrix Card */}
              <div className="p-4 rounded-xl bg-card border border-border">
                <h3 className="text-xs font-bold text-white uppercase tracking-wider mb-3">
                  Live Confusion Matrix (N = {benchmarkData.totalTests})
                </h3>
                <div className="grid grid-cols-2 max-w-sm gap-2 font-mono text-center">
                  <div className="p-3 rounded-lg bg-emerald-950/40 border border-emerald-800">
                    <span className="text-[10px] text-slate-400 block">True Positives (TP)</span>
                    <span className="text-xl font-bold text-emerald-400">{benchmarkData.truePositives}</span>
                  </div>
                  <div className={`p-3 rounded-lg border ${
                    benchmarkData.falsePositives > 0
                      ? 'bg-amber-950/40 border-amber-700'
                      : 'bg-slate-900 border-border'
                  }`}>
                    <span className="text-[10px] text-slate-400 block">False Positives (FP)</span>
                    <span className={`text-xl font-bold ${benchmarkData.falsePositives > 0 ? 'text-amber-400' : 'text-slate-400'}`}>
                      {benchmarkData.falsePositives}
                    </span>
                  </div>
                  <div className={`p-3 rounded-lg border ${
                    benchmarkData.falseNegatives > 0
                      ? 'bg-rose-950/40 border-rose-700'
                      : 'bg-slate-900 border-border'
                  }`}>
                    <span className="text-[10px] text-slate-400 block">False Negatives (FN)</span>
                    <span className={`text-xl font-bold ${benchmarkData.falseNegatives > 0 ? 'text-rose-400' : 'text-slate-400'}`}>
                      {benchmarkData.falseNegatives}
                    </span>
                  </div>
                  <div className="p-3 rounded-lg bg-blue-950/40 border border-blue-800">
                    <span className="text-[10px] text-slate-400 block">True Negatives (TN)</span>
                    <span className="text-xl font-bold text-blue-400">{benchmarkData.trueNegatives}</span>
                  </div>
                </div>
                {modelInfo && (
                  <p className="mt-3 pt-2.5 border-t border-border/50 text-[11px] text-slate-400 font-mono">
                    Trained ML Holdout Evaluation ({modelInfo.selectedBinaryModel || 'ML Classifier'}, n={modelInfo.testSamples} untouched): Acc {modelInfo.accuracy}% • Prec {modelInfo.precision}% • Rec {modelInfo.recall}% • F1 {modelInfo.f1Score}% • FPR {modelInfo.falsePositiveRate ?? 0}%
                  </p>
                )}
              </div>

              {/* Individual Test Cases Table */}
              <div className="p-4 rounded-xl bg-card border border-border overflow-hidden">
                <h3 className="text-xs font-bold text-white uppercase tracking-wider mb-3">
                  Test Case Execution Breakdown
                </h3>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs text-left">
                    <thead className="text-[11px] text-slate-400 uppercase bg-surface/60 border-b border-border">
                      <tr>
                        <th className="py-2.5 px-3">Test Case Name</th>
                        <th className="py-2.5 px-3">CWE ID</th>
                        <th className="py-2.5 px-3">Ground Truth</th>
                        <th className="py-2.5 px-3">Prediction</th>
                        <th className="py-2.5 px-3">Latency</th>
                        <th className="py-2.5 px-3">Result</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border/50">
                      {benchmarkData.results.map((res, idx) => (
                        <tr key={idx} className="hover:bg-surface/40 transition-colors">
                          <td className="py-2 px-3 font-medium text-white">{res.name}</td>
                          <td className="py-2 px-3 font-mono text-cyan-400">{res.cwe}</td>
                          <td className="py-2 px-3">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                              res.isVulnerable ? 'bg-rose-950/70 text-rose-300' : 'bg-emerald-950/70 text-emerald-300'
                            }`}>
                              {res.isVulnerable ? 'VULNERABLE' : 'SECURE'}
                            </span>
                          </td>
                          <td className="py-2 px-3">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                              res.predictedVulnerable ? 'bg-rose-950/70 text-rose-300' : 'bg-emerald-950/70 text-emerald-300'
                            }`}>
                              {res.predictedVulnerable ? 'VULNERABLE' : 'SECURE'}
                            </span>
                          </td>
                          <td className="py-2 px-3 font-mono text-slate-400">{res.latencyMs} ms</td>
                          <td className="py-2 px-3">
                            {res.passed ? (
                              <span className="flex items-center gap-1 text-emerald-400 font-bold">
                                <CheckCircle2 className="w-3.5 h-3.5" /> PASSED
                              </span>
                            ) : (
                              <span className="flex items-center gap-1 text-rose-400 font-bold">
                                <AlertTriangle className="w-3.5 h-3.5" /> FAILED
                              </span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          ) : (
            <div className="p-8 rounded-xl bg-card border border-border text-center space-y-3">
              <Activity className="w-10 h-10 text-slate-500 mx-auto opacity-60" />
              <h3 className="text-sm font-bold text-white">Benchmark Ready to Run</h3>
              <p className="text-xs text-slate-400 max-w-md mx-auto">
                Click <strong>"Execute Live Benchmark"</strong> above to evaluate the engine live against all CWE categories in front of your examiner.
              </p>
            </div>
          )}
        </div>
      )}

      {/* TAB 2: VIVA VOCE DEFENSE BANK */}
      {activeTab === 'viva' && (
        <div className="space-y-4">
          <div className="p-4 rounded-xl bg-card border border-border">
            <h2 className="text-sm font-bold text-white flex items-center gap-2">
              <HelpCircle className="w-4 h-4 text-cyan-400" />
              Curated Examiner Viva Voce Defense Bank
            </h2>
            <p className="text-xs text-slate-400 mt-1">
              Anticipated examiner defense questions, theoretical compiler proofs, ML evaluation tradeoffs, and formal formulas.
            </p>
          </div>

          <div className="space-y-3">
            {vivaData?.questions.map((q) => {
              const isOpen = expandedQuestion === q.id;
              return (
                <div 
                  key={q.id} 
                  className="rounded-xl bg-card border border-border overflow-hidden transition-all duration-200"
                >
                  <button
                    onClick={() => setExpandedQuestion(isOpen ? '' : q.id)}
                    className="w-full p-4 text-left flex items-center justify-between gap-4 hover:bg-surface/50"
                  >
                    <div className="space-y-1">
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800">
                        {q.category}
                      </span>
                      <h3 className="text-xs sm:text-sm font-bold text-white">
                        {q.question}
                      </h3>
                    </div>
                    <ChevronRight className={`w-4 h-4 text-slate-400 transition-transform ${isOpen ? 'rotate-90' : ''}`} />
                  </button>

                  {isOpen && (
                    <div className="p-4 pt-1 border-t border-border/50 bg-[#0B1020]/60 space-y-3 text-xs text-slate-300">
                      <div className="whitespace-pre-line leading-relaxed">
                        {q.answer}
                      </div>
                      {q.formula && (
                        <div className="p-2.5 rounded-lg bg-surface border border-border font-mono text-[11px] text-cyan-300">
                          <strong>Theoretical Formula:</strong> {q.formula}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* TAB 3: PRESENTATION SLIDE DECK */}
      {activeTab === 'presentation' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between pb-2 border-b border-border">
            <span className="text-xs font-bold text-slate-300">
              Slide {currentSlide + 1} of {SLIDES.length}
            </span>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setCurrentSlide(Math.max(0, currentSlide - 1))}
                disabled={currentSlide === 0}
                className="p-1.5 rounded-lg bg-surface border border-border text-slate-300 disabled:opacity-40 hover:bg-surface/80"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              <button
                onClick={() => setCurrentSlide(Math.min(SLIDES.length - 1, currentSlide + 1))}
                disabled={currentSlide === SLIDES.length - 1}
                className="p-1.5 rounded-lg bg-surface border border-border text-slate-300 disabled:opacity-40 hover:bg-surface/80"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>

          {/* Slide Canvas */}
          <div className="p-8 rounded-2xl bg-gradient-to-b from-card to-[#0B1020] border border-border shadow-xl min-h-[380px] flex flex-col justify-between space-y-6">
            <div className="space-y-1">
              <span className="text-xs font-mono text-cyan-400 uppercase tracking-wider">
                {SLIDES[currentSlide].tagline}
              </span>
              <h2 className="text-xl font-bold text-white tracking-tight">
                {SLIDES[currentSlide].title}
              </h2>
            </div>

            <div className="flex-1">
              {SLIDES[currentSlide].content}
            </div>

            <div className="pt-3 border-t border-border/40 flex justify-between items-center text-[10px] text-slate-500 font-mono">
              <span>SecureCode AI • PIET / Kurukshetra University</span>
              <span>Akansha & Vanshika</span>
            </div>
          </div>
        </div>
      )}

      {/* TAB 4: INTERACTIVE CVSS v3.1 CALCULATOR */}
      {activeTab === 'cvss' && (
        <div className="space-y-6">
          <div className="p-4 rounded-xl bg-card border border-border">
            <h2 className="text-sm font-bold text-white flex items-center gap-2">
              <Calculator className="w-4 h-4 text-cyan-400" />
              FIRST Common Vulnerability Scoring System (CVSS v3.1) Calculator
            </h2>
            <p className="text-xs text-slate-400 mt-1">
              Compute mathematically standardized Base Severity scores for any discovered vulnerability per the official FIRST specification.
            </p>
          </div>

          {/* CVSS Live Scorecard */}
          {cvssResult && (
            <div className="p-4 rounded-xl bg-surface border border-border flex flex-wrap items-center justify-between gap-4">
              <div className="flex items-center gap-4">
                <div className={`px-4 py-2 rounded-xl text-center font-bold ${
                  cvssResult.severity === 'CRITICAL' ? 'bg-rose-950 text-rose-300 border border-rose-700' :
                  cvssResult.severity === 'HIGH' ? 'bg-amber-950 text-amber-300 border border-amber-700' :
                  cvssResult.severity === 'MEDIUM' ? 'bg-yellow-950 text-yellow-300 border border-yellow-700' :
                  'bg-blue-950 text-blue-300 border border-blue-700'
                }`}>
                  <span className="text-2xl block leading-none">{cvssResult.baseScore}</span>
                  <span className="text-[10px] uppercase font-mono">{cvssResult.severity}</span>
                </div>
                <div>
                  <span className="text-[11px] text-slate-400 block font-mono">Official Vector String</span>
                  <span className="text-xs font-mono text-cyan-300">{cvssResult.vectorString}</span>
                  <span className="text-[11px] text-slate-400 block font-mono mt-0.5">
                    Exploitability: {cvssResult.exploitabilityScore} • Impact: {cvssResult.impactScore}
                  </span>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={copyCvssVector}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-card border border-border text-xs text-slate-300 hover:text-white"
                >
                  {copiedVector ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedVector ? 'Copied' : 'Copy Vector'}</span>
                </button>
              </div>
            </div>
          )}

          {/* Metric Selector Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            {/* Attack Vector */}
            <div className="p-3.5 rounded-xl bg-card border border-border space-y-2">
              <span className="font-semibold text-white block">Attack Vector (AV)</span>
              <div className="grid grid-cols-4 gap-1.5 font-mono">
                {[
                  { label: 'Network (N)', val: 'N' },
                  { label: 'Adjacent (A)', val: 'A' },
                  { label: 'Local (L)', val: 'L' },
                  { label: 'Physical (P)', val: 'P' },
                ].map((opt) => (
                  <button
                    key={opt.val}
                    onClick={() => handleCvssChange('attackVector', opt.val)}
                    className={`py-1.5 px-1 rounded text-center text-[10px] transition-colors ${
                      cvssRequest.attackVector === opt.val
                        ? 'bg-primary text-white font-bold'
                        : 'bg-surface text-slate-400 hover:bg-surface/80'
                    }`}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Attack Complexity */}
            <div className="p-3.5 rounded-xl bg-card border border-border space-y-2">
              <span className="font-semibold text-white block">Attack Complexity (AC)</span>
              <div className="grid grid-cols-2 gap-1.5 font-mono">
                {[
                  { label: 'Low (L)', val: 'L' },
                  { label: 'High (H)', val: 'H' },
                ].map((opt) => (
                  <button
                    key={opt.val}
                    onClick={() => handleCvssChange('attackComplexity', opt.val)}
                    className={`py-1.5 px-1 rounded text-center text-[10px] transition-colors ${
                      cvssRequest.attackComplexity === opt.val
                        ? 'bg-primary text-white font-bold'
                        : 'bg-surface text-slate-400 hover:bg-surface/80'
                    }`}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Privileges Required */}
            <div className="p-3.5 rounded-xl bg-card border border-border space-y-2">
              <span className="font-semibold text-white block">Privileges Required (PR)</span>
              <div className="grid grid-cols-3 gap-1.5 font-mono">
                {[
                  { label: 'None (N)', val: 'N' },
                  { label: 'Low (L)', val: 'L' },
                  { label: 'High (H)', val: 'H' },
                ].map((opt) => (
                  <button
                    key={opt.val}
                    onClick={() => handleCvssChange('privilegesRequired', opt.val)}
                    className={`py-1.5 px-1 rounded text-center text-[10px] transition-colors ${
                      cvssRequest.privilegesRequired === opt.val
                        ? 'bg-primary text-white font-bold'
                        : 'bg-surface text-slate-400 hover:bg-surface/80'
                    }`}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
            </div>

            {/* User Interaction */}
            <div className="p-3.5 rounded-xl bg-card border border-border space-y-2">
              <span className="font-semibold text-white block">User Interaction (UI)</span>
              <div className="grid grid-cols-2 gap-1.5 font-mono">
                {[
                  { label: 'None (N)', val: 'N' },
                  { label: 'Required (R)', val: 'R' },
                ].map((opt) => (
                  <button
                    key={opt.val}
                    onClick={() => handleCvssChange('userInteraction', opt.val)}
                    className={`py-1.5 px-1 rounded text-center text-[10px] transition-colors ${
                      cvssRequest.userInteraction === opt.val
                        ? 'bg-primary text-white font-bold'
                        : 'bg-surface text-slate-400 hover:bg-surface/80'
                    }`}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Scope */}
            <div className="p-3.5 rounded-xl bg-card border border-border space-y-2">
              <span className="font-semibold text-white block">Scope (S)</span>
              <div className="grid grid-cols-2 gap-1.5 font-mono">
                {[
                  { label: 'Unchanged (U)', val: 'U' },
                  { label: 'Changed (C)', val: 'C' },
                ].map((opt) => (
                  <button
                    key={opt.val}
                    onClick={() => handleCvssChange('scope', opt.val)}
                    className={`py-1.5 px-1 rounded text-center text-[10px] transition-colors ${
                      cvssRequest.scope === opt.val
                        ? 'bg-primary text-white font-bold'
                        : 'bg-surface text-slate-400 hover:bg-surface/80'
                    }`}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Confidentiality */}
            <div className="p-3.5 rounded-xl bg-card border border-border space-y-2">
              <span className="font-semibold text-white block">Confidentiality Impact (C)</span>
              <div className="grid grid-cols-3 gap-1.5 font-mono">
                {[
                  { label: 'None (N)', val: 'N' },
                  { label: 'Low (L)', val: 'L' },
                  { label: 'High (H)', val: 'H' },
                ].map((opt) => (
                  <button
                    key={opt.val}
                    onClick={() => handleCvssChange('confidentiality', opt.val)}
                    className={`py-1.5 px-1 rounded text-center text-[10px] transition-colors ${
                      cvssRequest.confidentiality === opt.val
                        ? 'bg-primary text-white font-bold'
                        : 'bg-surface text-slate-400 hover:bg-surface/80'
                    }`}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Integrity */}
            <div className="p-3.5 rounded-xl bg-card border border-border space-y-2">
              <span className="font-semibold text-white block">Integrity Impact (I)</span>
              <div className="grid grid-cols-3 gap-1.5 font-mono">
                {[
                  { label: 'None (N)', val: 'N' },
                  { label: 'Low (L)', val: 'L' },
                  { label: 'High (H)', val: 'H' },
                ].map((opt) => (
                  <button
                    key={opt.val}
                    onClick={() => handleCvssChange('integrity', opt.val)}
                    className={`py-1.5 px-1 rounded text-center text-[10px] transition-colors ${
                      cvssRequest.integrity === opt.val
                        ? 'bg-primary text-white font-bold'
                        : 'bg-surface text-slate-400 hover:bg-surface/80'
                    }`}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Availability */}
            <div className="p-3.5 rounded-xl bg-card border border-border space-y-2">
              <span className="font-semibold text-white block">Availability Impact (A)</span>
              <div className="grid grid-cols-3 gap-1.5 font-mono">
                {[
                  { label: 'None (N)', val: 'N' },
                  { label: 'Low (L)', val: 'L' },
                  { label: 'High (H)', val: 'H' },
                ].map((opt) => (
                  <button
                    key={opt.val}
                    onClick={() => handleCvssChange('availability', opt.val)}
                    className={`py-1.5 px-1 rounded text-center text-[10px] transition-colors ${
                      cvssRequest.availability === opt.val
                        ? 'bg-primary text-white font-bold'
                        : 'bg-surface text-slate-400 hover:bg-surface/80'
                    }`}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
