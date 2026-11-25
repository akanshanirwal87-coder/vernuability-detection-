import React from 'react';
import { Terminal, ShieldAlert, AlertTriangle, CheckCircle2, FolderGit2 } from 'lucide-react';

interface SecurityOverviewProps {
  totalScans: number;
  totalVulnerabilities: number;
  criticalFindings: number;
  highFindings: number;
  totalProjects?: number;
  remediationRate?: number;
}

export const SecurityOverview: React.FC<SecurityOverviewProps> = ({
  totalScans,
  totalVulnerabilities,
  criticalFindings,
  highFindings,
  totalProjects = 0,
  remediationRate = 0,
}) => {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      {/* Total Scans */}
      <div className="p-4 rounded-xl bg-[#111827] border border-slate-800 flex items-center justify-between transition-all hover:border-slate-700 shadow-sm">
        <div>
          <p className="text-xs font-medium text-slate-400">Total Scans Executed</p>
          <h3 className="text-2xl font-bold text-white mt-1">{totalScans}</h3>
          <span className="text-[11px] text-cyan-400 font-mono">AST & Static Analysis</span>
        </div>
        <div className="p-3 rounded-lg bg-indigo-500/10 border border-indigo-500/20 text-indigo-400">
          <Terminal className="w-5 h-5" />
        </div>
      </div>

      {/* Vulnerabilities Found */}
      <div className="p-4 rounded-xl bg-[#111827] border border-slate-800 flex items-center justify-between transition-all hover:border-slate-700 shadow-sm">
        <div>
          <p className="text-xs font-medium text-slate-400">Active Vulnerabilities</p>
          <h3 className="text-2xl font-bold text-white mt-1">{totalVulnerabilities}</h3>
          <span className="text-[11px] text-amber-400 font-mono">
            {highFindings} High Priority
          </span>
        </div>
        <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-400">
          <ShieldAlert className="w-5 h-5" />
        </div>
      </div>

      {/* Critical Findings */}
      <div
        className={`p-4 rounded-xl bg-[#111827] border transition-all shadow-sm flex items-center justify-between ${
          criticalFindings > 0
            ? 'border-red-500/40 bg-gradient-to-br from-[#111827] to-red-950/20'
            : 'border-slate-800 hover:border-slate-700'
        }`}
      >
        <div>
          <p className="text-xs font-medium text-slate-400">Critical Risk Items</p>
          <h3 className="text-2xl font-bold text-red-400 mt-1 flex items-center gap-1.5">
            {criticalFindings}
            {criticalFindings > 0 && (
              <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
            )}
          </h3>
          <span className="text-[11px] text-red-400 font-mono">
            {criticalFindings > 0 ? 'Requires Immediate Fix' : 'No Critical Issues'}
          </span>
        </div>
        <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400">
          <AlertTriangle className="w-5 h-5" />
        </div>
      </div>

      {/* Projects or Remediation */}
      <div className="p-4 rounded-xl bg-[#111827] border border-slate-800 flex items-center justify-between transition-all hover:border-slate-700 shadow-sm">
        <div>
          <p className="text-xs font-medium text-slate-400">Registered Projects</p>
          <h3 className="text-2xl font-bold text-emerald-400 mt-1">{totalProjects}</h3>
          <span className="text-[11px] text-emerald-400 font-mono">
            {remediationRate > 0 ? `${remediationRate}% Remediated` : 'Active Repositories'}
          </span>
        </div>
        <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
          <FolderGit2 className="w-5 h-5" />
        </div>
      </div>
    </div>
  );
};

export default SecurityOverview;
