import React from 'react';
import { Link } from 'react-router-dom';
import type { ScanHistoryItem } from '../../types/scan';
import { getSeverityStyle } from '../../utils/formatSeverity';
import { formatRelativeTime } from '../../utils/formatDate';
import { Terminal, Eye, FileCode2, Trash2 } from 'lucide-react';

interface RecentScansProps {
  scans: ScanHistoryItem[];
  onDelete?: (scanId: string) => void;
}

export const RecentScans: React.FC<RecentScansProps> = ({ scans, onDelete }) => {
  return (
    <div className="rounded-xl border border-slate-800 bg-[#111827] overflow-hidden">
      <div className="flex items-center justify-between p-5 border-b border-slate-800">
        <div>
          <h4 className="text-sm font-semibold text-white">Recent Security Audits</h4>
          <p className="text-xs text-slate-400 mt-0.5">Latest code scans and vulnerability evaluations</p>
        </div>
        <Link
          to="/history"
          className="text-xs font-semibold text-indigo-400 hover:text-indigo-300 hover:underline"
        >
          View Full History →
        </Link>
      </div>

      {scans.length === 0 ? (
        <div className="p-8 text-center text-slate-400">
          <Terminal className="mx-auto h-8 w-8 text-slate-600 mb-2" />
          <p className="text-sm font-medium text-slate-300">No scans found</p>
          <p className="text-xs text-slate-500 mt-1">Run a new scan to populate audit history</p>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-900/50 text-[11px] uppercase tracking-wider text-slate-400 border-b border-slate-800">
              <tr>
                <th className="px-5 py-3">Project / Target File</th>
                <th className="px-5 py-3">Language</th>
                <th className="px-5 py-3">Findings</th>
                <th className="px-5 py-3">Highest Severity</th>
                <th className="px-5 py-3">Executed</th>
                <th className="px-5 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {scans.slice(0, 5).map((scan) => {
                const style = getSeverityStyle(scan.highestSeverity);
                return (
                  <tr key={scan.id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="px-5 py-3.5">
                      <div className="font-medium text-white">{scan.projectName}</div>
                      <div className="text-[11px] font-mono text-slate-400">{scan.fileName}</div>
                    </td>
                    <td className="px-5 py-3.5">
                      <span className="rounded bg-slate-800 px-2 py-0.5 font-mono text-[11px] text-cyan-400 border border-slate-700">
                        {scan.language.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-5 py-3.5">
                      <span className="font-semibold text-white">{scan.totalFindings}</span>{' '}
                      <span className="text-slate-500">issues</span>
                    </td>
                    <td className="px-5 py-3.5">
                      <span
                        className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-[10px] font-bold border ${style.badgeBg} ${style.badgeText} ${style.badgeBorder}`}
                      >
                        <span className={`h-1.5 w-1.5 rounded-full ${style.dotColor}`} />
                        {scan.highestSeverity}
                      </span>
                    </td>
                    <td className="px-5 py-3.5 text-slate-400">
                      {formatRelativeTime(scan.createdAt)}
                    </td>
                    <td className="px-5 py-3.5 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <Link
                          to={`/results/${scan.id}`}
                          className="rounded p-1 text-slate-400 hover:bg-slate-800 hover:text-white transition-colors"
                          title="View Scan Findings"
                        >
                          <Eye className="h-4 w-4" />
                        </Link>
                        <Link
                          to={`/remediation/${scan.id}`}
                          className="rounded p-1 text-slate-400 hover:bg-indigo-500/10 hover:text-indigo-400 transition-colors"
                          title="Remediation Workspace"
                        >
                          <FileCode2 className="h-4 w-4" />
                        </Link>
                        {onDelete && (
                          <button
                            onClick={() => onDelete(scan.id)}
                            className="rounded p-1 text-slate-400 hover:bg-red-500/10 hover:text-red-400 transition-colors"
                            title="Delete Scan"
                          >
                            <Trash2 className="h-4 w-4" />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

export default RecentScans;
