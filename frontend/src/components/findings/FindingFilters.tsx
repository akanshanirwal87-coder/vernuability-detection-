import React from 'react';
import type { Severity } from '../../types/scan';
import { Search, Filter } from 'lucide-react';

interface FindingFiltersProps {
  selectedSeverity: string;
  onSelectSeverity: (sev: string) => void;
  searchQuery: string;
  onSearchChange: (query: string) => void;
  selectedSource?: string;
  onSelectSource?: (src: string) => void;
}

export const FindingFilters: React.FC<FindingFiltersProps> = ({
  selectedSeverity,
  onSelectSeverity,
  searchQuery,
  onSearchChange,
  selectedSource = 'ALL',
  onSelectSource,
}) => {
  const severities: Array<Severity | 'ALL'> = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

  return (
    <div className="flex flex-col sm:flex-row gap-3 items-stretch sm:items-center justify-between rounded-xl border border-slate-800 bg-[#111827] p-3">
      {/* Search Bar */}
      <div className="relative flex-1">
        <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-500" />
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => onSearchChange(e.target.value)}
          placeholder="Filter by vulnerability name, CWE-89, file, or keyword..."
          className="w-full rounded-lg border border-slate-700 bg-slate-900/80 py-1.5 pl-9 pr-3 text-xs text-white placeholder-slate-500 transition focus:border-indigo-500 focus:outline-none"
        />
      </div>

      {/* Severity Filter Chips */}
      <div className="flex items-center gap-1.5 overflow-x-auto pb-1 sm:pb-0">
        <span className="text-[11px] font-semibold text-slate-400 mr-1 hidden md:inline">
          Severity:
        </span>
        {severities.map((sev) => {
          const isActive = selectedSeverity === sev;
          return (
            <button
              key={sev}
              onClick={() => onSelectSeverity(sev)}
              className={`rounded-lg px-2.5 py-1 text-xs font-semibold transition ${
                isActive
                  ? 'bg-indigo-600 text-white shadow-sm'
                  : 'bg-slate-800/80 text-slate-400 hover:bg-slate-800 hover:text-white'
              }`}
            >
              {sev}
            </button>
          );
        })}
      </div>
    </div>
  );
};

export default FindingFilters;
