import React from 'react';
import type { ScanResult } from '../../types/scan';
import { generatePdfReport, exportCsvReport, exportJsonReport } from '../../services/reportService';
import { Download, FileText, FileSpreadsheet, FileJson } from 'lucide-react';
import { toast } from 'sonner';

interface ReportExportProps {
  scan: ScanResult;
}

export const ReportExport: React.FC<ReportExportProps> = ({ scan }) => {
  const handlePdf = () => {
    try {
      generatePdfReport(scan);
      toast.success('Generated PDF report');
    } catch {
      toast.error('Failed to generate PDF');
    }
  };

  const handleCsv = () => {
    try {
      exportCsvReport(scan);
      toast.success('Exported findings to CSV');
    } catch {
      toast.error('Failed to export CSV');
    }
  };

  const handleJson = () => {
    try {
      exportJsonReport(scan);
      toast.success('Exported full audit to JSON');
    } catch {
      toast.error('Failed to export JSON');
    }
  };

  return (
    <div className="flex flex-wrap items-center gap-2">
      <button
        onClick={handlePdf}
        className="flex items-center gap-1.5 rounded-lg bg-indigo-600 px-3 py-1.5 text-xs font-semibold text-white shadow-md shadow-indigo-600/20 hover:bg-indigo-500 transition active:scale-95"
      >
        <FileText className="h-3.5 w-3.5" />
        <span>Export PDF</span>
      </button>
      <button
        onClick={handleCsv}
        className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-semibold text-slate-200 hover:bg-slate-700 hover:text-white transition active:scale-95"
      >
        <FileSpreadsheet className="h-3.5 w-3.5 text-emerald-400" />
        <span>Export CSV</span>
      </button>
      <button
        onClick={handleJson}
        className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-semibold text-slate-200 hover:bg-slate-700 hover:text-white transition active:scale-95"
      >
        <FileJson className="h-3.5 w-3.5 text-cyan-400" />
        <span>Export JSON</span>
      </button>
    </div>
  );
};

export default ReportExport;
