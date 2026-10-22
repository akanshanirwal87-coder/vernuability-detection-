import React from 'react';
import { Database, Info } from 'lucide-react';

interface DemoDataBannerProps {
  message?: string;
}

export const DemoDataBanner: React.FC<DemoDataBannerProps> = ({
  message = "DEMO DATA: Showing deterministic sample scan records for demonstration purposes."
}) => {
  return (
    <div className="bg-amber-950/30 border border-amber-800/60 rounded-lg p-3 text-amber-200 text-xs flex items-center justify-between gap-3 shadow-sm mb-4">
      <div className="flex items-center gap-2.5">
        <span className="bg-amber-500/20 text-amber-400 font-bold px-1.5 py-0.5 rounded border border-amber-600/50 text-[10px] tracking-wider uppercase">
          DEMO DATA
        </span>
        <span className="text-amber-200/90">{message}</span>
      </div>
      <div className="hidden sm:flex items-center gap-1.5 text-amber-400/80 font-mono text-[11px]">
        <Database className="w-3.5 h-3.5" />
        <span>Pre-loaded Fixtures</span>
      </div>
    </div>
  );
};

