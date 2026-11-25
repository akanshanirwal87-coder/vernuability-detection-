import React from 'react';
import { Loader2 } from 'lucide-react';

interface LoaderProps {
  label?: string;
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

export const Loader: React.FC<LoaderProps> = ({
  label = 'Loading...',
  size = 'md',
  className = '',
}) => {
  const sizeMap = {
    sm: 'h-4 w-4',
    md: 'h-6 w-6',
    lg: 'h-10 w-10',
  };

  return (
    <div className={`flex flex-col items-center justify-center gap-3 p-6 text-slate-400 ${className}`}>
      <Loader2 className={`${sizeMap[size]} animate-spin text-indigo-400`} />
      {label && <span className="text-xs font-medium text-slate-400">{label}</span>}
    </div>
  );
};

export const CardSkeleton: React.FC<{ rows?: number }> = ({ rows = 3 }) => {
  return (
    <div className="animate-pulse rounded-xl border border-slate-800 bg-[#111827]/60 p-5 space-y-4">
      <div className="h-5 w-1/3 rounded bg-slate-800" />
      <div className="space-y-2">
        {Array.from({ length: rows }).map((_, i) => (
          <div
            key={i}
            className="h-3.5 rounded bg-slate-800/60"
            style={{ width: `${85 - i * 15}%` }}
          />
        ))}
      </div>
    </div>
  );
};

export const TableSkeleton: React.FC<{ rows?: number; cols?: number }> = ({ rows = 5, cols = 4 }) => {
  return (
    <div className="animate-pulse rounded-xl border border-slate-800 bg-[#111827]/60 p-4">
      <div className="flex gap-4 border-b border-slate-800 pb-3">
        {Array.from({ length: cols }).map((_, j) => (
          <div key={j} className="h-4 flex-1 rounded bg-slate-800" />
        ))}
      </div>
      <div className="divide-y divide-slate-800/50">
        {Array.from({ length: rows }).map((_, i) => (
          <div key={i} className="flex gap-4 py-3.5">
            {Array.from({ length: cols }).map((_, j) => (
              <div key={j} className="h-3.5 flex-1 rounded bg-slate-800/40" />
            ))}
          </div>
        ))}
      </div>
    </div>
  );
};

export default Loader;
