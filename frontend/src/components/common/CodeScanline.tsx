import React from 'react';
import { usePrefersReducedMotion } from '../../hooks/usePrefersReducedMotion';

interface CodeScanlineProps {
  label?: string;
}

export const CodeScanline: React.FC<CodeScanlineProps> = ({ 
  label = 'ANALYZING AST & SECURITY SINKS...' 
}) => {
  const prefersReduced = usePrefersReducedMotion();

  return (
    <div 
      className="code-scanline-container"
      aria-label="Code security scanning active"
      role="status"
    >
      {/* Top Cyber Status Pill */}
      <div className="absolute top-3 right-4 z-40 flex items-center gap-2 px-3 py-1 rounded-full bg-slate-900/90 border border-cyan-500/40 backdrop-blur-md shadow-lg shadow-cyan-950/50">
        <span className="relative flex h-2 w-2">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75" />
          <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-500" />
        </span>
        <span className="text-[10px] font-mono font-semibold tracking-wider text-cyan-300">
          {label}
        </span>
      </div>

      {/* Background Soft Scan Glow */}
      <div className="absolute inset-0 bg-cyan-500/[0.02] pointer-events-none" />

      {/* Moving Laser Beam and Scanline (disabled if user prefers reduced motion) */}
      {!prefersReduced && (
        <div className="absolute inset-x-0 h-full animate-scan-sweep pointer-events-none">
          <div className="code-scanline-beam -top-14" />
          <div className="code-scanline top-0" />
        </div>
      )}
    </div>
  );
};

