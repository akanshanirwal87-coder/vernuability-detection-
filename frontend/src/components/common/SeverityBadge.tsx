import React from 'react';
import { Severity } from '../../types/scan';
import { ShieldAlert, AlertTriangle, AlertCircle, ShieldCheck, Info } from 'lucide-react';

interface SeverityBadgeProps {
  severity: Severity;
  size?: 'sm' | 'md' | 'lg';
  showIcon?: boolean;
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({
  severity,
  size = 'md',
  showIcon = true
}) => {
  const getStyles = () => {
    switch (severity) {
      case 'CRITICAL':
        return {
          bg: 'bg-red-950/40 text-red-400 border-red-800/60',
          icon: <ShieldAlert className={size === 'sm' ? 'w-3 h-3' : 'w-4 h-4'} />,
          label: 'CRITICAL'
        };
      case 'HIGH':
        return {
          bg: 'bg-orange-950/40 text-orange-400 border-orange-800/60',
          icon: <AlertTriangle className={size === 'sm' ? 'w-3 h-3' : 'w-4 h-4'} />,
          label: 'HIGH'
        };
      case 'MEDIUM':
        return {
          bg: 'bg-amber-950/40 text-amber-400 border-amber-800/60',
          icon: <AlertCircle className={size === 'sm' ? 'w-3 h-3' : 'w-4 h-4'} />,
          label: 'MEDIUM'
        };
      case 'LOW':
        return {
          bg: 'bg-emerald-950/40 text-emerald-400 border-emerald-800/60',
          icon: <ShieldCheck className={size === 'sm' ? 'w-3 h-3' : 'w-4 h-4'} />,
          label: 'LOW'
        };
      default:
        return {
          bg: 'bg-blue-950/40 text-blue-400 border-blue-800/60',
          icon: <Info className={size === 'sm' ? 'w-3 h-3' : 'w-4 h-4'} />,
          label: 'INFO'
        };
    }
  };

  const config = getStyles();
  const sizeClasses = size === 'sm' 
    ? 'text-[10px] px-1.5 py-0.5 gap-1 font-semibold' 
    : size === 'lg' 
      ? 'text-xs px-3 py-1.5 gap-2 font-bold tracking-wide' 
      : 'text-xs px-2 py-0.5 gap-1.5 font-medium';

  return (
    <span className={`inline-flex items-center rounded-md border ${config.bg} ${sizeClasses}`}>
      {showIcon && config.icon}
      <span>{config.label}</span>
    </span>
  );
};

