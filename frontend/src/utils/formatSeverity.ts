import type { Severity } from '../types/scan';

export interface SeverityStyle {
  label: Severity;
  badgeBg: string;
  badgeText: string;
  badgeBorder: string;
  dotColor: string;
  ringColor: string;
  priority: number;
}

export const SEVERITY_CONFIG: Record<Severity, SeverityStyle> = {
  CRITICAL: {
    label: 'CRITICAL',
    badgeBg: 'bg-red-500/10',
    badgeText: 'text-red-400',
    badgeBorder: 'border-red-500/30',
    dotColor: 'bg-red-500',
    ringColor: 'ring-red-500/20',
    priority: 1,
  },
  HIGH: {
    label: 'HIGH',
    badgeBg: 'bg-amber-500/10',
    badgeText: 'text-amber-400',
    badgeBorder: 'border-amber-500/30',
    dotColor: 'bg-amber-500',
    ringColor: 'ring-amber-500/20',
    priority: 2,
  },
  MEDIUM: {
    label: 'MEDIUM',
    badgeBg: 'bg-yellow-500/10',
    badgeText: 'text-yellow-400',
    badgeBorder: 'border-yellow-500/30',
    dotColor: 'bg-yellow-500',
    ringColor: 'ring-yellow-500/20',
    priority: 3,
  },
  LOW: {
    label: 'LOW',
    badgeBg: 'bg-blue-500/10',
    badgeText: 'text-blue-400',
    badgeBorder: 'border-blue-500/30',
    dotColor: 'bg-blue-500',
    ringColor: 'ring-blue-500/20',
    priority: 4,
  },
  INFO: {
    label: 'INFO',
    badgeBg: 'bg-slate-500/10',
    badgeText: 'text-slate-400',
    badgeBorder: 'border-slate-500/30',
    dotColor: 'bg-slate-500',
    ringColor: 'ring-slate-500/20',
    priority: 5,
  },
};

export function getSeverityStyle(severity?: string): SeverityStyle {
  if (!severity) return SEVERITY_CONFIG.INFO;
  const upper = severity.toUpperCase() as Severity;
  return SEVERITY_CONFIG[upper] || SEVERITY_CONFIG.INFO;
}

export function compareSeverity(a: Severity, b: Severity): number {
  return (SEVERITY_CONFIG[a]?.priority ?? 99) - (SEVERITY_CONFIG[b]?.priority ?? 99);
}
