import React from 'react';

interface SkeletonProps {
  className?: string;
  rounded?: 'sm' | 'md' | 'lg' | 'xl' | 'full';
}

export const Skeleton: React.FC<SkeletonProps> = ({ 
  className = '', 
  rounded = 'md' 
}) => {
  const roundedClass = {
    sm: 'rounded-sm',
    md: 'rounded-md',
    lg: 'rounded-lg',
    xl: 'rounded-xl',
    full: 'rounded-full',
  }[rounded];

  return (
    <div 
      className={`skeleton-shimmer border border-border/40 ${roundedClass} ${className}`}
      aria-hidden="true"
    />
  );
};

export const DashboardCardSkeleton: React.FC = () => (
  <div className="p-4 rounded-xl bg-card border border-border flex items-center justify-between">
    <div className="space-y-2 flex-1 mr-4">
      <Skeleton className="h-3 w-24" />
      <Skeleton className="h-7 w-16" />
      <Skeleton className="h-2.5 w-28" />
    </div>
    <Skeleton className="w-11 h-11" rounded="lg" />
  </div>
);

export const ChartSkeleton: React.FC<{ height?: string }> = ({ height = 'h-56' }) => (
  <div className={`p-5 rounded-xl bg-card border border-border space-y-4`}>
    <div className="flex items-center justify-between">
      <Skeleton className="h-3.5 w-36" />
      <Skeleton className="h-3 w-20" />
    </div>
    <div className={`${height} flex items-center justify-center p-4`}>
      <Skeleton className="w-full h-full" rounded="lg" />
    </div>
  </div>
);

export const TableSkeleton: React.FC<{ rows?: number }> = ({ rows = 5 }) => (
  <div className="space-y-2">
    {Array.from({ length: rows }).map((_, i) => (
      <div 
        key={i} 
        className="flex items-center justify-between p-3.5 border-b border-border/40 gap-4"
      >
        <Skeleton className="h-3.5 w-24" />
        <Skeleton className="h-3.5 w-40 flex-1 max-w-xs" />
        <Skeleton className="h-3.5 w-16" />
        <Skeleton className="h-3.5 w-20" />
        <Skeleton className="h-5 w-16" rounded="sm" />
        <Skeleton className="h-3.5 w-12" />
      </div>
    ))}
  </div>
);

export const FindingsListSkeleton: React.FC<{ count?: number }> = ({ count = 3 }) => (
  <div className="space-y-3">
    {Array.from({ length: count }).map((_, i) => (
      <div key={i} className="p-4 rounded-xl bg-card border border-border space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Skeleton className="h-5 w-20" rounded="md" />
            <Skeleton className="h-4 w-48" />
          </div>
          <Skeleton className="h-4 w-16" />
        </div>
        <Skeleton className="h-3 w-full" />
        <Skeleton className="h-14 w-full" rounded="lg" />
      </div>
    ))}
  </div>
);

