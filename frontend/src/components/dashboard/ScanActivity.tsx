import React from 'react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';

interface ActivityPoint {
  date: string;
  scans: number;
}

interface ScanActivityProps {
  data: ActivityPoint[];
}

export const ScanActivity: React.FC<ScanActivityProps> = ({ data }) => {
  return (
    <div className="rounded-xl border border-slate-800 bg-[#111827] p-5">
      <div className="flex items-center justify-between mb-4 border-b border-slate-800 pb-3">
        <div>
          <h4 className="text-sm font-semibold text-white">Scan Activity & Velocity</h4>
          <p className="text-xs text-slate-400 mt-0.5">Execution volume across recent days</p>
        </div>
      </div>

      {data.length === 0 ? (
        <div className="flex h-52 flex-col items-center justify-center text-center text-slate-400">
          <p className="text-xs">No scan activity recorded yet</p>
          <span className="text-[11px] text-slate-500 mt-1">Initiate a scan to track activity trends</span>
        </div>
      ) : (
        <div className="h-56 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="scanGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#6366F1" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#6366F1" stopOpacity={0.0} />
                </linearGradient>
              </defs>
              <XAxis
                dataKey="date"
                stroke="#64748b"
                fontSize={11}
                tickLine={false}
                axisLine={false}
              />
              <YAxis
                stroke="#64748b"
                fontSize={11}
                tickLine={false}
                axisLine={false}
                allowDecimals={false}
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#0F172A',
                  borderColor: '#334155',
                  borderRadius: '0.5rem',
                  fontSize: '12px',
                  color: '#F8FAFC',
                }}
              />
              <Area
                type="monotone"
                dataKey="scans"
                stroke="#6366F1"
                strokeWidth={2}
                fillOpacity={1}
                fill="url(#scanGradient)"
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
};

export default ScanActivity;
