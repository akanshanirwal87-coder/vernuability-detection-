import React from 'react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts';

interface SeverityCount {
  name: string;
  count: number;
  fill: string;
}

interface SeverityChartProps {
  data: SeverityCount[];
}

export const SeverityChart: React.FC<SeverityChartProps> = ({ data }) => {
  const total = data.reduce((acc, curr) => acc + curr.count, 0);

  return (
    <div className="rounded-xl border border-slate-800 bg-[#111827] p-5">
      <div className="flex items-center justify-between mb-4 border-b border-slate-800 pb-3">
        <div>
          <h4 className="text-sm font-semibold text-white">Vulnerability Severity Distribution</h4>
          <p className="text-xs text-slate-400 mt-0.5">Categorized by CVSS / CWE Impact</p>
        </div>
        <span className="rounded-full bg-slate-800 px-2.5 py-1 font-mono text-[11px] text-slate-300">
          {total} Total Issues
        </span>
      </div>

      {total === 0 ? (
        <div className="flex h-52 flex-col items-center justify-center text-center text-slate-400">
          <p className="text-xs">No vulnerabilities detected</p>
          <span className="text-[11px] text-slate-500 mt-1">Codebase meets baseline security criteria</span>
        </div>
      ) : (
        <div className="h-56 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <XAxis
                dataKey="name"
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
              <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                {data.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.fill} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
};

export default SeverityChart;
