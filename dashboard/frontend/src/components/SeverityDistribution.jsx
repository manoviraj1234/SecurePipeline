import React from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';

export default function SeverityDistribution({ distribution }) {
  const data = [
    { name: 'Critical', count: distribution?.critical || 0, color: '#ef4444' },
    { name: 'High', count: distribution?.high || 0, color: '#f97316' },
    { name: 'Medium', count: distribution?.medium || 0, color: '#eab308' },
    { name: 'Low', count: distribution?.low || 0, color: '#10b981' },
    { name: 'Info', count: distribution?.info || 0, color: '#3b82f6' },
  ];

  const total = data.reduce((acc, curr) => acc + curr.count, 0);

  return (
    <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-sm font-bold text-white uppercase tracking-wider">Severity Distribution</h3>
          <p className="text-xs text-slate-400">Categorization of active vulnerabilities</p>
        </div>
        <span className="text-xs font-mono font-bold bg-slate-800 text-slate-300 px-2.5 py-1 rounded-full border border-slate-700">
          {total} Active
        </span>
      </div>

      <div className="h-48 w-full">
        {total === 0 ? (
          <div className="h-full flex items-center justify-center text-xs text-slate-500 font-medium italic">
            Zero vulnerabilities recorded in active scans.
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <XAxis dataKey="name" stroke="#64748b" fontSize={11} tickLine={false} />
              <YAxis stroke="#64748b" fontSize={11} tickLine={false} allowDecimals={false} />
              <Tooltip
                contentStyle={{ backgroundColor: '#1e293b', borderColor: '#334155', borderRadius: '8px', color: '#fff', fontSize: '12px' }}
                cursor={{ fill: 'rgba(255, 255, 255, 0.04)' }}
              />
              <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                {data.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>

      <div className="grid grid-cols-5 gap-2 mt-4 pt-3 border-t border-slate-800/80 text-center">
        {data.map((item) => (
          <div key={item.name} className="flex flex-col items-center">
            <span className="text-[10px] uppercase font-semibold text-slate-400">{item.name}</span>
            <span className="text-sm font-bold font-mono" style={{ color: item.color }}>
              {item.count}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
