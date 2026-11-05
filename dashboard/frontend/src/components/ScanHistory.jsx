import React from 'react';
import { History, CheckCircle2, ShieldAlert, AlertOctagon, ArrowRight } from 'lucide-react';

export default function ScanHistory({ scans, onSelectScan }) {
  const getBadge = (decision) => {
    const d = (decision || '').toUpperCase();
    if (d === 'PASS') {
      return (
        <span className="px-2 py-0.5 rounded text-xs font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
          PASS
        </span>
      );
    }
    if (d === 'BLOCK') {
      return (
        <span className="px-2 py-0.5 rounded text-xs font-bold bg-rose-500/15 text-rose-400 border border-rose-500/30">
          BLOCK
        </span>
      );
    }
    return (
      <span className="px-2 py-0.5 rounded text-xs font-bold bg-amber-500/15 text-amber-400 border border-amber-500/30">
        INCOMPLETE
      </span>
    );
  };

  return (
    <div className="bg-[#0f172a] border border-slate-800 rounded-xl overflow-hidden">
      <div className="p-4 border-b border-slate-800 bg-slate-900/50 flex items-center justify-between">
        <div>
          <h3 className="text-sm font-bold text-white uppercase tracking-wider">CI/CD Security Scan History</h3>
          <p className="text-xs text-slate-400">Audit trail of all pipeline security evaluations</p>
        </div>
        <span className="text-xs font-mono font-bold bg-slate-800 text-slate-300 px-2.5 py-1 rounded-full border border-slate-700">
          {scans.length} Scans Recorded
        </span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead className="bg-[#0a0f1d] text-slate-400 uppercase font-semibold border-b border-slate-800 tracking-wider">
            <tr>
              <th className="py-3 px-4">Scan ID</th>
              <th className="py-3 px-4">Report Identifier</th>
              <th className="py-3 px-4">Execution Timestamp</th>
              <th className="py-3 px-4">Gate Decision</th>
              <th className="py-3 px-4">Security Score</th>
              <th className="py-3 px-4">Regression / Trend</th>
              <th className="py-3 px-4">Severity Breakdown (C / H / M / L)</th>
              <th className="py-3 px-4 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/80">
            {scans.length === 0 ? (
              <tr>
                <td colSpan={8} className="py-12 text-center text-slate-500 italic">
                  No pipeline security scans have been recorded in the database yet.
                </td>
              </tr>
            ) : (
              scans.map((s, idx) => {
                const prev = scans[idx + 1];
                let delta = null;
                let trend = null;
                if (prev && s.security_score !== null && prev.security_score !== null) {
                  delta = s.security_score - prev.security_score;
                  trend = delta > 0 ? 'IMPROVED' : delta < 0 ? 'REGRESSED' : 'STABLE';
                }

                return (
                  <tr key={s.id} className="hover:bg-slate-800/40 transition">
                    <td className="py-3 px-4 font-mono font-bold text-slate-300">
                      #{s.id}
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-400">
                      {s.report_id}
                    </td>
                    <td className="py-3 px-4 text-slate-300">
                      {new Date(s.scan_timestamp).toLocaleString()}
                    </td>
                    <td className="py-3 px-4">
                      {getBadge(s.gate_decision)}
                    </td>
                    <td className="py-3 px-4 font-mono font-bold">
                      {s.security_score !== null ? (
                        <span className={s.security_score >= 80 ? 'text-emerald-400' : s.security_score >= 50 ? 'text-amber-400' : 'text-rose-400'}>
                          {s.security_score} / 100
                        </span>
                      ) : (
                        <span className="text-slate-500">N/A</span>
                      )}
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap">
                      {trend === 'IMPROVED' ? (
                        <span className="inline-flex items-center gap-1 text-[11px] font-mono font-bold text-emerald-400 bg-emerald-950/50 border border-emerald-800/60 px-2 py-0.5 rounded">
                          ▲ +{delta} (Improved)
                        </span>
                      ) : trend === 'REGRESSED' ? (
                        <span className="inline-flex items-center gap-1 text-[11px] font-mono font-bold text-rose-400 bg-rose-950/50 border border-rose-800/60 px-2 py-0.5 rounded">
                          ▼ {delta} (Regressed)
                        </span>
                      ) : trend === 'STABLE' ? (
                        <span className="text-[11px] font-mono text-slate-400">
                          — No change
                        </span>
                      ) : (
                        <span className="text-[11px] font-mono text-slate-500">
                          Baseline
                        </span>
                      )}
                    </td>
                  <td className="py-3 px-4 font-mono text-xs">
                    <span className="text-rose-400 font-bold">{s.critical_count}</span>
                    <span className="text-slate-600 mx-1">/</span>
                    <span className="text-orange-400 font-bold">{s.high_count}</span>
                    <span className="text-slate-600 mx-1">/</span>
                    <span className="text-amber-400">{s.medium_count}</span>
                    <span className="text-slate-600 mx-1">/</span>
                    <span className="text-emerald-400">{s.low_count}</span>
                  </td>
                  <td className="py-3 px-4 text-right">
                    <button
                      onClick={() => onSelectScan(s.id)}
                      className="inline-flex items-center gap-1 bg-slate-800 hover:bg-slate-700 text-sky-400 border border-slate-700 px-2.5 py-1 rounded text-xs font-medium transition"
                    >
                      Filter Findings
                      <ArrowRight className="w-3 h-3" />
                    </button>
                  </td>
                </tr>
              );
            })
          )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
