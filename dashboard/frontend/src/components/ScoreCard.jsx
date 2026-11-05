import React from 'react';
import { ShieldCheck, ShieldAlert, AlertTriangle, AlertOctagon, CheckCircle2 } from 'lucide-react';

export default function ScoreCard({ summary }) {
  const gateDecision = summary?.latest_gate_decision || 'NO_SCANS';
  const score = summary?.latest_security_score;

  const decisionStyles = {
    PASS: {
      bg: 'bg-emerald-950/60 border-emerald-500/50 text-emerald-300',
      badge: 'bg-emerald-500 text-slate-950',
      icon: ShieldCheck,
      title: 'SECURITY GATE PASSED',
      desc: 'All security scanners executed successfully. Zero critical or high vulnerabilities detected. Deployment is authorized.',
    },
    BLOCK: {
      bg: 'bg-rose-950/60 border-rose-500/50 text-rose-300',
      badge: 'bg-rose-500 text-white',
      icon: ShieldAlert,
      title: 'DEPLOYMENT BLOCKED',
      desc: 'Critical or High-severity vulnerabilities were detected in source code, secrets, dependencies, or container image.',
    },
    INCOMPLETE: {
      bg: 'bg-amber-950/60 border-amber-500/50 text-amber-300',
      badge: 'bg-amber-500 text-slate-950',
      icon: AlertOctagon,
      title: 'SCAN INCOMPLETE (FAIL-CLOSED)',
      desc: 'One or more required security scanners failed, were skipped, or not installed. Security gate failed closed to prevent insecure deployment.',
    },
    NO_SCANS: {
      bg: 'bg-slate-900 border-slate-700 text-slate-300',
      badge: 'bg-slate-700 text-slate-200',
      icon: AlertTriangle,
      title: 'NO SCANS RECORDED',
      desc: 'Waiting for initial security scan ingestion from GitHub Actions pipeline or local scanner execution.',
    },
  };

  const currentTheme = decisionStyles[gateDecision] || decisionStyles.NO_SCANS;
  const GateIcon = currentTheme.icon;

  return (
    <div className="space-y-4">
      {/* Dynamic Security Gate Banner */}
      <div className={`p-4 md:p-5 rounded-xl border flex flex-col md:flex-row items-start md:items-center justify-between gap-4 ${currentTheme.bg}`}>
        <div className="flex items-start md:items-center gap-3.5">
          <div className="p-2.5 rounded-lg bg-black/30 shrink-0">
            <GateIcon className="w-7 h-7" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className={`text-xs px-2.5 py-0.5 rounded font-black tracking-wide uppercase ${currentTheme.badge}`}>
                {gateDecision}
              </span>
              <h2 className="text-base font-bold text-white tracking-tight">{currentTheme.title}</h2>
            </div>
            <p className="text-xs text-slate-300 mt-1 max-w-2xl leading-relaxed">{currentTheme.desc}</p>
          </div>
        </div>

        {summary?.latest_scan?.scan_timestamp && (
          <div className="text-left md:text-right shrink-0 text-xs text-slate-400">
            <div>Latest Scan:</div>
            <div className="font-mono text-slate-200 font-medium">
              {new Date(summary.latest_scan.scan_timestamp).toLocaleString()}
            </div>
          </div>
        )}
      </div>

      {/* KPI Stat Cards Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3.5">
        {/* Security Score */}
        <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Security Score</span>
          <div className="mt-2 flex items-baseline gap-1.5">
            <span className={`text-3xl font-extrabold font-mono ${
              score !== null && score !== undefined
                ? score >= 80 ? 'text-emerald-400' : score >= 50 ? 'text-amber-400' : 'text-rose-400'
                : 'text-slate-500'
            }`}>
              {score !== null && score !== undefined ? score : 'N/A'}
            </span>
            {score !== null && score !== undefined && <span className="text-xs text-slate-500 font-bold">/ 100</span>}
          </div>
          <span className="text-[11px] text-slate-500 mt-1">
            {score !== null && score !== undefined ? 'Verified Score' : 'Coverage Incomplete'}
          </span>
        </div>

        {/* Total Findings */}
        <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Total Findings</span>
          <div className="mt-2 text-3xl font-extrabold font-mono text-white">
            {summary?.total_findings ?? 0}
          </div>
          <span className="text-[11px] text-slate-500 mt-1">In the latest scan</span>
        </div>

        {/* Critical Card */}
        <div className="bg-[#0f172a] border border-rose-900/40 rounded-xl p-4 flex flex-col justify-between">
          <span className="text-xs font-semibold text-rose-400 uppercase tracking-wider flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-rose-500 animate-pulse"></span>
            Critical
          </span>
          <div className="mt-2 text-3xl font-extrabold font-mono text-rose-400">
            {summary?.critical_count ?? 0}
          </div>
          <span className="text-[11px] text-rose-400/70 mt-1">Blocks Pipeline</span>
        </div>

        {/* High Card */}
        <div className="bg-[#0f172a] border border-orange-900/40 rounded-xl p-4 flex flex-col justify-between">
          <span className="text-xs font-semibold text-orange-400 uppercase tracking-wider flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-orange-500"></span>
            High
          </span>
          <div className="mt-2 text-3xl font-extrabold font-mono text-orange-400">
            {summary?.high_count ?? 0}
          </div>
          <span className="text-[11px] text-orange-400/70 mt-1">Blocks Pipeline</span>
        </div>

        {/* Medium Card */}
        <div className="bg-[#0f172a] border border-amber-900/40 rounded-xl p-4 flex flex-col justify-between">
          <span className="text-xs font-semibold text-amber-400 uppercase tracking-wider">Medium</span>
          <div className="mt-2 text-3xl font-extrabold font-mono text-amber-400">
            {summary?.medium_count ?? 0}
          </div>
          <span className="text-[11px] text-amber-400/70 mt-1">Warn Only</span>
        </div>

        {/* Low Card */}
        <div className="bg-[#0f172a] border border-emerald-900/40 rounded-xl p-4 flex flex-col justify-between">
          <span className="text-xs font-semibold text-emerald-400 uppercase tracking-wider">Low</span>
          <div className="mt-2 text-3xl font-extrabold font-mono text-emerald-400">
            {summary?.low_count ?? 0}
          </div>
          <span className="text-[11px] text-emerald-400/70 mt-1">Informational</span>
        </div>
      </div>
    </div>
  );
}
