import React from 'react';
import { LayoutDashboard, Bug, Activity, History, Code2 } from 'lucide-react';

export default function Sidebar({ activeTab, onSelectTab, counts }) {
  const tabs = [
    { id: 'overview', label: 'Overview', icon: LayoutDashboard },
    { id: 'vulnerabilities', label: 'Vulnerabilities', icon: Bug, count: counts?.totalFindings },
    { id: 'scanners', label: 'Scanner Status', icon: Activity },
    { id: 'history', label: 'Scan History', icon: History, count: counts?.totalScans },
    { id: 'analyzer', label: 'Code Analyzer', icon: Code2 },
  ];

  return (
    <aside className="w-full md:w-64 bg-[#0f172a] border-r border-slate-800 p-4 shrink-0">
      <div className="text-[11px] font-semibold tracking-wider text-slate-400 uppercase px-3 mb-2">
        Navigation
      </div>
      <nav className="space-y-1">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => onSelectTab(tab.id)}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-sm font-medium transition ${
                isActive
                  ? 'bg-sky-500/15 text-sky-400 border border-sky-500/30'
                  : 'text-slate-300 hover:bg-slate-800/60 hover:text-white'
              }`}
            >
              <div className="flex items-center gap-2.5">
                <Icon className={`w-4 h-4 ${isActive ? 'text-sky-400' : 'text-slate-400'}`} />
                <span>{tab.label}</span>
              </div>
              {tab.count !== undefined && tab.count > 0 && (
                <span className={`text-xs px-2 py-0.5 rounded-full font-mono ${
                  isActive ? 'bg-sky-500/30 text-sky-200' : 'bg-slate-800 text-slate-400'
                }`}>
                  {tab.count}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      <div className="mt-8 border-t border-slate-800 pt-4 px-3">
        <div className="text-[11px] font-semibold tracking-wider text-slate-400 uppercase mb-2">
          Gate Policy
        </div>
        <div className="bg-slate-900/90 rounded-lg p-3 border border-slate-800 text-xs text-slate-300 space-y-1.5">
          <div className="flex items-center gap-1.5 font-medium text-rose-400">
            <span className="w-1.5 h-1.5 rounded-full bg-rose-400"></span>
            Block: Critical &amp; High
          </div>
          <div className="flex items-center gap-1.5 font-medium text-amber-400">
            <span className="w-1.5 h-1.5 rounded-full bg-amber-400"></span>
            Warn: Medium &amp; Low
          </div>
          <div className="flex items-center gap-1.5 font-medium text-purple-400">
            <span className="w-1.5 h-1.5 rounded-full bg-purple-400"></span>
            Fail-Closed: Missing/Failed
          </div>
        </div>
      </div>
    </aside>
  );
}
