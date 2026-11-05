import React from 'react';
import { Shield, RefreshCw, Server, AlertTriangle } from 'lucide-react';

export default function Header({ backendConnected, onRefresh, loading }) {
  return (
    <header className="bg-[#0f172a] border-b border-slate-800 px-6 py-4 flex flex-col md:flex-row items-center justify-between gap-4 sticky top-0 z-20">
      <div className="flex items-center gap-3">
        <div className="bg-sky-500/10 p-2.5 rounded-lg border border-sky-500/30 text-sky-400">
          <Shield className="w-7 h-7" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold tracking-tight text-white">SecurePipeline</h1>
            <span className="bg-sky-500/20 text-sky-300 text-xs px-2 py-0.5 rounded-full font-medium border border-sky-500/30">
              DevSecOps
            </span>
          </div>
          <p className="text-xs text-slate-400">Automated CI/CD Vulnerability Detection &amp; Security Gate</p>
        </div>
      </div>

      <div className="flex items-center gap-4">
        {/* Connection status badge */}
        <div className="flex items-center gap-2 text-xs font-medium px-3 py-1.5 rounded-full border bg-slate-900/80">
          <Server className={`w-3.5 h-3.5 ${backendConnected ? 'text-emerald-400' : 'text-amber-400'}`} />
          <span className={backendConnected ? 'text-emerald-300' : 'text-amber-300'}>
            {backendConnected ? 'Backend Connected (FastAPI)' : 'Connecting to API...'}
          </span>
          <span className={`w-2 h-2 rounded-full ${backendConnected ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'}`}></span>
        </div>

        {/* Refresh button */}
        <button
          onClick={onRefresh}
          disabled={loading}
          className="flex items-center gap-1.5 bg-slate-800 hover:bg-slate-700 active:bg-slate-900 border border-slate-700 text-slate-200 px-3 py-1.5 rounded-lg text-xs font-semibold transition disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>
    </header>
  );
}
