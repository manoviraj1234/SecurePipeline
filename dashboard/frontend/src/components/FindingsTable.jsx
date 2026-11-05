import React from 'react';
import { Search, Filter, ExternalLink, ShieldAlert, ArrowUpDown, ChevronLeft, ChevronRight } from 'lucide-react';

export default function FindingsTable({
  findings,
  total,
  page,
  pageSize,
  onPageChange,
  filters,
  onFilterChange,
  onSelectFinding,
  showFilters = true,
}) {
  const severityBadges = {
    CRITICAL: 'bg-rose-500/15 text-rose-400 border-rose-500/30',
    HIGH: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
    MEDIUM: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
    LOW: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
    INFO: 'bg-sky-500/15 text-sky-400 border-sky-500/30',
  };

  const totalPages = Math.ceil(total / pageSize) || 1;

  return (
    <div className="bg-[#0f172a] border border-slate-800 rounded-xl overflow-hidden">
      {/* Search and Filters Header */}
      {showFilters && <div className="p-4 border-b border-slate-800 flex flex-col md:flex-row items-center justify-between gap-3 bg-slate-900/50">
        <div className="relative w-full md:w-80">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search CVE, package, or file..."
            value={filters.search}
            onChange={(e) => onFilterChange('search', e.target.value)}
            className="w-full bg-slate-800 border border-slate-700 text-xs text-white rounded-lg pl-9 pr-3 py-2 focus:outline-none focus:border-sky-500 placeholder-slate-500"
          />
        </div>

        <div className="flex items-center gap-2.5 w-full md:w-auto">
          {/* Severity filter */}
          <div className="flex items-center gap-1.5 bg-slate-800 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-300">
            <Filter className="w-3.5 h-3.5 text-slate-400" />
            <select
              value={filters.severity}
              onChange={(e) => onFilterChange('severity', e.target.value)}
              className="bg-transparent text-xs text-white focus:outline-none cursor-pointer"
            >
              <option value="" className="bg-slate-900">All Severities</option>
              <option value="CRITICAL" className="bg-slate-900 text-rose-400">Critical</option>
              <option value="HIGH" className="bg-slate-900 text-orange-400">High</option>
              <option value="MEDIUM" className="bg-slate-900 text-amber-400">Medium</option>
              <option value="LOW" className="bg-slate-900 text-emerald-400">Low</option>
            </select>
          </div>

          {/* Priority filter */}
          <div className="flex items-center gap-1.5 bg-slate-800 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-300">
            <select
              value={filters.priority || ''}
              onChange={(e) => onFilterChange('priority', e.target.value)}
              className="bg-transparent text-xs text-white focus:outline-none cursor-pointer"
            >
              <option value="" className="bg-slate-900">All Priorities</option>
              <option value="P0" className="bg-slate-900 text-rose-400">P0 - Blocker</option>
              <option value="P1" className="bg-slate-900 text-orange-400">P1 - High Priority</option>
              <option value="P2" className="bg-slate-900 text-amber-400">P2 - Medium Priority</option>
              <option value="P3" className="bg-slate-900 text-sky-400">P3 - Low Priority</option>
            </select>
          </div>

          {/* Scanner filter */}
          <div className="flex items-center gap-1.5 bg-slate-800 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-300">
            <select
              value={filters.scanner}
              onChange={(e) => onFilterChange('scanner', e.target.value)}
              className="bg-transparent text-xs text-white focus:outline-none cursor-pointer"
            >
              <option value="" className="bg-slate-900">All Scanners</option>
              <option value="semgrep" className="bg-slate-900">Semgrep SAST</option>
              <option value="gitleaks" className="bg-slate-900">Gitleaks Secrets</option>
              <option value="trivy_fs" className="bg-slate-900">Trivy Filesystem</option>
              <option value="trivy_image" className="bg-slate-900">Trivy Image</option>
            </select>
          </div>
        </div>
      </div>}

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead className="bg-[#0a0f1d] text-slate-400 uppercase font-semibold border-b border-slate-800 tracking-wider">
            <tr>
              <th className="py-3 px-4">Priority / Risk</th>
              <th className="py-3 px-4">Severity</th>
              <th className="py-3 px-4">Finding ID</th>
              <th className="py-3 px-4">Scanner</th>
              <th className="py-3 px-4">Location / Component</th>
              <th className="py-3 px-4">Description</th>
              <th className="py-3 px-4 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/80">
            {findings.length === 0 ? (
              <tr>
                <td colSpan={7} className="py-12 text-center text-slate-500 italic">
                  No vulnerability findings match the current filter criteria.
                </td>
              </tr>
            ) : (
              findings.map((f) => {
                const sev = (f.severity || 'MEDIUM').toUpperCase();
                const badgeClass = severityBadges[sev] || severityBadges.MEDIUM;
                const location = f.file ? `${f.file}${f.line ? `:${f.line}` : ''}` : f.package || 'codebase';
                const prio = f.priority || 'P2';
                const prioBadges = {
                  P0: 'bg-rose-500/20 text-rose-300 border-rose-500/40',
                  P1: 'bg-orange-500/20 text-orange-300 border-orange-500/40',
                  P2: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
                  P3: 'bg-sky-500/20 text-sky-300 border-sky-500/40',
                };

                return (
                  <tr key={f.id} className="hover:bg-slate-800/40 transition">
                    <td className="py-3 px-4 whitespace-nowrap">
                      <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-mono font-bold border ${prioBadges[prio] || prioBadges.P2}`}>
                        {prio === 'P0' ? '🔥 P0' : prio}
                        <span className="opacity-75">({f.risk_score || 50}/100)</span>
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <span className={`inline-block px-2 py-0.5 rounded text-[11px] font-bold border ${badgeClass}`}>
                        {sev}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-mono font-semibold text-slate-200">
                      {f.finding_id}
                    </td>
                    <td className="py-3 px-4 text-slate-400 capitalize">
                      {f.scanner.replace('_', ' ')}
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-300 max-w-[200px] truncate" title={location}>
                      {location}
                    </td>
                    <td className="py-3 px-4 text-slate-300 max-w-xs truncate" title={f.description}>
                      {f.description}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => onSelectFinding(f)}
                        className="bg-sky-500/10 hover:bg-sky-500/20 text-sky-400 border border-sky-500/30 px-2.5 py-1 rounded text-xs font-medium transition"
                      >
                        Details
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Footer */}
      <div className="p-3 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400 bg-slate-900/30">
        <div>
          Showing <span className="text-white font-medium">{findings.length}</span> of{' '}
          <span className="text-white font-medium">{total}</span> findings
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => onPageChange(page - 1)}
            disabled={page <= 1}
            className="p-1 rounded bg-slate-800 border border-slate-700 text-slate-300 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed"
          >
            <ChevronLeft className="w-4 h-4" />
          </button>
          <span className="font-mono text-slate-300">
            Page {page} of {totalPages}
          </span>
          <button
            onClick={() => onPageChange(page + 1)}
            disabled={page >= totalPages}
            className="p-1 rounded bg-slate-800 border border-slate-700 text-slate-300 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed"
          >
            <ChevronRight className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
}
