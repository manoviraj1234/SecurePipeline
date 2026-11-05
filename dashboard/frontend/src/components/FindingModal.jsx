import React from 'react';
import { X, ExternalLink, Wrench, Shield, AlertTriangle } from 'lucide-react';

export default function FindingModal({ finding, onClose }) {
  if (!finding) return null;

  const sevColors = {
    CRITICAL: 'bg-rose-500/15 text-rose-400 border-rose-500/40',
    HIGH: 'bg-orange-500/15 text-orange-400 border-orange-500/40',
    MEDIUM: 'bg-amber-500/15 text-amber-400 border-amber-500/40',
    LOW: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/40',
    INFO: 'bg-sky-500/15 text-sky-400 border-sky-500/40',
  };

  const badgeClass = sevColors[finding.severity] || sevColors.MEDIUM;
  const hint = `${finding.finding_id || ''} ${finding.title || ''} ${finding.description || ''} ${finding.package || ''}`.toLowerCase();

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="bg-[#0f172a] border border-slate-700 rounded-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto shadow-2xl flex flex-col">
        {/* Header */}
        <div className="p-5 border-b border-slate-800 flex items-start justify-between gap-4 sticky top-0 bg-[#0f172a] z-10">
          <div>
            <div className="flex items-center gap-2 mb-1.5 flex-wrap">
              <span className={`text-xs px-2.5 py-0.5 rounded-full font-bold border ${badgeClass}`}>
                {finding.severity}
              </span>
              <span className="text-xs px-2.5 py-0.5 rounded-full font-mono font-bold bg-rose-500/15 text-rose-300 border border-rose-500/30">
                Priority {finding.priority || 'P2'} • Risk {finding.risk_score || 50}/100
              </span>
              <span className="text-xs text-slate-400 font-mono capitalize">
                Scanner: {finding.scanner.replace('_', ' ')}
              </span>
            </div>
            <h2 className="text-lg font-bold text-white font-mono">{finding.finding_id}</h2>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-5 text-sm">
          {/* Description */}
          <div>
            <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-1.5">Description</h3>
            <p className="text-slate-200 leading-relaxed bg-slate-900/60 p-3.5 rounded-lg border border-slate-800">
              {finding.description}
            </p>
          </div>

          {/* Contextual Risk Analysis */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <Shield className="w-4 h-4 text-sky-400" />
                Contextual Risk &amp; Reachability Analysis
              </span>
              <span className="text-xs font-mono font-bold text-sky-300 bg-sky-950/60 px-2 py-0.5 rounded border border-sky-800">
                Score: {finding.risk_score || 50} / 100
              </span>
            </div>
            {finding.risk_factors && finding.risk_factors.length > 0 ? (
              <ul className="space-y-1 text-xs text-slate-300">
                {finding.risk_factors.map((factor, idx) => (
                  <li key={idx} className="flex items-center gap-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-sky-400"></span>
                    <span>{factor}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-xs text-slate-400 italic">
                Evaluated based on component reachability, public ingress exposure, and threat impact.
              </p>
            )}
          </div>

          {/* Location & Package Details */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5 text-xs">
            <div className="bg-slate-900/60 p-3 rounded-lg border border-slate-800">
              <span className="text-slate-500 font-medium uppercase tracking-wider block mb-1">Target File / Path</span>
              <span className="font-mono text-slate-300 font-semibold break-all">
                {finding.file || 'N/A'}{finding.line ? ` : line ${finding.line}` : ''}
              </span>
            </div>
            <div className="bg-slate-900/60 p-3 rounded-lg border border-slate-800">
              <span className="text-slate-500 font-medium uppercase tracking-wider block mb-1">Affected Package</span>
              <span className="font-mono text-slate-300 font-semibold">
                {finding.package || 'Source Code Pattern'}
              </span>
            </div>
            {finding.installed_version && (
              <div className="bg-slate-900/60 p-3 rounded-lg border border-slate-800">
                <span className="text-slate-500 font-medium uppercase tracking-wider block mb-1">Installed Version</span>
                <span className="font-mono text-rose-300 font-bold">{finding.installed_version}</span>
              </div>
            )}
            {finding.fixed_version && (
              <div className="bg-slate-900/60 p-3 rounded-lg border border-slate-800">
                <span className="text-slate-500 font-medium uppercase tracking-wider block mb-1">Fixed Version</span>
                <span className="font-mono text-emerald-300 font-bold">{finding.fixed_version}</span>
              </div>
            )}
          </div>

          {/* Remediation Guidance */}
          <div className="bg-sky-950/30 border border-sky-500/30 rounded-xl p-4 space-y-3">
            <div className="flex items-center gap-2 text-sky-400 font-bold text-xs uppercase tracking-wider">
              <Wrench className="w-4 h-4" />
              AI Remediation &amp; Solution
            </div>
            <p className="text-xs text-sky-200 leading-relaxed">
              {finding.remediation || 'Upgrade dependency to the latest secure version or apply least privilege principles.'}
            </p>

            {/* Practical Solution Box */}
            <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-3">
              <span className="text-[11px] font-bold text-emerald-400 uppercase tracking-wider block mb-1.5">
                💡 Recommended Code / Configuration Fix:
              </span>
              {hint.includes('250') || hint.includes('privilege') || finding.file?.includes('Dockerfile') ? (
                <pre className="text-xs font-mono text-emerald-300 bg-emerald-950/30 p-2.5 rounded border border-emerald-900/50 overflow-x-auto">
{`# Add non-root user in Dockerfile:
RUN useradd -m -u 1000 appuser
WORKDIR /app
COPY . .
USER appuser  # Drop root privileges before execution`}
                </pre>
              ) : finding.fixed_version ? (
                <pre className="text-xs font-mono text-emerald-300 bg-emerald-950/30 p-2.5 rounded border border-emerald-900/50 overflow-x-auto">
{`# Update ${finding.package || 'package'} in requirements.txt or Dockerfile:
${finding.package}==${finding.fixed_version}`}
                </pre>
              ) : hint.includes('eval') || hint.includes('exec(') ? (
                <pre className="text-xs font-mono text-emerald-300 bg-emerald-950/30 p-2.5 rounded border border-emerald-900/50 overflow-x-auto">
{`# Replace dangerous eval() with safe literal parsing:
import ast
safe_data = ast.literal_eval(user_input)`}
                </pre>
              ) : /shell|subprocess|command injection|os\.system/.test(hint) ? (
                <pre className="text-xs font-mono text-emerald-300 bg-emerald-950/30 p-2.5 rounded border border-emerald-900/50 overflow-x-auto">
{`# Avoid shell=True to prevent command injection:
import subprocess
subprocess.run(["allowed_command", arg], shell=False, check=True)`}
                </pre>
              ) : (
                <pre className="text-xs font-mono text-emerald-300 bg-emerald-950/30 p-2.5 rounded border border-emerald-900/50 overflow-x-auto">
{`# Recommended fix:
1. Isolate the affected component
2. Upgrade dependency or sanitize user-controlled parameters
3. Enforce the Principle of Least Privilege`}
                </pre>
              )}
            </div>
          </div>

          {/* References */}
          {finding.references && finding.references.length > 0 && (
            <div>
              <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-1.5">References &amp; Standards</h3>
              <ul className="space-y-1 text-xs font-mono">
                {finding.references.map((ref, idx) => (
                  <li key={idx} className="flex items-center gap-1.5 text-slate-400 truncate">
                    <ExternalLink className="w-3.5 h-3.5 text-sky-400 shrink-0" />
                    {ref.startsWith('http') ? (
                      <a href={ref} target="_blank" rel="noreferrer" className="text-sky-400 hover:underline truncate">
                        {ref}
                      </a>
                    ) : (
                      <span>{ref}</span>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-900/50 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg text-xs font-semibold transition"
          >
            Close Details
          </button>
        </div>
      </div>
    </div>
  );
}
