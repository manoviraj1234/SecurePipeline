import React from 'react';
import {
  Code2,
  KeyRound,
  FileBox,
  PackageCheck,
  Container,
  CheckCircle2,
  XCircle,
  AlertCircle,
  Clock,
  ShieldCheck,
} from 'lucide-react';

export default function ScannerStatus({ scanners }) {
  const toolDefs = [
    {
      id: 'semgrep',
      name: 'Semgrep SAST',
      type: 'Static Code Analysis',
      icon: Code2,
      accent: 'text-sky-400 bg-sky-500/10 border-sky-500/20',
      desc: 'Detects command injection, eval flaws, and OWASP Top 10 risks in Python source.',
    },
    {
      id: 'gitleaks',
      name: 'Gitleaks',
      type: 'Secret Detection',
      icon: KeyRound,
      accent: 'text-amber-400 bg-amber-500/10 border-amber-500/20',
      desc: 'Scans git commits and files for hardcoded API keys, tokens, and credentials.',
    },
    {
      id: 'syft',
      name: 'Syft SBOM',
      type: 'Software Bill of Materials',
      icon: FileBox,
      accent: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/20',
      desc: 'Catalogs all dependency packages, licenses, and components into CycloneDX SBOM.',
    },
    {
      id: 'trivy_fs',
      name: 'Trivy Filesystem',
      type: 'Dependency Vulnerabilities',
      icon: PackageCheck,
      accent: 'text-purple-400 bg-purple-500/10 border-purple-500/20',
      desc: 'Audits application packages and lockfiles against public CVE databases.',
    },
    {
      id: 'trivy_image',
      name: 'Trivy Image',
      type: 'Container Image Security',
      icon: Container,
      accent: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
      desc: 'Inspects base image layers and OS system packages prior to deployment.',
    },
  ];

  const getStatusBadge = (status) => {
    const s = (status || 'UNKNOWN').toUpperCase();
    if (s === 'SUCCESS') {
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-semibold px-2.5 py-1 rounded-full bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 whitespace-nowrap">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
          SUCCESS
        </span>
      );
    }
    if (s === 'FAILED') {
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-semibold px-2.5 py-1 rounded-full bg-rose-500/15 text-rose-400 border border-rose-500/30 whitespace-nowrap">
          <XCircle className="w-3.5 h-3.5" />
          FAILED
        </span>
      );
    }
    if (s === 'NOT_INSTALLED') {
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-semibold px-2.5 py-1 rounded-full bg-amber-500/15 text-amber-400 border border-amber-500/30 whitespace-nowrap">
          <AlertCircle className="w-3.5 h-3.5" />
          NOT INSTALLED
        </span>
      );
    }
    if (s === 'SKIPPED') {
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-semibold px-2.5 py-1 rounded-full bg-slate-800 text-slate-400 border border-slate-700 whitespace-nowrap">
          <Clock className="w-3.5 h-3.5" />
          SKIPPED
        </span>
      );
    }
    return (
      <span className="text-xs font-semibold px-2.5 py-1 rounded-full bg-slate-800 text-slate-400 border border-slate-700 whitespace-nowrap">
        {s}
      </span>
    );
  };

  const getCountPill = (toolId, statusInfo) => {
    if (statusInfo.artifact_count !== undefined && statusInfo.artifact_count > 0) {
      return (
        <span className="text-[11px] font-mono text-cyan-300 bg-cyan-950/60 border border-cyan-800/60 px-2 py-0.5 rounded-md">
          {statusInfo.artifact_count} pkgs
        </span>
      );
    }
    if (statusInfo.findings_count !== undefined) {
      if (statusInfo.findings_count === 0) {
        return (
          <span className="text-[11px] font-mono text-emerald-300 bg-emerald-950/60 border border-emerald-800/60 px-2 py-0.5 rounded-md">
            Clean (0)
          </span>
        );
      }
      return (
        <span className="text-[11px] font-mono text-amber-300 bg-amber-950/60 border border-amber-800/60 px-2 py-0.5 rounded-md">
          {statusInfo.findings_count} findings
        </span>
      );
    }
    return null;
  };

  return (
    <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-sky-400" />
            Scanner Infrastructure Health
          </h3>
          <p className="text-xs text-slate-400">Integrated pipeline security tools</p>
        </div>
        <span className="text-xs font-mono text-slate-400 bg-slate-800/80 px-2.5 py-1 rounded-lg border border-slate-700">
          5 / 5 Active
        </span>
      </div>

      <div className="space-y-2.5">
        {toolDefs.map((tool) => {
          const Icon = tool.icon;
          const statusInfo = scanners?.[tool.id] || {};
          const currentStatus = statusInfo.status || 'not_installed';
          const errMsg = statusInfo.error_message;

          return (
            <div
              key={tool.id}
              className="bg-slate-900/90 hover:bg-slate-800/50 border border-slate-800/90 rounded-lg p-3 transition flex flex-col gap-2"
            >
              <div className="flex items-center justify-between gap-3">
                <div className="flex items-center gap-3 min-w-0">
                  <div className={`p-2 rounded-lg border shrink-0 ${tool.accent}`}>
                    <Icon className="w-4 h-4" />
                  </div>
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <h4 className="text-sm font-semibold text-white tracking-tight truncate">
                        {tool.name}
                      </h4>
                      {getCountPill(tool.id, statusInfo)}
                    </div>
                    <p className="text-[11px] text-slate-400 truncate">{tool.type}</p>
                  </div>
                </div>

                <div className="shrink-0">{getStatusBadge(currentStatus)}</div>
              </div>

              {errMsg && (
                <div className="text-[11px] text-rose-400/90 font-mono bg-rose-950/40 border border-rose-900/40 rounded px-2 py-1 break-all">
                  {errMsg}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
