import React, { useState } from 'react';
import {
  Code2,
  Shield,
  AlertTriangle,
  CheckCircle,
  Copy,
  Play,
  Trash2,
  ChevronDown,
  ChevronUp,
  FileCode,
  Loader2,
} from 'lucide-react';
import { analyzeCode } from '../api';

const EXAMPLE_CODE = `import subprocess
import os
import sqlite3
import pickle
import hashlib
import random
import requests

# Hardcoded secret
API_KEY = "AKIAIOSFODNN7EXAMPLE"
DB_PASSWORD = "super_secret_password_123"

def run_command(user_input):
    # Command injection vulnerability
    return subprocess.check_output(user_input, shell=True)

def process_data(data):
    # Code injection vulnerability
    result = eval(data)
    return result

def get_user(username):
    # SQL injection vulnerability
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")
    return cursor.fetchall()

def load_data(raw_bytes):
    # Insecure deserialization
    return pickle.loads(raw_bytes)

def hash_password(password):
    # Weak cryptography
    return hashlib.md5(password.encode()).hexdigest()

def generate_token():
    # Insecure random
    return random.randint(100000, 999999)

def fetch_url(user_url):
    # SSRF vulnerability
    return requests.get(user_url, verify=False)`;

const SEVERITY_COLORS = {
  CRITICAL: { badge: 'bg-rose-500/20 text-rose-400 border-rose-500/40', accent: 'text-rose-400', dot: 'bg-rose-500' },
  HIGH: { badge: 'bg-orange-500/20 text-orange-400 border-orange-500/40', accent: 'text-orange-400', dot: 'bg-orange-500' },
  MEDIUM: { badge: 'bg-amber-500/20 text-amber-400 border-amber-500/40', accent: 'text-amber-400', dot: 'bg-amber-500' },
  LOW: { badge: 'bg-sky-500/20 text-sky-400 border-sky-500/40', accent: 'text-sky-400', dot: 'bg-sky-500' },
};

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

export default function CodeAnalyzer() {
  const [code, setCode] = useState('');
  const [language, setLanguage] = useState('python');
  const [filename, setFilename] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [expandedCards, setExpandedCards] = useState({});
  const [copiedId, setCopiedId] = useState(null);

  const handleAnalyze = async () => {
    if (!code.trim()) return;
    try {
      setLoading(true);
      setError(null);
      setExpandedCards({});
      const data = await analyzeCode(
        code,
        language,
        filename || `submitted_code.${language === 'python' ? 'py' : language === 'javascript' ? 'js' : 'java'}`
      );
      setResult(data);
    } catch (err) {
      console.error('Analysis failed:', err);
      setError(err.response?.data?.detail || 'Failed to analyze code. Ensure the backend is running.');
      setResult(null);
    } finally {
      setLoading(false);
    }
  };

  const handleClear = () => {
    setCode('');
    setFilename('');
    setResult(null);
    setError(null);
    setExpandedCards({});
  };

  const handleLoadExample = () => {
    setCode(EXAMPLE_CODE);
    setLanguage('python');
    setFilename('example_vulnerable.py');
    setResult(null);
    setError(null);
    setExpandedCards({});
  };

  const toggleCard = (id) => {
    setExpandedCards((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const copyToClipboard = async (text, id) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedId(id);
      setTimeout(() => setCopiedId(null), 2000);
    } catch {
      // Fallback: textarea copy
      const ta = document.createElement('textarea');
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      setCopiedId(id);
      setTimeout(() => setCopiedId(null), 2000);
    }
  };

  const sortedFindings = result?.findings
    ? [...result.findings].sort(
        (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
      )
    : [];

  return (
    <div className="space-y-6">
      {/* Code Input Section */}
      <div className="bg-slate-900/80 border border-slate-700/60 rounded-xl p-5 space-y-4">
        <div className="flex items-center gap-2 mb-1">
          <Code2 className="w-5 h-5 text-sky-400" />
          <h3 className="text-sm font-bold text-white uppercase tracking-wider">Code Input</h3>
        </div>

        <textarea
          value={code}
          onChange={(e) => setCode(e.target.value)}
          rows={15}
          placeholder={`# Paste your code here for security analysis...\nimport subprocess\n\ndef run_command(user_input):\n    return subprocess.check_output(user_input, shell=True)`}
          className="w-full bg-[#0d1321] border border-slate-700/80 rounded-lg p-4 text-sm text-slate-200 font-mono placeholder-slate-600 focus:outline-none focus:ring-2 focus:ring-sky-500/40 focus:border-sky-500/60 resize-y transition"
          spellCheck={false}
        />

        <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3">
          {/* Language Selector */}
          <div className="flex items-center gap-2">
            <label className="text-xs text-slate-400 font-medium">Language:</label>
            <select
              value={language}
              onChange={(e) => setLanguage(e.target.value)}
              className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:ring-2 focus:ring-sky-500/40"
            >
              <option value="python">Python</option>
              <option value="javascript" disabled>JavaScript (Coming Soon)</option>
              <option value="java" disabled>Java (Coming Soon)</option>
            </select>
          </div>

          {/* Filename Input */}
          <div className="flex items-center gap-2">
            <label className="text-xs text-slate-400 font-medium">Filename:</label>
            <input
              type="text"
              value={filename}
              onChange={(e) => setFilename(e.target.value)}
              placeholder="submitted_code.py"
              className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-sky-500/40 w-48"
            />
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex flex-wrap gap-2 pt-1">
          <button
            onClick={handleAnalyze}
            disabled={loading || !code.trim()}
            className="flex items-center gap-2 bg-sky-600 hover:bg-sky-500 disabled:bg-slate-700 disabled:text-slate-500 text-white px-4 py-2 rounded-lg text-sm font-semibold transition"
          >
            {loading ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Play className="w-4 h-4" />
            )}
            {loading ? 'Analyzing...' : 'Analyze Code'}
          </button>

          <button
            onClick={handleLoadExample}
            disabled={loading}
            className="flex items-center gap-2 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-300 px-4 py-2 rounded-lg text-sm font-medium border border-slate-700 transition"
          >
            <FileCode className="w-4 h-4" />
            Load Example
          </button>

          <button
            onClick={handleClear}
            disabled={loading}
            className="flex items-center gap-2 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-300 px-4 py-2 rounded-lg text-sm font-medium border border-slate-700 transition"
          >
            <Trash2 className="w-4 h-4" />
            Clear
          </button>
        </div>
      </div>

      {/* Error Banner */}
      {error && (
        <div className="bg-rose-950/80 border border-rose-500/50 rounded-xl p-4 flex items-center gap-2.5 text-rose-300 text-xs font-medium">
          <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Empty State */}
      {!result && !error && !loading && (
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-12 flex flex-col items-center justify-center text-center space-y-3">
          <Shield className="w-12 h-12 text-slate-600" />
          <h3 className="text-sm font-semibold text-slate-400">No Analysis Results Yet</h3>
          <p className="text-xs text-slate-500 max-w-md">
            Submit code to begin analysis. Paste your source code above and click "Analyze Code" to detect vulnerabilities and receive AI-powered improvement suggestions.
          </p>
        </div>
      )}

      {/* Loading State */}
      {loading && (
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-12 flex flex-col items-center justify-center text-center space-y-3">
          <Loader2 className="w-10 h-10 text-sky-400 animate-spin" />
          <h3 className="text-sm font-semibold text-slate-300">Analyzing Code...</h3>
          <p className="text-xs text-slate-500">Scanning for vulnerabilities, security patterns, and generating recommendations</p>
        </div>
      )}

      {/* Analysis Results */}
      {result && (
        <div className="space-y-5">
          {/* Summary Banner */}
          <div className="bg-slate-900/80 border border-slate-700/60 rounded-xl p-5">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                {result.total_vulnerabilities > 0 ? (
                  <AlertTriangle className="w-6 h-6 text-amber-400" />
                ) : (
                  <CheckCircle className="w-6 h-6 text-emerald-400" />
                )}
                <div>
                  <h3 className="text-sm font-bold text-white">
                    {result.total_vulnerabilities > 0
                      ? `${result.total_vulnerabilities} Vulnerabilit${result.total_vulnerabilities === 1 ? 'y' : 'ies'} Found`
                      : 'No Vulnerabilities Detected'}
                  </h3>
                  <p className="text-xs text-slate-400">
                    {result.language} • {result.filename} • {result.analysis_timestamp ? new Date(result.analysis_timestamp).toLocaleString() : 'Just now'}
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-3">
                {SEVERITY_ORDER.map((sev) => {
                  const count = result.severity_counts?.[sev] || 0;
                  if (count === 0) return null;
                  const colors = SEVERITY_COLORS[sev];
                  return (
                    <div
                      key={sev}
                      className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold border ${colors.badge}`}
                    >
                      <span className={`w-1.5 h-1.5 rounded-full ${colors.dot}`} />
                      {sev}: {count}
                    </div>
                  );
                })}

                <span
                  className={`px-2.5 py-1 rounded-full text-xs font-semibold border ${
                    result.status === 'success'
                      ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40'
                      : 'bg-rose-500/20 text-rose-400 border-rose-500/40'
                  }`}
                >
                  {result.status === 'success' ? 'Analysis Complete' : 'Error'}
                </span>
              </div>
            </div>

            {result.summary && (
              <p className="mt-3 text-xs text-slate-300 bg-slate-800/60 rounded-lg px-4 py-2.5 border border-slate-700/40">
                {result.summary}
              </p>
            )}
          </div>

          {/* Findings List */}
          {sortedFindings.length > 0 && (
            <div className="space-y-3">
              <div className="flex items-center gap-2">
                <Shield className="w-4 h-4 text-sky-400" />
                <h3 className="text-sm font-bold text-white uppercase tracking-wider">Detailed Findings</h3>
              </div>

              {sortedFindings.map((finding, index) => {
                const colors = SEVERITY_COLORS[finding.severity] || SEVERITY_COLORS.LOW;
                const isExpanded = expandedCards[finding.id];
                const cardBg = index % 2 === 0 ? 'bg-slate-900/70' : 'bg-slate-900/50';

                return (
                  <div
                    key={finding.id}
                    className={`${cardBg} border border-slate-700/50 rounded-xl overflow-hidden transition-all duration-300`}
                  >
                    {/* Card Header */}
                    <button
                      onClick={() => toggleCard(finding.id)}
                      className="w-full flex items-center justify-between px-5 py-3.5 hover:bg-slate-800/40 transition-colors"
                    >
                      <div className="flex items-center gap-3 flex-wrap">
                        <span
                          className={`px-2.5 py-0.5 rounded-md text-xs font-bold border ${colors.badge}`}
                        >
                          {finding.severity}
                        </span>
                        <span className="text-sm font-medium text-white">{finding.name}</span>
                        {finding.cwe && (
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-slate-800 text-slate-400 border border-slate-700">
                            {finding.cwe}
                          </span>
                        )}
                        {finding.line_number && (
                          <span className="text-xs text-slate-500">
                            Line {finding.line_number}
                          </span>
                        )}
                        {finding.owasp && (
                          <span className="text-[10px] text-slate-500 font-medium">
                            {finding.owasp}
                          </span>
                        )}
                      </div>
                      {isExpanded ? (
                        <ChevronUp className="w-4 h-4 text-slate-400 shrink-0" />
                      ) : (
                        <ChevronDown className="w-4 h-4 text-slate-400 shrink-0" />
                      )}
                    </button>

                    {/* Card Body */}
                    <div
                      className={`transition-all duration-300 ease-in-out overflow-hidden ${
                        isExpanded ? 'max-h-[2000px] opacity-100' : 'max-h-0 opacity-0'
                      }`}
                    >
                      <div className="px-5 pb-5 space-y-4 border-t border-slate-700/40">
                        {/* Vulnerable Code */}
                        {finding.vulnerable_code && (
                          <div className="pt-4">
                            <h4 className="text-xs font-semibold text-rose-400 uppercase tracking-wider mb-2">
                              Vulnerable Code
                            </h4>
                            <pre className="bg-rose-950/30 border border-rose-500/20 rounded-lg p-3 text-xs text-rose-200 font-mono overflow-x-auto whitespace-pre-wrap">
                              {finding.vulnerable_code}
                            </pre>
                          </div>
                        )}

                        {/* Explanation */}
                        {finding.explanation && (
                          <div>
                            <h4 className="text-xs font-semibold text-amber-400 uppercase tracking-wider mb-2">
                              Explanation
                            </h4>
                            <div className="bg-amber-950/20 border border-amber-500/20 rounded-lg p-3 text-xs text-amber-200/90 leading-relaxed">
                              {finding.explanation}
                            </div>
                          </div>
                        )}

                        {/* Suggested Fix */}
                        {finding.suggested_fix && (
                          <div>
                            <h4 className="text-xs font-semibold text-emerald-400 uppercase tracking-wider mb-2">
                              Suggested Fix
                            </h4>
                            <div className="bg-emerald-950/20 border border-emerald-500/20 rounded-lg p-3 text-xs text-emerald-200/90 leading-relaxed">
                              <ul className="list-disc list-inside space-y-1">
                                {(Array.isArray(finding.suggested_fix)
                                  ? finding.suggested_fix
                                  : finding.suggested_fix.split('\n').filter(Boolean)
                                ).map((tip, i) => (
                                  <li key={i}>{tip.replace(/^[-•]\s*/, '')}</li>
                                ))}
                              </ul>
                            </div>
                          </div>
                        )}

                        {/* Improved Code */}
                        {finding.improved_code && (
                          <div>
                            <div className="flex items-center justify-between mb-2">
                              <h4 className="text-xs font-semibold text-emerald-400 uppercase tracking-wider">
                                Improved Code
                              </h4>
                              <button
                                onClick={() => copyToClipboard(finding.improved_code, finding.id)}
                                className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-white bg-slate-800 hover:bg-slate-700 px-2.5 py-1 rounded-md border border-slate-700 transition"
                              >
                                {copiedId === finding.id ? (
                                  <>
                                    <CheckCircle className="w-3 h-3 text-emerald-400" />
                                    <span className="text-emerald-400">Copied!</span>
                                  </>
                                ) : (
                                  <>
                                    <Copy className="w-3 h-3" />
                                    <span>Copy</span>
                                  </>
                                )}
                              </button>
                            </div>
                            <pre className="bg-emerald-950/20 border border-emerald-500/20 rounded-lg p-3 text-xs text-emerald-200 font-mono overflow-x-auto whitespace-pre-wrap">
                              {finding.improved_code}
                            </pre>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
