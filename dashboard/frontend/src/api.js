import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_URL || '/api';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 10000,
});

export const fetchHealth = async () => {
  const res = await api.get('/health');
  return res.data;
};

export const fetchDashboardSummary = async () => {
  const res = await api.get('/dashboard/summary');
  return res.data;
};

export const fetchSeverityDistribution = async () => {
  const res = await api.get('/dashboard/severity-distribution');
  return res.data;
};

export const fetchScannerStatus = async () => {
  const res = await api.get('/dashboard/scanner-status');
  return res.data;
};

export const fetchScanHistory = async (limit = 10) => {
  const res = await api.get(`/dashboard/scan-history?limit=${limit}`);
  return res.data;
};

export const fetchScans = async (skip = 0, limit = 20, gateDecision = null) => {
  let url = `/scans?skip=${skip}&limit=${limit}`;
  if (gateDecision) {
    url += `&gate_decision=${gateDecision}`;
  }
  const res = await api.get(url);
  return res.data;
};

export const fetchScanDetail = async (scanId) => {
  const res = await api.get(`/scans/${scanId}`);
  return res.data;
};

export const fetchFindings = async ({ skip = 0, limit = 50, scanId = null, severity = null, scanner = null, search = null, priority = null }) => {
  let url = `/findings?skip=${skip}&limit=${limit}`;
  if (scanId) url += `&scan_id=${scanId}`;
  if (severity) url += `&severity=${severity}`;
  if (scanner) url += `&scanner=${scanner}`;
  if (priority) url += `&priority=${priority}`;
  if (search) url += `&search=${encodeURIComponent(search)}`;
  const res = await api.get(url);
  return res.data;
};

export const fetchScanRegression = async (scanId) => {
  const res = await api.get(`/scans/${scanId}/regression`);
  return res.data;
};

export const fetchFindingDetail = async (findingId) => {
  const res = await api.get(`/findings/${findingId}`);
  return res.data;
};

export const analyzeCode = async (code, language = 'python', filename = 'submitted_code.py') => {
  const res = await api.post('/analyzer/analyze', { code, language, filename });
  return res.data;
};

export const fetchAnalyzerPatterns = async () => {
  const res = await api.get('/analyzer/patterns');
  return res.data;
};

export default api;
