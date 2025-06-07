/**
 * FinGuardAI API Service
 * 
 * Provides functions for interacting with the FinGuardAI backend API.
 */

/**
 * API Base URL configuration
 * 
 * This dynamically selects the appropriate API URL based on the environment:
 * - In development: Uses localhost:5001
 * - In production: Uses the environment variable or API proxy
 * - When deployed: Uses the Render backend URL
 */
export const API_BASE_URL = 
  // Development environment (localhost)
  (typeof window !== 'undefined' && window.location.hostname === 'localhost') 
    ? "http://localhost:5001" 
    // Production environment (deployed)
    : process.env.NEXT_PUBLIC_API_URL || "/api";

// Log the API URL being used (only in development)
if (process.env.NODE_ENV !== 'production' && typeof window !== 'undefined') {
  console.log(`Using API URL: ${API_BASE_URL}`);
}

/**
 * Initiates an integrated vulnerability scan
 */
export const startIntegratedScan = async (
  target: string, 
  options: {
    ports?: string;
    scan_type?: "basic" | "deep";
    intensity?: "stealthy" | "normal" | "aggressive"; // kept for backwards compatibility
    format?: "html" | "text" | "json";
    env?: "dev" | "test" | "prod";
  }
) => {
  const response = await fetch(`${API_BASE_URL}/scan/integrated`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      target,
      ...options
    }),
  });
  
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Failed to start scan: ${response.status} ${response.statusText} - ${errorText}`);
  }
  
  return response.json();
};

/**
 * Fetches the status of an integrated scan
 */
export const fetchScanStatus = async (target: string) => {
  const response = await fetch(`${API_BASE_URL}/scan/integrated/status?target=${encodeURIComponent(target)}`);
  if (!response.ok) {
    throw new Error(`Failed to fetch scan status: ${response.statusText}`);
  }
  return response.json();
};

/**
 * Fetches all available environment configurations
 */
export const fetchEnvironmentConfigs = async () => {
  const response = await fetch(`${API_BASE_URL}/environment/config`);
  if (!response.ok) {
    throw new Error(`Failed to fetch environments: ${response.statusText}`);
  }
  return response.json();
};

/**
 * Fetches all available scan reports
 */
export const fetchReports = async (timeFilter?: string) => {
  const url = timeFilter 
    ? `${API_BASE_URL}/reports?timeframe=${encodeURIComponent(timeFilter)}` 
    : `${API_BASE_URL}/reports`;
    
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to fetch reports: ${response.statusText}`);
  }
  return response.json();
};

/**
 * Fetches a specific report by ID
 */
export const fetchReportById = async (reportId: string) => {
  const response = await fetch(`${API_BASE_URL}/reports/${encodeURIComponent(reportId)}`);
  if (!response.ok) {
    throw new Error(`Failed to fetch report: ${response.statusText}`);
  }
  return response.json();
};

/**
 * Fetches ML predictions for a specific scan
 */
export const fetchMLPredictions = async (scanId: string) => {
  const response = await fetch(`${API_BASE_URL}/ml/predictions?scanId=${encodeURIComponent(scanId)}`);
  if (!response.ok) {
    throw new Error(`Failed to fetch ML predictions: ${response.statusText}`);
  }
  return response.json();
};

/**
 * Fetches remediation recommendations for a vulnerability
 */
export const fetchRemediationRecommendations = async (vulnerabilityId: string, options?: { detailed?: boolean }) => {
  const url = options?.detailed 
    ? `${API_BASE_URL}/remediation/${encodeURIComponent(vulnerabilityId)}?detailed=true` 
    : `${API_BASE_URL}/remediation/${encodeURIComponent(vulnerabilityId)}`;
    
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to fetch remediation recommendations: ${response.statusText}`);
  }
  return response.json();
};

/**
 * Fetches financial impact assessment for a scan
 */
export const fetchFinancialImpact = async (scanId: string) => {
  const response = await fetch(`${API_BASE_URL}/financial-impact?scanId=${encodeURIComponent(scanId)}`);
  if (!response.ok) {
    throw new Error(`Failed to fetch financial impact: ${response.statusText}`);
  }
  return response.json();
};

/**
 * Exports a report in the specified format
 */
export const exportReport = async (reportId: string, format: "pdf" | "csv" | "json") => {
  const response = await fetch(`${API_BASE_URL}/reports/${encodeURIComponent(reportId)}/export?format=${format}`);
  if (!response.ok) {
    throw new Error(`Failed to export report: ${response.statusText}`);
  }
  
  // Handle different export formats
  if (format === "json") {
    return response.json();
  } else {
    return response.blob();
  }
};

/**
 * Fetches ML model statistics
 */
export const fetchModelStats = async () => {
  const response = await fetch(`${API_BASE_URL}/ml/model-stats`);
  if (!response.ok) {
    throw new Error(`Failed to fetch ML model stats: ${response.statusText}`);
  }
  return response.json();
};
