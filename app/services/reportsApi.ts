/**
 * FinGuardAI Reports API Service
 * 
 * Provides functions for interacting with the reports-related endpoints
 */

import { API_BASE_URL } from "./api";

export interface Report {
  id: string;
  target: string;
  date: string;
  severity: "critical" | "high" | "medium" | "low";
  vulnerabilities_count: number;
  environment: string;
  report_path?: string;
  scan_id?: string;
}

export interface ReportDetail {
  id: string;
  target: string;
  date: string;
  severity: "critical" | "high" | "medium" | "low";
  environment: string;
  scan_id: string;
  vulnerabilities: Vulnerability[];
  summary: {
    critical_count: number;
    high_count: number;
    medium_count: number;
    low_count: number;
    total_count: number;
    estimated_fix_time: string;
    estimated_financial_impact: number;
  };
}

export interface Vulnerability {
  id: string;
  name: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low";
  cve?: string;
  cvss_score?: number;
  affected_component: string;
  remediation?: string;
}

export interface RemediationRecommendation {
  id: string;
  vulnerability_id: string;
  recommendation: string;
  difficulty: "easy" | "medium" | "hard";
  estimated_time: string;
  code_example?: string;
  references?: string[];
  priority: "critical" | "high" | "medium" | "low";
  cost_of_inaction: number;
}

/**
 * Fetches all available scan reports
 */
export const fetchReports = async (timeFilter?: string): Promise<Report[]> => {
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
export const fetchReportById = async (reportId: string): Promise<ReportDetail> => {
  const response = await fetch(`${API_BASE_URL}/reports/${encodeURIComponent(reportId)}`);
  if (!response.ok) {
    throw new Error(`Failed to fetch report: ${response.statusText}`);
  }
  return response.json();
};

/**
 * Fetches remediation recommendations for a vulnerability
 */
export const fetchRemediationRecommendations = async (
  vulnerabilityId: string, 
  options?: { detailed?: boolean }
): Promise<RemediationRecommendation> => {
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
