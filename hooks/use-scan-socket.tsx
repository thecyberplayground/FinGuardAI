import { useState, useRef, useEffect } from "react";
import { io, Socket } from "socket.io-client";

// Types for vulnerability data and scan results
export interface Vulnerability {
  id?: string;
  name: string;
  severity: "critical" | "high" | "medium" | "low" | "unknown";
  description: string;
  port?: string;
  service?: string;
  cve_id?: string;
  cvss_score?: number;
  affected_component: string;
  remediation?: string;
  confidence?: number;
}

interface FinancialImpact {
  total_cost: number;
  breakdown: {
    [key: string]: number;
  };
  currency: string;
}

interface MLPrediction {
  confidence: number;
  severity: string;
  recommendation: string;
}

interface ScanPhase {
  phase: string;
  progress: number;
  message: string;
  timestamp: string;
}

interface ScanReport {
  reportId: string;
  htmlReportPath: string;
  jsonReportPath: string;
}

interface ScanSocketState {
  isScanning: boolean;
  scanProgress: number;
  currentPhase: string;
  phaseProgress: Record<string, number>;
  scanResult: string[];
  vulnerabilities: Vulnerability[];
  financialImpact?: FinancialImpact;
  mlPredictions?: MLPrediction[];
  scanReport?: ScanReport;
  scanError: string | null;
  startScan: (target: string, scanParams?: { ports?: string, intensity?: string, scan_type?: string, format?: string, environment?: string }) => void;
  cancelScan: () => void;
}

export function useScanSocket(): ScanSocketState {
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [currentPhase, setCurrentPhase] = useState<string>("");
  const [phaseProgress, setPhaseProgress] = useState<Record<string, number>>({});
  const [scanResult, setScanResult] = useState<string[]>([]);
  const [scanError, setScanError] = useState<string | null>(null);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [financialImpact, setFinancialImpact] = useState<FinancialImpact | undefined>(undefined);
  const [mlPredictions, setMlPredictions] = useState<MLPrediction[] | undefined>(undefined);
  const [scanReport, setScanReport] = useState<ScanReport | undefined>(undefined);
  const socketRef = useRef<Socket | null>(null);

  const startScan = (target: string, scanParams: { ports?: string, scan_type?: string, intensity?: string, format?: string, environment?: string } = {}) => {
    if (!target) {
      setScanError("Please enter a target IP or hostname.");
      return;
    }
    
    // Reset all state for a new scan
    setIsScanning(true);
    setScanProgress(0);
    setCurrentPhase("Initializing");
    setPhaseProgress({});
    setScanResult([]);
    setScanError(null);
    setVulnerabilities([]);
    setFinancialImpact(undefined);
    setMlPredictions(undefined);
    setScanReport(undefined);

    // Disconnect any existing socket
    if (socketRef.current) {
      socketRef.current.disconnect();
    }
    
    // Connect to the socket server
    const socket = io("http://127.0.0.1:5001"); // Updated port to match backend
    socketRef.current = socket;

    // Start the scan with parameters
    const environment = scanParams.environment || "prod";
    const scanType = scanParams.scan_type || "basic"; // Use scan_type parameter, default to basic
    const ports = scanParams.ports || "1-1000";
    const format = scanParams.format || "json";
  
    socket.emit("start_scan", {
      target,
      scan_type: scanType, // This will now be 'basic' or 'deep'
      environment,
      ports,
      format
    });
    
    // Handle scan events
    socket.on("scan_progress", (data) => {
      // Handle overall progress updates
      if (typeof data.overall_progress === "number") {
        setScanProgress(data.overall_progress);
      }
      
      // Handle phase updates
      if (data.phase) {
        setCurrentPhase(data.phase);
        // Update phase progress - ensure we have a valid number
        const phaseProgressValue = typeof data.phase_progress === 'number' ? data.phase_progress : 0;
        setPhaseProgress(prev => ({
          ...prev,
          [data.phase]: phaseProgressValue
        }));
        
        // Add phase message to scan results if provided
        if (data.message) {
          setScanResult(prev => [...prev, `[${data.phase}] ${data.message}`]);
        }
      }
    });
    
    // Handle vulnerability data
    socket.on("vulnerability_data", (data) => {
      if (data.vulnerabilities && Array.isArray(data.vulnerabilities)) {
        setVulnerabilities(data.vulnerabilities);
      }
    });
    
    // Handle ML predictions
    socket.on("ml_results", (data) => {
      // Handle confidence scores and ML predictions
      if (data.predictions && Array.isArray(data.predictions)) {
        setMlPredictions(data.predictions);
      }
      
      // Handle financial impact assessment
      if (data.financial_impact) {
        setFinancialImpact(data.financial_impact);
      }
    });
    
    // Handle report generation
    socket.on("report_generated", (data) => {
      if (data.report_id && data.html_path && data.json_path) {
        setScanReport({
          reportId: data.report_id,
          htmlReportPath: data.html_path,
          jsonReportPath: data.json_path
        });
      }
    });
    
    // Handle scan completion
    socket.on("scan_complete", (data) => {
      setIsScanning(false);
      setScanProgress(100);
      setCurrentPhase("Complete");
      
      // Add completion message to scan results
      setScanResult(prev => [...prev, "[COMPLETE] Scan completed successfully"]);
      
      // Automatically disconnect after scan completion
      socket.disconnect();
    });
    
    // Handle scan errors
    socket.on("scan_error", (data) => {
      setScanError(data.error || "Unknown error occurred during scan");
      setIsScanning(false);
      
      // Add error message to scan results
      setScanResult(prev => [...prev, `[ERROR] ${data.error}`]);
      
      // Automatically disconnect after error
      socket.disconnect();
    });
    
    // Handle basic output lines (backwards compatibility)
    socket.on("scan_output", (data) => {
      if (data.line) {
        // Ensure we only add strings to the scanResult array
        const lineValue = typeof data.line === 'object' ? 
          (data.line === null ? 'null' : JSON.stringify(data.line)) : 
          String(data.line || '');
        setScanResult((prev) => [...prev, lineValue]);
      }
      
      // Handle progress updates for backwards compatibility
      if (typeof data.progress === "number") {
        setScanProgress(data.progress);
      }
      
      // Legacy scan completion
      if (data.line === "SCAN_COMPLETE") {
        setIsScanning(false);
        setScanProgress(100);
        setCurrentPhase("Complete");
        socket.disconnect();
      }
    });
    
    socket.on("disconnect", () => {
      setIsScanning(false);
    });
  };

  // Cleanup function for socket
  useEffect(() => {
    return () => {
      if (socketRef.current) {
        socketRef.current.disconnect();
      }
    };
  }, []);
  
  // Function to cancel an ongoing scan
  const cancelScan = () => {
    if (socketRef.current) {
      socketRef.current.emit("cancel_scan");
      socketRef.current.disconnect();
    }
    setIsScanning(false);
    setScanProgress(0);
    setCurrentPhase("Cancelled");
    
    // Add cancellation message to scan results
    setScanResult(prev => [...prev, "[CANCELLED] Scan cancelled by user"]);
  };

  return { 
    isScanning, 
    scanProgress, 
    currentPhase,
    phaseProgress,
    scanResult, 
    vulnerabilities,
    financialImpact,
    mlPredictions,
    scanReport,
    scanError, 
    startScan,
    cancelScan
  };
}
