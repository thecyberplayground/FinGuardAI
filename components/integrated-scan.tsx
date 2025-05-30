"use client"

import { useState, useEffect, useCallback } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { CircularProgress } from "@/components/circular-progress"
import { StatusLog } from "@/components/status-log"
import { io, Socket } from "socket.io-client"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { MLPredictionDisplay } from "@/components/ml-prediction-display"
import { FinancialImpactDisplay } from "@/components/financial-impact-display"
import { AlertCircle, Check, Info, Loader2 } from "lucide-react"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"

// Import API services
import { 
  startIntegratedScan, 
  fetchScanStatus, 
  fetchEnvironmentConfigs, 
  fetchMLPredictions, 
  fetchFinancialImpact 
} from "@/app/services/api"

interface EnvConfig {
  ports: string;
  intensity: string;
  format: string;
  [key: string]: any;
}

interface EnvironmentConfigs {
  [key: string]: EnvConfig;
}

interface IntegratedScanProps {
  className?: string
}

// Define ML prediction and financial impact types
interface MLPrediction {
  id: string;
  type: string;
  name: string;
  confidence: number;
  severity: "critical" | "high" | "medium" | "low";
  description: string;
  impact?: string;
  cve?: string;
  remediation?: string;
  financialImpact?: {
    estimatedCost: number;
    recoveryTime: string;
    businessRisk: string;
  };
}

interface FinancialImpactItem {
  id: string;
  category: string;
  name: string;
  estimatedCost: number;
  recoveryTime: string;
  businessRisk: "critical" | "high" | "medium" | "low";
  description: string;
  relatedVulnerability?: string;
  mitigationCost?: number;
  regulatoryImpact?: string;
}

export function IntegratedScan({ className }: IntegratedScanProps) {
  // Basic scan state
  const [target, setTarget] = useState<string>("");
  const [scanInProgress, setScanInProgress] = useState<boolean>(false);
  const [scanCompleted, setScanCompleted] = useState<boolean>(false);
  const [scanProgress, setScanProgress] = useState<number>(0);
  const [logs, setLogs] = useState<string[]>([]);
  const [environment, setEnvironment] = useState<string>("prod");
  const [portRange, setPortRange] = useState<string>("1-1000");
  const [intensity, setIntensity] = useState<string>("normal");
  const [reportFormat, setReportFormat] = useState<string>("json");
  const [socket, setSocket] = useState<Socket | null>(null);
  const [error, setError] = useState<string | null>(null);
  
  // Environment config state
  const [envConfigs, setEnvConfigs] = useState<EnvironmentConfigs>({});
  const [loadingEnvConfigs, setLoadingEnvConfigs] = useState<boolean>(false);
  
  // ML and financial impact state
  const [scanId, setScanId] = useState<string>("");
  const [scanResults, setScanResults] = useState<any>(null);
  const [activeTab, setActiveTab] = useState<string>("logs");
  const [mlPredictions, setMlPredictions] = useState<MLPrediction[]>([]);
  const [financialImpacts, setFinancialImpacts] = useState<FinancialImpactItem[]>([]);
  const [modelAccuracy, setModelAccuracy] = useState<number>(0);
  const [industryBenchmark, setIndustryBenchmark] = useState<number>(0);
  const [loadingMlData, setLoadingMlData] = useState<boolean>(false);
  const [scanStartTime, setScanStartTime] = useState<string>("");
  const [scanFinishTime, setScanFinishTime] = useState<string>("");

  // Helper function to add log messages
  const addLog = useCallback((message: string) => {
    setLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] ${message}`]);
  }, []);

  // Connect to Socket.IO server when component mounts
  useEffect(() => {
    // Use the same API_BASE_URL from our API service
    const socketUrl = typeof window !== 'undefined' && window.location.hostname === 'localhost'
      ? "http://localhost:5001"
      : process.env.NEXT_PUBLIC_API_URL || "";
      
    const newSocket = io(socketUrl);

    newSocket.on("connect", () => {
      addLog("Connected to server");
    });

    newSocket.on("disconnect", () => {
      addLog("Disconnected from server");
    });

    newSocket.on("scan_progress", (data) => {
      setScanProgress(data.progress);
      addLog(`Scan progress: ${data.progress}% - ${data.message || ""}`);
      
      if (data.progress === 100) {
        setScanInProgress(false);
        setScanCompleted(true);
        setScanFinishTime(new Date().toISOString());
        addLog("Scan completed");
        fetchScanResults(target);
      }
    });

    newSocket.on("scan_error", (data) => {
      setError(data.message);
      setScanInProgress(false);
      addLog(`Scan error: ${data.message}`);
    });

    // ML prediction events
    newSocket.on("ml_prediction", (data) => {
      addLog(`ML Prediction received: ${data.prediction_type}`);
      // Update UI with new ML prediction data
      fetchMLData(scanId);
    });

    // Vulnerability detected event
    newSocket.on("vulnerability_detected", (data) => {
      addLog(`Vulnerability detected: ${data.name} (${data.severity})`);
    });

    setSocket(newSocket);

    return () => {
      newSocket.disconnect();
    };
  }, [addLog, target, scanId]);

  // Fetch environment configurations on mount
  useEffect(() => {
    const loadEnvironmentConfigs = async () => {
      try {
        setLoadingEnvConfigs(true);
        addLog("Fetching environment configurations...");
        const configs = await fetchEnvironmentConfigs();
        setEnvConfigs(configs);
        
        // Set default configuration based on selected environment
        if (configs[environment]) {
          setPortRange(configs[environment].ports || "1-1000");
          setIntensity(configs[environment].intensity || "normal");
          setReportFormat(configs[environment].format || "json");
        }
        
        addLog("Environment configurations loaded");
      } catch (error) {
        setError(`Failed to load environment configurations: ${error instanceof Error ? error.message : String(error)}`);
        addLog(`Error loading environment configurations: ${error instanceof Error ? error.message : String(error)}`);
      } finally {
        setLoadingEnvConfigs(false);
      }
    };

    loadEnvironmentConfigs();
  }, [addLog]);

  // Update configuration when environment changes
  useEffect(() => {
    if (envConfigs && envConfigs[environment]) {
      setPortRange(envConfigs[environment].ports || "1-1000");
      setIntensity(envConfigs[environment].intensity || "normal");
      setReportFormat(envConfigs[environment].format || "json");
      addLog(`Environment switched to: ${environment}`);
    }
  }, [environment, envConfigs, addLog]);

  // Fetch scan results
  const fetchScanResults = async (targetHost: string) => {
    try {
      addLog(`Fetching scan results for ${targetHost}...`);
      const results = await fetchScanStatus(targetHost);
      setScanResults(results);
      setScanId(results.scan_id || "");
      
      if (results.scan_id) {
        fetchMLData(results.scan_id);
      }
      
      addLog("Scan results retrieved successfully");
    } catch (error) {
      setError(`Failed to fetch scan results: ${error instanceof Error ? error.message : String(error)}`);
      addLog(`Error fetching scan results: ${error instanceof Error ? error.message : String(error)}`);
    }
  };

  // Fetch ML predictions and financial impact data
  const fetchMLData = async (currentScanId: string) => {
    if (!currentScanId) return;
    
    try {
      setLoadingMlData(true);
      addLog("Fetching ML predictions...");
      
      // Fetch ML predictions
      const predictions = await fetchMLPredictions(currentScanId);
      setMlPredictions(predictions.items || []);
      setModelAccuracy(predictions.model_accuracy || 0);
      
      // Fetch financial impact data
      const financialData = await fetchFinancialImpact(currentScanId);
      setFinancialImpacts(financialData.impacts || []);
      setIndustryBenchmark(financialData.industry_benchmark || 0);
      
      addLog("ML data retrieved successfully");
    } catch (error) {
      addLog(`Error fetching ML data: ${error instanceof Error ? error.message : String(error)}`);
    } finally {
      setLoadingMlData(false);
    }
  };

  // Start a scan
  const startScan = async () => {
    if (!target) {
      setError("Please enter a target to scan");
      return;
    }

    // Validate target format
    let processedTarget = target.trim();
    
    // Simple URL validation
    if (!processedTarget.startsWith('http://') && !processedTarget.startsWith('https://')) {
      // If it's just a domain without protocol, add http:// prefix
      if (processedTarget.includes('.') && !processedTarget.includes(' ')) {
        processedTarget = `http://${processedTarget}`;
        addLog(`Added http:// prefix to ${target} for scanning`);
      }
    }

    try {
      setError(null);
      setScanInProgress(true);
      setScanCompleted(false);
      setScanProgress(0);
      setScanResults(null);
      setMlPredictions([]);
      setFinancialImpacts([]);
      setLogs([]);
      setActiveTab("logs");
      setScanStartTime(new Date().toISOString());
      
      addLog(`Starting scan of ${processedTarget} in ${environment} environment...`);
      addLog(`Scan configuration: ports=${portRange}, intensity=${intensity}, format=${reportFormat}`);
      
      const startTime = Date.now();
      const response = await startIntegratedScan(processedTarget, {
        ports: portRange,
        intensity: intensity as "stealthy" | "normal" | "aggressive",
        format: reportFormat as "html" | "text" | "json",
        env: environment as "dev" | "test" | "prod"
      });
      const endTime = Date.now();
      
      addLog(`API response received in ${(endTime - startTime) / 1000} seconds`);
      
      if (response.status === "error") {
        throw new Error(`API returned error: ${response.error || 'Unknown error'}`);
      }
      
      setScanId(response.scan_id || "");
      addLog(`Scan initiated with ID: ${response.scan_id || response.scanId || 'N/A'}`);
      
      if (response.processed_target) {
        addLog(`Target processed as: ${response.processed_target}`);
      }
      
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : String(error);
      setError(`Failed to start scan: ${errorMsg}`);
      addLog(`Error starting scan: ${errorMsg}`);
      addLog(`Detailed error info: ${JSON.stringify(error)}`); 
      setScanInProgress(false);
    }
  };

  return (
    <Card className={className}>
      <CardHeader>
        <CardTitle>Integrated Vulnerability Scan</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            <div className="flex flex-col gap-2 md:col-span-2 lg:col-span-1">
              <Label htmlFor="target">Target</Label>
              <Input
                id="target"
                placeholder="IP address or hostname"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                disabled={scanInProgress}
              />
            </div>

            <div className="flex flex-col gap-2">
              <Label htmlFor="environment">Environment</Label>
              <Select 
                value={environment} 
                onValueChange={setEnvironment}
                disabled={scanInProgress || loadingEnvConfigs}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select Environment" />
                </SelectTrigger>
                <SelectContent>
                  {Object.keys(envConfigs).map((env) => (
                    <SelectItem key={env} value={env}>
                      {env.charAt(0).toUpperCase() + env.slice(1)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="flex flex-col gap-2">
              <Label htmlFor="scan-type">Scan Intensity</Label>
              <Select 
                value={intensity} 
                onValueChange={setIntensity}
                disabled={scanInProgress}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select Scan Intensity" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="stealthy">Stealthy</SelectItem>
                  <SelectItem value="normal">Normal</SelectItem>
                  <SelectItem value="aggressive">Aggressive</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="flex flex-col gap-2">
              <Label htmlFor="port-range">Port Range</Label>
              <Input
                id="port-range"
                placeholder="e.g., 80,443,8080-8090"
                value={portRange}
                onChange={(e) => setPortRange(e.target.value)}
                disabled={scanInProgress}
              />
            </div>

            <div className="flex flex-col gap-2">
              <Label htmlFor="report-format">Report Format</Label>
              <Select 
                value={reportFormat} 
                onValueChange={setReportFormat}
                disabled={scanInProgress}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select Format" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="html">HTML</SelectItem>
                  <SelectItem value="text">Text</SelectItem>
                  <SelectItem value="json">JSON</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="flex items-end">
              <Button 
                className="w-full" 
                onClick={startScan} 
                disabled={scanInProgress || !target}
              >
                {scanInProgress ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Scanning...
                  </>
                ) : "Start Scan"}
              </Button>
            </div>
          </div>

          {error && (
            <Alert variant="destructive">
              <AlertCircle className="h-4 w-4" />
              <AlertTitle>Error</AlertTitle>
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}

          {scanInProgress && (
            <div className="flex flex-col items-center gap-4 p-4">
              <CircularProgress value={Number(scanProgress)} size="lg" />
              <div className="text-center">
                <p className="text-sm text-muted-foreground">
                  Scanning {target}... ({scanProgress}% complete)
                </p>
              </div>
            </div>
          )}

          {(scanInProgress || scanCompleted) && (
            <Tabs defaultValue={activeTab} onValueChange={setActiveTab} className="w-full">
              <TabsList className="grid w-full grid-cols-3">
                <TabsTrigger value="logs">Scan Logs</TabsTrigger>
                <TabsTrigger value="ml" disabled={mlPredictions.length === 0 && !loadingMlData}>
                  ML Predictions {loadingMlData && <Loader2 className="ml-2 h-3 w-3 animate-spin" />}
                </TabsTrigger>
                <TabsTrigger value="financial" disabled={financialImpacts.length === 0 && !loadingMlData}>
                  Financial Impact
                </TabsTrigger>
              </TabsList>
              
              <TabsContent value="logs" className="mt-4">
                <div className="rounded-md border p-4">
                  <h3 className="text-sm font-medium mb-2">Scan Log</h3>
                  <div className="bg-muted rounded-md p-2 max-h-[300px] overflow-auto">
                    {logs.map((log, index) => (
                      <div key={index} className="text-xs font-mono py-0.5">
                        {log}
                      </div>
                    ))}
                  </div>
                </div>
                
                {scanResults && (
                  <div className="mt-4 border rounded-md p-4">
                    <h3 className="font-medium mb-2">Scan Results</h3>
                    <pre className="text-xs bg-muted p-2 rounded overflow-auto max-h-[300px]">
                      {JSON.stringify(scanResults, null, 2)}
                    </pre>
                    
                    {scanResults.report_path && (
                      <div className="mt-4">
                        <Button 
                          variant="outline" 
                          size="sm"
                          onClick={() => window.open(`/reports/${scanResults.report_path}`, '_blank')}
                        >
                          View Full Report
                        </Button>
                      </div>
                    )}
                  </div>
                )}
              </TabsContent>
              
              <TabsContent value="ml" className="mt-4">
                <MLPredictionDisplay 
                  predictions={mlPredictions}
                  modelAccuracy={modelAccuracy}
                  scanTime={scanStartTime ? `Scan started: ${new Date(scanStartTime).toLocaleString()}` : ""}
                  isLoading={loadingMlData}
                />
              </TabsContent>
              
              <TabsContent value="financial" className="mt-4">
                <FinancialImpactDisplay 
                  financialImpacts={financialImpacts}
                  scanTarget={target}
                  scanDate={scanStartTime ? new Date(scanStartTime).toLocaleString() : ""}
                  isLoading={loadingMlData}
                  industryBenchmark={industryBenchmark}
                />
              </TabsContent>
            </Tabs>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
