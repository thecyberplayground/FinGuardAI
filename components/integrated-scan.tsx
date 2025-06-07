"use client"

import { useState, useEffect } from "react"
import { API_BASE_URL } from "@/app/services/api"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { CircularProgress } from "@/components/circular-progress"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { MLPredictionDisplay } from "@/components/ml-prediction-display"
import { FinancialImpactDisplay } from "@/components/financial-impact-display"
import { AlertCircle, Check, Info, Loader2 } from "lucide-react"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"

// Import useScanSocket hook
import { useScanSocket } from "@/hooks/use-scan-socket"

// Define the Prediction interface expected by MLPredictionDisplay
interface Prediction {
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

// Import API services
import { fetchEnvironmentConfigs } from "@/app/services/api"

interface EnvConfig {
  ports: string;
  scan_type: string; // Changed intensity to scan_type for consistency
  format: string;
  [key: string]: any;
}

interface EnvironmentConfigs {
  [key: string]: EnvConfig;
}

interface IntegratedScanProps {
  className?: string
}

// Helper function to convert MLPrediction to Prediction format
const convertMLPredictionsToDisplayFormat = (mlPredictions: any[]): Prediction[] => {
  if (!mlPredictions || !Array.isArray(mlPredictions)) return [];
  
  return mlPredictions.map((prediction, index) => ({
    id: prediction.id || `pred-${index}`,
    type: prediction.type || 'vulnerability',
    name: prediction.recommendation || prediction.name || 'Unknown Prediction',
    confidence: prediction.confidence || 0,
    severity: prediction.severity || 'medium',
    description: prediction.description || prediction.recommendation || '',
    remediation: prediction.remediation || '',
    impact: prediction.impact || '',
    cve: prediction.cve_id || '',
    financialImpact: prediction.financial_impact ? {
      estimatedCost: prediction.financial_impact.estimated_cost || 0,
      recoveryTime: prediction.financial_impact.recovery_time || 'Unknown',
      businessRisk: prediction.financial_impact.business_risk || 'Unknown'
    } : undefined
  }));
};

export function IntegratedScan({ className }: IntegratedScanProps) {
  // Use the scan socket hook
  const {
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
    startScan: startSocketScan,
    cancelScan
  } = useScanSocket();
  
  // Form state
  const [target, setTarget] = useState<string>("");
  const [environment, setEnvironment] = useState<string>("prod");
  const [portRange, setPortRange] = useState<string>("1-1000");
  const [scanType, setScanType] = useState<string>("basic"); // Changed from intensity to scan_type
  const [reportFormat, setReportFormat] = useState<string>("json");
  
  // Environment config state
  const [envConfigs, setEnvConfigs] = useState<EnvironmentConfigs>({});
  const [loadingEnvConfigs, setLoadingEnvConfigs] = useState<boolean>(false);
  
  // UI state
  const [activeTab, setActiveTab] = useState<string>("logs");
  const [scanStartTime, setScanStartTime] = useState<string>("");
  
  // Derive scan completed state from hook data
  const scanCompleted = !isScanning && (scanProgress >= 100 || scanReport !== null);

  // Load environment configurations
  useEffect(() => {
    async function loadEnvironmentConfigs() {
      try {
        setLoadingEnvConfigs(true);
        const configs = await fetchEnvironmentConfigs();
        setEnvConfigs(configs);
        
        // Set initial values if available
        if (configs && configs[environment]) {
          setPortRange(configs[environment].ports || "1-1000");
          setScanType(configs[environment].scan_type || "basic");
          setReportFormat(configs[environment].format || "json");
        }
      } catch (error) {
        console.error("Failed to load environment configurations:", error);
      } finally {
        setLoadingEnvConfigs(false);
      }
    }

    loadEnvironmentConfigs();
  }, [environment]);

  // Update configuration when environment changes
  useEffect(() => {
    if (envConfigs && envConfigs[environment]) {
      setPortRange(envConfigs[environment].ports || "1-1000");
      setScanType(envConfigs[environment].scan_type || "basic");
      setReportFormat(envConfigs[environment].format || "json");
    }
  }, [environment, envConfigs]);
  
  // Function to start a scan
  const handleStartScan = () => {
    if (!target) {
      return;
    }
    
    setScanStartTime(new Date().toISOString());
    setActiveTab("logs");
    
    // Process target to ensure proper format
    let processedTarget = target.trim();
    if (!processedTarget.startsWith('http://') && !processedTarget.startsWith('https://')) {
      if (processedTarget.includes('.') && !processedTarget.includes(' ')) {
        processedTarget = `http://${processedTarget}`;
      }
    }
    
    // Call our hook's startScan with the environment context
    startSocketScan(processedTarget, {
      ports: portRange || "1-1000",
      scan_type: scanType || "basic", // Using scanType consistently
      format: reportFormat || "json",
      environment: environment || "prod"
    });
  };
  
  // Function to handle canceling a scan
  const handleCancelScan = () => {
    cancelScan();
  };

  return (
    <Card className={className}>
      <CardHeader>
        <CardTitle>Integrated Vulnerability Scan</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="target">Target (IP or Domain)</Label>
              <Input
                id="target"
                placeholder="e.g., 192.168.1.1 or example.com"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                disabled={isScanning}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="environment">Environment</Label>
              <Select
                value={environment}
                onValueChange={setEnvironment}
                disabled={isScanning || loadingEnvConfigs}
              >
                <SelectTrigger id="environment">
                  <SelectValue placeholder="Select environment" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="dev">Development</SelectItem>
                  <SelectItem value="test">Testing</SelectItem>
                  <SelectItem value="prod">Production</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          
          <div className="flex flex-wrap gap-4">
            <div className="space-y-2 flex-1">
              <Label htmlFor="ports">Port Range</Label>
              <Input
                id="ports"
                placeholder="e.g., 1-1000"
                value={portRange}
                onChange={(e) => setPortRange(e.target.value)}
                disabled={isScanning || loadingEnvConfigs}
              />
            </div>
            <div className="space-y-2 flex-1">
              <Label htmlFor="scan-type">Scan Type</Label>
              <Select
                value={scanType}
                onValueChange={setScanType}
                disabled={isScanning}
              >
                <SelectTrigger id="scan-type">
                  <SelectValue placeholder="Select scan type" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="basic">Basic</SelectItem>
                  <SelectItem value="deep">Deep</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2 flex-1">
              <Label htmlFor="format">Report Format</Label>
              <Select
                value={reportFormat}
                onValueChange={setReportFormat}
                disabled={isScanning || loadingEnvConfigs}
              >
                <SelectTrigger id="format">
                  <SelectValue placeholder="Select format" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="json">JSON</SelectItem>
                  <SelectItem value="html">HTML</SelectItem>
                  <SelectItem value="xml">XML</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="flex justify-end space-x-2 pt-2">
            {isScanning ? (
              <Button 
                variant="destructive" 
                onClick={handleCancelScan}
              >
                Cancel Scan
              </Button>
            ) : (
              <Button 
                onClick={handleStartScan} 
                disabled={!target || loadingEnvConfigs}
              >
                {isScanning ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Scanning...
                  </>
                ) : "Start Scan"}
              </Button>
            )}
          </div>
        </div>

        {scanError && (
          <Alert variant="destructive" className="mt-4">
            <AlertCircle className="h-4 w-4" />
            <AlertTitle>Error</AlertTitle>
            <AlertDescription>{scanError}</AlertDescription>
          </Alert>
        )}

        {isScanning && (
          <div className="flex flex-col items-center gap-4 p-4 mt-4">
            <CircularProgress value={scanProgress ? Number(scanProgress) : 0} size={160} />
            <div className="text-center">
              <p className="text-sm text-muted-foreground">
                {currentPhase ? (
                  <>
                    Phase: {currentPhase} - {phaseProgress && typeof phaseProgress[currentPhase] === 'number' ? phaseProgress[currentPhase] : 0}% complete
                    <br />
                    Overall progress: {scanProgress || 0}%
                  </>
                ) : (
                  <>Scanning {target}... ({scanProgress || 0}% complete)</>
                )}
              </p>
            </div>
          </div>
        )}

        {(isScanning || scanCompleted) && (
          <Tabs defaultValue={activeTab} onValueChange={setActiveTab} className="w-full mt-4">
            <TabsList className="grid w-full grid-cols-3">
              <TabsTrigger value="logs">Scan Logs</TabsTrigger>
              <TabsTrigger value="ml" disabled={!mlPredictions || mlPredictions.length === 0}>
                ML Predictions
              </TabsTrigger>
              <TabsTrigger value="financial" disabled={!financialImpact}>
                Financial Impact
              </TabsTrigger>
            </TabsList>
            
            <TabsContent value="logs" className="mt-4">
              <div className="rounded-md border p-4">
                <h3 className="text-sm font-medium mb-2">Scan Log</h3>
                <div className="bg-muted rounded-md p-2 max-h-[300px] overflow-auto">
                  {scanResult && scanResult.map((log: any, index: number) => (
                    <div key={index} className="text-xs font-mono py-0.5">
                      {typeof log === 'object' && log !== null ? JSON.stringify(log) : log === null || log === undefined ? "" : String(log)}
                    </div>
                  ))}
                  {(!scanResult || scanResult.length === 0) && (
                    <div className="text-xs font-mono py-0.5">No logs available yet...</div>
                  )}
                </div>
              </div>
              
              {scanReport && (
                <div className="mt-4 border rounded-md p-4">
                  <h3 className="font-medium mb-2">Scan Report</h3>
                  <div className="mt-4">
                    <Button 
                      variant="outline" 
                      size="sm"
                      onClick={() => {
                        // Ensure we have a valid report ID format
                        const reportId = scanReport.reportId || scanReport.id;
                        console.log('Opening report with ID:', reportId);
                        window.open(`${API_BASE_URL}/reports/${reportId}?format=html`, '_blank');
                      }}
                    >
                      View Full Report
                    </Button>
                  </div>
                </div>
              )}
            </TabsContent>
            
            <TabsContent value="ml" className="mt-4">
              {mlPredictions && Array.isArray(mlPredictions) && mlPredictions.length > 0 ? (
                <MLPredictionDisplay 
                  predictions={convertMLPredictionsToDisplayFormat(mlPredictions || [])}
                  modelAccuracy={0.85}
                  scanTime={scanStartTime ? `Scan started: ${new Date(scanStartTime).toLocaleString()}` : ""}
                  isLoading={isScanning}
                />
              ) : (
                <div className="p-4 text-center text-muted-foreground">
                  {isScanning ? "Waiting for ML predictions..." : "No ML predictions available"}
                </div>
              )}
            </TabsContent>
            
            <TabsContent value="financial" className="mt-4">
              {financialImpact && Array.isArray(financialImpact) && financialImpact.length > 0 ? (
                <FinancialImpactDisplay 
                  financialImpacts={financialImpact}
                  scanTarget={target}
                  scanDate={scanStartTime ? new Date(scanStartTime).toLocaleString() : ""}
                  isLoading={isScanning}
                  industryBenchmark={0.78}
                />
              ) : (
                <div className="p-4 text-center text-muted-foreground">
                  {isScanning ? "Calculating financial impact..." : "No financial impact data available"}
                </div>
              )}
            </TabsContent>
          </Tabs>
        )}
      </CardContent>
    </Card>
  );
}