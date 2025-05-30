"use client"

import { useState } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Progress } from "@/components/ui/progress"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Brain, AlertTriangle, ShieldAlert, DollarSign } from "lucide-react"

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

interface MLPredictionDisplayProps {
  predictions: Prediction[];
  modelAccuracy?: number;
  scanTime?: string;
  isLoading?: boolean;
}

export function MLPredictionDisplay({
  predictions = [],
  modelAccuracy = 0,
  scanTime = "",
  isLoading = false,
}: MLPredictionDisplayProps) {
  const [activeTab, setActiveTab] = useState("vulnerabilities");

  // Group predictions by type
  const vulnerabilities = predictions.filter(p => p.type === "vulnerability");
  const threats = predictions.filter(p => p.type === "threat");
  const anomalies = predictions.filter(p => p.type === "anomaly");
  
  // Count by severity
  const criticalCount = predictions.filter(p => p.severity === "critical").length;
  const highCount = predictions.filter(p => p.severity === "high").length;
  const mediumCount = predictions.filter(p => p.severity === "medium").length;
  const lowCount = predictions.filter(p => p.severity === "low").length;

  // Calculate financial impact if available
  const totalFinancialImpact = predictions
    .filter(p => p.financialImpact?.estimatedCost)
    .reduce((sum, p) => sum + (p.financialImpact?.estimatedCost || 0), 0);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical": return "bg-red-600 hover:bg-red-700";
      case "high": return "bg-red-500 hover:bg-red-600";
      case "medium": return "bg-amber-500 hover:bg-amber-600";
      case "low": return "bg-green-500 hover:bg-green-600";
      default: return "bg-slate-500 hover:bg-slate-600";
    }
  };

  const getSeverityBgColor = (severity: string) => {
    switch (severity) {
      case "critical": return "bg-red-100 dark:bg-red-900/20";
      case "high": return "bg-red-50 dark:bg-red-800/20";
      case "medium": return "bg-amber-50 dark:bg-amber-800/20";
      case "low": return "bg-green-50 dark:bg-green-800/20";
      default: return "bg-slate-50 dark:bg-slate-800/20";
    }
  };

  if (isLoading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Brain className="h-5 w-5" />
            ML Prediction Analysis
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex justify-center items-center h-48">
            <div className="flex flex-col items-center gap-3">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
              <p className="text-sm text-muted-foreground">Loading prediction data...</p>
            </div>
          </div>
        </CardContent>
      </Card>
    );
  }

  if (predictions.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Brain className="h-5 w-5" />
            ML Prediction Analysis
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex justify-center items-center h-48 text-muted-foreground">
            <div className="text-center">
              <AlertTriangle className="h-8 w-8 mx-auto mb-2 opacity-50" />
              <p>No predictions available for this scan.</p>
              <p className="text-sm mt-1">Run a new scan to generate ML predictions.</p>
            </div>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2">
          <Brain className="h-5 w-5" />
          ML Prediction Analysis
          {modelAccuracy > 0 && (
            <Badge variant="outline" className="ml-2 text-xs">
              Model accuracy: {Math.round(modelAccuracy * 100)}%
            </Badge>
          )}
          {scanTime && (
            <span className="text-xs text-muted-foreground ml-auto">
              {scanTime}
            </span>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-4 gap-3 mb-4">
          <div className="flex flex-col p-3 rounded-lg bg-red-50 dark:bg-red-900/20">
            <span className="text-xs font-medium text-muted-foreground">Critical</span>
            <span className="text-2xl font-bold text-red-600">{criticalCount}</span>
          </div>
          <div className="flex flex-col p-3 rounded-lg bg-red-50/80 dark:bg-red-800/20">
            <span className="text-xs font-medium text-muted-foreground">High</span>
            <span className="text-2xl font-bold text-red-500">{highCount}</span>
          </div>
          <div className="flex flex-col p-3 rounded-lg bg-amber-50 dark:bg-amber-800/20">
            <span className="text-xs font-medium text-muted-foreground">Medium</span>
            <span className="text-2xl font-bold text-amber-500">{mediumCount}</span>
          </div>
          <div className="flex flex-col p-3 rounded-lg bg-green-50 dark:bg-green-800/20">
            <span className="text-xs font-medium text-muted-foreground">Low</span>
            <span className="text-2xl font-bold text-green-500">{lowCount}</span>
          </div>
        </div>

        {totalFinancialImpact > 0 && (
          <div className="mb-4 p-3 rounded-lg border border-amber-200 bg-amber-50 dark:bg-amber-900/10 dark:border-amber-900/30">
            <div className="flex items-center gap-2">
              <DollarSign className="h-5 w-5 text-amber-600" />
              <span className="font-semibold text-amber-700 dark:text-amber-400">Estimated Financial Impact:</span>
              <span className="ml-auto font-bold text-amber-800 dark:text-amber-300">
                ${totalFinancialImpact.toLocaleString()}
              </span>
            </div>
          </div>
        )}

        <Tabs defaultValue={activeTab} onValueChange={setActiveTab} className="w-full">
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="vulnerabilities">
              Vulnerabilities ({vulnerabilities.length})
            </TabsTrigger>
            <TabsTrigger value="threats">
              Threats ({threats.length})
            </TabsTrigger>
            <TabsTrigger value="anomalies">
              Anomalies ({anomalies.length})
            </TabsTrigger>
          </TabsList>
          
          <TabsContent value="vulnerabilities" className="mt-4">
            <div className="space-y-3">
              {vulnerabilities.length > 0 ? (
                vulnerabilities.map((vuln) => (
                  <div 
                    key={vuln.id} 
                    className={`p-3 rounded-lg border ${getSeverityBgColor(vuln.severity)}`}
                  >
                    <div className="flex items-start gap-2">
                      <ShieldAlert className="h-5 w-5 mt-0.5 text-red-500" />
                      <div className="flex-1">
                        <div className="flex items-center gap-2">
                          <h4 className="font-medium">{vuln.name}</h4>
                          <Badge className={getSeverityColor(vuln.severity)}>
                            {vuln.severity.toUpperCase()}
                          </Badge>
                          {vuln.cve && (
                            <Badge variant="outline">
                              <a 
                                href={`https://nvd.nist.gov/vuln/detail/${vuln.cve}`} 
                                target="_blank" 
                                rel="noopener noreferrer"
                                className="hover:underline"
                              >
                                {vuln.cve}
                              </a>
                            </Badge>
                          )}
                        </div>
                        <p className="text-sm text-muted-foreground mt-1">
                          {vuln.description}
                        </p>
                        {vuln.remediation && (
                          <div className="mt-2 text-sm">
                            <span className="font-medium">Remediation: </span>
                            {vuln.remediation}
                          </div>
                        )}
                        <div className="mt-2">
                          <div className="flex items-center gap-2 text-sm">
                            <span className="text-muted-foreground">Confidence:</span>
                            <Progress value={vuln.confidence} className="h-2 w-24" />
                            <span>{Math.round(vuln.confidence)}%</span>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                ))
              ) : (
                <div className="text-center py-8 text-muted-foreground">
                  No vulnerabilities detected
                </div>
              )}
            </div>
          </TabsContent>
          
          <TabsContent value="threats" className="mt-4">
            <div className="space-y-3">
              {threats.length > 0 ? (
                threats.map((threat) => (
                  <div 
                    key={threat.id} 
                    className={`p-3 rounded-lg border ${getSeverityBgColor(threat.severity)}`}
                  >
                    <div className="flex items-start gap-2">
                      <AlertTriangle className="h-5 w-5 mt-0.5 text-amber-500" />
                      <div className="flex-1">
                        <div className="flex items-center gap-2">
                          <h4 className="font-medium">{threat.name}</h4>
                          <Badge className={getSeverityColor(threat.severity)}>
                            {threat.severity.toUpperCase()}
                          </Badge>
                        </div>
                        <p className="text-sm text-muted-foreground mt-1">
                          {threat.description}
                        </p>
                        {threat.impact && (
                          <div className="mt-2 text-sm">
                            <span className="font-medium">Impact: </span>
                            {threat.impact}
                          </div>
                        )}
                        <div className="mt-2">
                          <div className="flex items-center gap-2 text-sm">
                            <span className="text-muted-foreground">Confidence:</span>
                            <Progress value={threat.confidence} className="h-2 w-24" />
                            <span>{Math.round(threat.confidence)}%</span>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                ))
              ) : (
                <div className="text-center py-8 text-muted-foreground">
                  No threats detected
                </div>
              )}
            </div>
          </TabsContent>
          
          <TabsContent value="anomalies" className="mt-4">
            <div className="space-y-3">
              {anomalies.length > 0 ? (
                anomalies.map((anomaly) => (
                  <div 
                    key={anomaly.id} 
                    className={`p-3 rounded-lg border ${getSeverityBgColor(anomaly.severity)}`}
                  >
                    <div className="flex items-start gap-2">
                      <AlertTriangle className="h-5 w-5 mt-0.5 text-blue-500" />
                      <div className="flex-1">
                        <div className="flex items-center gap-2">
                          <h4 className="font-medium">{anomaly.name}</h4>
                          <Badge className={getSeverityColor(anomaly.severity)}>
                            {anomaly.severity.toUpperCase()}
                          </Badge>
                        </div>
                        <p className="text-sm text-muted-foreground mt-1">
                          {anomaly.description}
                        </p>
                        <div className="mt-2">
                          <div className="flex items-center gap-2 text-sm">
                            <span className="text-muted-foreground">Confidence:</span>
                            <Progress value={anomaly.confidence} className="h-2 w-24" />
                            <span>{Math.round(anomaly.confidence)}%</span>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                ))
              ) : (
                <div className="text-center py-8 text-muted-foreground">
                  No anomalies detected
                </div>
              )}
            </div>
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
}
