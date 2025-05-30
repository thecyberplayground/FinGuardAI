"use client"

import { useState } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { DollarSign, Clock, AlertCircle, TrendingUp, TrendingDown, Building } from "lucide-react"

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

interface FinancialImpactDisplayProps {
  financialImpacts: FinancialImpactItem[];
  scanTarget?: string;
  scanDate?: string;
  isLoading?: boolean;
  industryBenchmark?: number;
}

export function FinancialImpactDisplay({
  financialImpacts = [],
  scanTarget = "",
  scanDate = "",
  isLoading = false,
  industryBenchmark = 0
}: FinancialImpactDisplayProps) {
  const [activeTab, setActiveTab] = useState("overview");

  // Group impacts by category
  const directCosts = financialImpacts.filter(item => item.category === "direct");
  const indirectCosts = financialImpacts.filter(item => item.category === "indirect");
  const regulatoryCosts = financialImpacts.filter(item => item.category === "regulatory");
  
  // Calculate totals
  const totalImpact = financialImpacts.reduce((sum, item) => sum + item.estimatedCost, 0);
  const totalMitigationCost = financialImpacts.reduce((sum, item) => sum + (item.mitigationCost || 0), 0);
  const costDifference = totalImpact - totalMitigationCost;
  const costRatio = totalMitigationCost > 0 ? totalImpact / totalMitigationCost : 0;
  
  // Helper function for risk colors
  const getRiskColor = (risk: string) => {
    switch (risk) {
      case "critical": return "text-red-600";
      case "high": return "text-red-500";
      case "medium": return "text-amber-500";
      case "low": return "text-green-500";
      default: return "text-slate-500";
    }
  };

  if (isLoading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <DollarSign className="h-5 w-5" />
            Financial Impact Assessment
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex justify-center items-center h-48">
            <div className="flex flex-col items-center gap-3">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
              <p className="text-sm text-muted-foreground">Loading financial data...</p>
            </div>
          </div>
        </CardContent>
      </Card>
    );
  }

  if (financialImpacts.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <DollarSign className="h-5 w-5" />
            Financial Impact Assessment
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex justify-center items-center h-48 text-muted-foreground">
            <div className="text-center">
              <DollarSign className="h-8 w-8 mx-auto mb-2 opacity-50" />
              <p>No financial impact data available.</p>
              <p className="text-sm mt-1">Run a comprehensive scan to generate financial assessments.</p>
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
          <DollarSign className="h-5 w-5" />
          Financial Impact Assessment
          {scanTarget && (
            <Badge variant="outline" className="ml-2">
              {scanTarget}
            </Badge>
          )}
          {scanDate && (
            <span className="text-xs text-muted-foreground ml-auto">
              {scanDate}
            </span>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
          <div className="flex flex-col p-3 rounded-lg bg-red-50 dark:bg-red-900/20">
            <span className="text-xs font-medium text-muted-foreground">Total Risk</span>
            <span className="text-xl font-bold text-red-600">${totalImpact.toLocaleString()}</span>
          </div>
          <div className="flex flex-col p-3 rounded-lg bg-blue-50 dark:bg-blue-900/20">
            <span className="text-xs font-medium text-muted-foreground">Mitigation Cost</span>
            <span className="text-xl font-bold text-blue-600">${totalMitigationCost.toLocaleString()}</span>
          </div>
          <div className="flex flex-col p-3 rounded-lg bg-green-50 dark:bg-green-900/20">
            <span className="text-xs font-medium text-muted-foreground">Potential Savings</span>
            <span className="text-xl font-bold text-green-600">${costDifference.toLocaleString()}</span>
          </div>
          <div className="flex flex-col p-3 rounded-lg bg-purple-50 dark:bg-purple-900/20">
            <span className="text-xs font-medium text-muted-foreground">ROI Ratio</span>
            <span className="text-xl font-bold text-purple-600">{costRatio.toFixed(1)}x</span>
          </div>
        </div>

        {industryBenchmark > 0 && (
          <div className="mb-4 p-3 rounded-lg border bg-slate-50 dark:bg-slate-900/30">
            <div className="flex items-center gap-2">
              <Building className="h-5 w-5 text-slate-600" />
              <span className="font-semibold">Industry Benchmark:</span>
              <span className="ml-auto font-bold">
                ${industryBenchmark.toLocaleString()}
              </span>
              {totalImpact < industryBenchmark ? (
                <Badge className="bg-green-500">
                  <TrendingDown className="h-3 w-3 mr-1" />
                  {(((industryBenchmark - totalImpact) / industryBenchmark) * 100).toFixed(1)}% Below
                </Badge>
              ) : (
                <Badge className="bg-red-500">
                  <TrendingUp className="h-3 w-3 mr-1" />
                  {(((totalImpact - industryBenchmark) / industryBenchmark) * 100).toFixed(1)}% Above
                </Badge>
              )}
            </div>
          </div>
        )}

        <Tabs defaultValue={activeTab} onValueChange={setActiveTab} className="w-full">
          <TabsList className="grid w-full grid-cols-4">
            <TabsTrigger value="overview">
              Overview
            </TabsTrigger>
            <TabsTrigger value="direct">
              Direct ({directCosts.length})
            </TabsTrigger>
            <TabsTrigger value="indirect">
              Indirect ({indirectCosts.length})
            </TabsTrigger>
            <TabsTrigger value="regulatory">
              Regulatory ({regulatoryCosts.length})
            </TabsTrigger>
          </TabsList>
          
          <TabsContent value="overview" className="mt-4">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Impact Category</TableHead>
                  <TableHead>Count</TableHead>
                  <TableHead>Financial Impact</TableHead>
                  <TableHead>Mitigation Cost</TableHead>
                  <TableHead>Potential Savings</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                <TableRow>
                  <TableCell className="font-medium">Direct Costs</TableCell>
                  <TableCell>{directCosts.length}</TableCell>
                  <TableCell>${directCosts.reduce((sum, item) => sum + item.estimatedCost, 0).toLocaleString()}</TableCell>
                  <TableCell>${directCosts.reduce((sum, item) => sum + (item.mitigationCost || 0), 0).toLocaleString()}</TableCell>
                  <TableCell>
                    ${(directCosts.reduce((sum, item) => sum + item.estimatedCost, 0) - 
                       directCosts.reduce((sum, item) => sum + (item.mitigationCost || 0), 0)).toLocaleString()}
                  </TableCell>
                </TableRow>
                <TableRow>
                  <TableCell className="font-medium">Indirect Costs</TableCell>
                  <TableCell>{indirectCosts.length}</TableCell>
                  <TableCell>${indirectCosts.reduce((sum, item) => sum + item.estimatedCost, 0).toLocaleString()}</TableCell>
                  <TableCell>${indirectCosts.reduce((sum, item) => sum + (item.mitigationCost || 0), 0).toLocaleString()}</TableCell>
                  <TableCell>
                    ${(indirectCosts.reduce((sum, item) => sum + item.estimatedCost, 0) - 
                       indirectCosts.reduce((sum, item) => sum + (item.mitigationCost || 0), 0)).toLocaleString()}
                  </TableCell>
                </TableRow>
                <TableRow>
                  <TableCell className="font-medium">Regulatory Costs</TableCell>
                  <TableCell>{regulatoryCosts.length}</TableCell>
                  <TableCell>${regulatoryCosts.reduce((sum, item) => sum + item.estimatedCost, 0).toLocaleString()}</TableCell>
                  <TableCell>${regulatoryCosts.reduce((sum, item) => sum + (item.mitigationCost || 0), 0).toLocaleString()}</TableCell>
                  <TableCell>
                    ${(regulatoryCosts.reduce((sum, item) => sum + item.estimatedCost, 0) - 
                       regulatoryCosts.reduce((sum, item) => sum + (item.mitigationCost || 0), 0)).toLocaleString()}
                  </TableCell>
                </TableRow>
                <TableRow className="font-bold">
                  <TableCell>Total</TableCell>
                  <TableCell>{financialImpacts.length}</TableCell>
                  <TableCell>${totalImpact.toLocaleString()}</TableCell>
                  <TableCell>${totalMitigationCost.toLocaleString()}</TableCell>
                  <TableCell>${costDifference.toLocaleString()}</TableCell>
                </TableRow>
              </TableBody>
            </Table>
          </TabsContent>
          
          {['direct', 'indirect', 'regulatory'].map((category) => (
            <TabsContent key={category} value={category} className="mt-4">
              <div className="space-y-3">
                {financialImpacts
                  .filter(item => item.category === category)
                  .map((item) => (
                    <div 
                      key={item.id} 
                      className="p-3 rounded-lg border"
                    >
                      <div className="flex items-start">
                        <div className="flex-1">
                          <div className="flex items-center gap-2">
                            <h4 className="font-medium">{item.name}</h4>
                            <span className={`ml-auto font-bold ${getRiskColor(item.businessRisk)}`}>
                              ${item.estimatedCost.toLocaleString()}
                            </span>
                          </div>
                          <p className="text-sm text-muted-foreground mt-1">
                            {item.description}
                          </p>
                          <div className="flex flex-wrap gap-x-4 gap-y-1 mt-2 text-sm">
                            <div className="flex items-center gap-1">
                              <Clock className="h-4 w-4 text-amber-500" />
                              <span>Recovery: {item.recoveryTime}</span>
                            </div>
                            {item.mitigationCost !== undefined && (
                              <div className="flex items-center gap-1">
                                <DollarSign className="h-4 w-4 text-blue-500" />
                                <span>Mitigation: ${item.mitigationCost.toLocaleString()}</span>
                              </div>
                            )}
                            {item.regulatoryImpact && (
                              <div className="flex items-center gap-1">
                                <AlertCircle className="h-4 w-4 text-red-500" />
                                <span>{item.regulatoryImpact}</span>
                              </div>
                            )}
                          </div>
                        </div>
                      </div>
                    </div>
                  ))}
                {financialImpacts.filter(item => item.category === category).length === 0 && (
                  <div className="text-center py-8 text-muted-foreground">
                    No {category} costs identified
                  </div>
                )}
              </div>
            </TabsContent>
          ))}
        </Tabs>
      </CardContent>
    </Card>
  );
}
