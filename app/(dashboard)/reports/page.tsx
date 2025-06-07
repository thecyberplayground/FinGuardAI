"use client"

import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent } from "@/components/ui/card"
import { PieChart } from "@/components/pie-chart"
import { LineChart } from "@/components/line-chart"
import { CircularProgress } from "@/components/circular-progress"
import { Eye, AlertTriangle, AlertCircle, CheckCircle, Download, FileDown, Filter, Loader2, Info } from "lucide-react"
import { ThemeToggle } from "@/components/theme-toggle"
import { motion } from "framer-motion"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"

// Import API services
import { fetchReports, fetchRemediationRecommendations, exportReport, Report } from "@/app/services/reportsApi"

export default function ReportsPage() {
  const [mounted, setMounted] = useState(false)
  const [threatData, setThreatData] = useState({ high: 0, medium: 0, low: 0 })
  const [timeFilter, setTimeFilter] = useState("all")
  const [systemRiskScore, setSystemRiskScore] = useState(0)
  const [reports, setReports] = useState<Report[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [exporting, setExporting] = useState(false)
  const [exportFormat, setExportFormat] = useState<"pdf" | "csv" | "json">("pdf")
  const [currentReportId, setCurrentReportId] = useState<string | null>(null)
  
  // Risk prediction data based on reports
  const [riskPredictionData, setRiskPredictionData] = useState<any>({
    labels: [],
    datasets: []
  })

  // Fetch reports when component mounts or timeFilter changes
  useEffect(() => {
    setMounted(true)
    fetchReportData()
  }, [timeFilter])
  
  // Function to fetch report data from API
  const fetchReportData = async () => {
    try {
      setLoading(true)
      setError(null)
      
      // Fetch reports from API
      const data = await fetchReports(timeFilter !== "all" ? timeFilter : undefined)
      setReports(data)
      
      // Calculate threat distribution
      const high = data.filter((r) => r.severity === "high").length
      const medium = data.filter((r) => r.severity === "medium").length
      const low = data.filter((r) => r.severity === "low").length
      setThreatData({ high, medium, low })
      
      // Calculate average system risk score based on vulnerabilities
      if (data.length > 0) {
        const avgRisk = data.reduce((sum, report) => {
          // Convert severity to a risk score
          const riskScore = 
            report.severity === "critical" ? 90 :
            report.severity === "high" ? 75 :
            report.severity === "medium" ? 50 :
            report.severity === "low" ? 25 : 0
          return sum + riskScore
        }, 0) / data.length
        
        setSystemRiskScore(Math.round(avgRisk))
      }
      
      // Generate risk prediction data based on reports
      if (data.length > 0) {
        // Get last 7 days or all if less
        const sortedReports = [...data].sort(
          (a, b) => new Date(b.date).getTime() - new Date(a.date).getTime()
        ).slice(0, 7)
        
        const labels = sortedReports.map(r => {
          const date = new Date(r.date)
          return `${date.getMonth()+1}/${date.getDate()}`
        }).reverse()
        
        const historicalRisk: number[] = sortedReports.map(r => {
          return r.severity === "critical" ? 90 :
                 r.severity === "high" ? 75 :
                 r.severity === "medium" ? 50 :
                 r.severity === "low" ? 25 : 0
        }).reverse()
        
        // Simple prediction - trend continuation with some regression to mean
        const predictedRisk = [...historicalRisk]
        for (let i = 0; i < 3; i++) {
          const lastVal = predictedRisk[predictedRisk.length - 1]
          const secondLastVal = predictedRisk[predictedRisk.length - 2] || lastVal
          const trend = lastVal - secondLastVal
          // Dampen the trend for prediction (regression to mean)
          const nextVal = Math.max(0, Math.min(100, lastVal + trend * 0.8))
          predictedRisk.push(nextVal)
        }
        
        // Update chart data
        setRiskPredictionData({
          labels: [...labels, 'Day +1', 'Day +2', 'Day +3'],
          datasets: [
            {
              label: "Historical Risk",
              data: [...historicalRisk, null, null, null],
              borderColor: "#ff5555",
              backgroundColor: "rgba(255, 85, 85, 0.1)",
              fill: true,
              tension: 0.4,
              borderWidth: 2,
            },
            {
              label: "Predicted Risk",
              data: predictedRisk,
              borderColor: "#00d4b8",
              backgroundColor: "rgba(0, 212, 184, 0.1)",
              borderDash: [5, 5],
              fill: false,
              tension: 0.4,
              borderWidth: 2,
            },
          ],
        })
      }
    } catch (err) {
      setError(`Error loading reports: ${err instanceof Error ? err.message : String(err)}`)
    } finally {
      setLoading(false)
    }
  }
  
  // Function to view remediation recommendations
  const viewRemediation = async (vulnId: string) => {
    try {
      // Get remediation recommendations
      const remediation = await fetchRemediationRecommendations(vulnId, { detailed: true })
      
      // For now, show in an alert, but in a real implementation would use a modal
      alert(`Remediation recommendation: ${remediation.recommendation}\n\nDifficulty: ${remediation.difficulty}\nEstimated time: ${remediation.estimated_time}`)
    } catch (err) {
      alert(`Error loading remediation: ${err instanceof Error ? err.message : String(err)}`)
    }
  }
  
  // Function to export a report
  const handleExport = async (reportId: string) => {
    try {
      setExporting(true)
      setCurrentReportId(reportId)
      
      const exported = await exportReport(reportId, exportFormat)
      
      if (exportFormat === "json") {
        // For JSON, create a data URL and trigger download
        const dataStr = JSON.stringify(exported, null, 2)
        const dataUri = `data:application/json;charset=utf-8,${encodeURIComponent(dataStr)}`
        
        const link = document.createElement('a')
        link.href = dataUri
        link.download = `report-${reportId}.json`
        document.body.appendChild(link)
        link.click()
        document.body.removeChild(link)
      } else {
        // For PDF or CSV, create a blob URL and trigger download
        const blob = new Blob([exported], { 
          type: exportFormat === "pdf" ? "application/pdf" : "text/csv" 
        })
        const url = URL.createObjectURL(blob)
        
        const link = document.createElement('a')
        link.href = url
        link.download = `report-${reportId}.${exportFormat}`
        document.body.appendChild(link)
        link.click()
        URL.revokeObjectURL(url)
      }
    } catch (err) {
      setError(`Failed to export report: ${err instanceof Error ? err.message : String(err)}`)
    } finally {
      setExporting(false)
      setCurrentReportId(null)
    }
  }

  if (!mounted) return null

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between bg-white/5 backdrop-blur-md dark:bg-black/20 p-4 rounded-lg shadow-sm border border-white/5">
        <h1 className="text-2xl font-bold tracking-tight dark:text-white font-orbitron bg-clip-text text-transparent bg-gradient-to-r from-[#00d4b8] to-[#7b2cbf]">
          FinGuardAI Reports
        </h1>
        <div className="flex items-center space-x-2">
          <Select defaultValue={timeFilter} onValueChange={setTimeFilter}>
            <SelectTrigger className="w-[180px] bg-white/5 border-white/10 text-white">
              <SelectValue placeholder="Select time range" />
            </SelectTrigger>
            <SelectContent className="bg-[#161b22] border border-white/10 backdrop-blur-md">
              <SelectItem value="24h">Last 24 Hours</SelectItem>
              <SelectItem value="week">Last Week</SelectItem>
              <SelectItem value="month">Last Month</SelectItem>
              <SelectItem value="all">All Time</SelectItem>
            </SelectContent>
          </Select>

          <ThemeToggle />
        </div>
      </div>

      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }}>
        <Card className="overflow-hidden border-0 shadow-lg bg-white/5 backdrop-blur-md dark:bg-black/20 border border-white/5 mb-4">
          <CardContent className="p-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div>
                <h3 className="text-lg font-medium mb-4 dark:text-white font-orbitron bg-clip-text text-transparent bg-gradient-to-r from-[#00d4b8] to-[#7b2cbf]">
                  Severity Distribution
                </h3>
                <PieChart data={threatData} height="180px" />
              </div>

              <div className="md:col-span-2">
                <h3 className="text-lg font-medium mb-4 dark:text-white font-orbitron bg-clip-text text-transparent bg-gradient-to-r from-[#00d4b8] to-[#7b2cbf]">
                  Risk Prediction Trend
                </h3>
                <LineChart labels={riskPredictionData.labels} datasets={riskPredictionData.datasets} height="180px" />
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mt-6">
              <div className="bg-black/20 backdrop-blur-sm rounded-lg p-4 text-center border border-white/5">
                <div className="flex justify-center mb-2">
                  <AlertCircle className="h-6 w-6 text-[#ff5555]" />
                </div>
                <div className="text-2xl font-bold text-[#ff5555] drop-shadow-[0_0_5px_rgba(255,85,85,0.5)]">
                  {threatData.high}
                </div>
                <div className="text-sm text-[#ff5555]/80">High Severity</div>
              </div>
              <div className="bg-black/20 backdrop-blur-sm rounded-lg p-4 text-center border border-white/5">
                <div className="flex justify-center mb-2">
                  <AlertTriangle className="h-6 w-6 text-[#ffaa00]" />
                </div>
                <div className="text-2xl font-bold text-[#ffaa00] drop-shadow-[0_0_5px_rgba(255,170,0,0.5)]">
                  {threatData.medium}
                </div>
                <div className="text-sm text-[#ffaa00]/80">Medium Severity</div>
              </div>
              <div className="bg-black/20 backdrop-blur-sm rounded-lg p-4 text-center border border-white/5">
                <div className="flex justify-center mb-2">
                  <CheckCircle className="h-6 w-6 text-[#00cc99]" />
                </div>
                <div className="text-2xl font-bold text-[#00cc99] drop-shadow-[0_0_5px_rgba(0,204,153,0.5)]">
                  {threatData.low}
                </div>
                <div className="text-sm text-[#00cc99]/80">Low Severity</div>
              </div>
              <div className="bg-black/20 backdrop-blur-sm rounded-lg p-4 text-center border border-white/5">
                <div className="flex justify-center">
                  <CircularProgress value={systemRiskScore} size={80} showValue={false} glowEffect={true} />
                </div>
                <div className="text-lg font-bold text-transparent bg-clip-text bg-gradient-to-r from-[#00d4b8] to-[#7b2cbf] drop-shadow-[0_0_5px_rgba(0,212,184,0.5)] mt-2">
                  {systemRiskScore}%
                </div>
                <div className="text-sm text-gray-400">System Risk Score</div>
              </div>
            </div>
          </CardContent>
        </Card>
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3, delay: 0.1 }}
      >
        <div className="bg-white/5 backdrop-blur-md dark:bg-black/20 border border-white/5 rounded-lg p-4">
          {loading ? (
            <div className="flex justify-center items-center py-12">
              <div className="flex flex-col items-center gap-3">
                <Loader2 className="h-8 w-8 animate-spin text-primary" />
                <p className="text-sm text-muted-foreground">Loading reports...</p>
              </div>
            </div>
          ) : error ? (
            <div className="bg-red-100 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md p-4 my-4">
              <div className="flex items-start">
                <AlertCircle className="h-5 w-5 text-red-500 mt-0.5" />
                <div className="ml-3">
                  <h3 className="text-sm font-medium text-red-800 dark:text-red-200">Error loading reports</h3>
                  <div className="mt-2 text-sm text-red-700 dark:text-red-300">
                    <p>{error}</p>
                  </div>
                </div>
              </div>
            </div>
          ) : reports.length === 0 ? (
            <div className="text-center py-12">
              <div className="flex flex-col items-center gap-3">
                <Info className="h-8 w-8 text-muted-foreground opacity-50" />
                <p className="text-muted-foreground">No reports found</p>
                <p className="text-sm text-muted-foreground">Run a scan to generate reports</p>
              </div>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Target</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Vulnerabilities</TableHead>
                  <TableHead>Environment</TableHead>
                  <TableHead>Date</TableHead>
                  <TableHead>Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {reports.map((report) => (
                  <TableRow key={report.id}>
                    <TableCell className="font-medium">{report.target}</TableCell>
                    <TableCell>
                      {report.severity === "critical" && (
                        <Badge className="bg-red-600 text-white">
                          <AlertCircle className="h-3 w-3 mr-1" />
                          Critical
                        </Badge>
                      )}
                      {report.severity === "high" && (
                        <Badge className="bg-red-500 text-white">
                          <AlertCircle className="h-3 w-3 mr-1" />
                          High
                        </Badge>
                      )}
                      {report.severity === "medium" && (
                        <Badge className="bg-amber-500 text-white">
                          <AlertTriangle className="h-3 w-3 mr-1" />
                          Medium
                        </Badge>
                      )}
                      {report.severity === "low" && (
                        <Badge className="bg-green-500 text-white">
                          <CheckCircle className="h-3 w-3 mr-1" />
                          Low
                        </Badge>
                      )}
                    </TableCell>
                    <TableCell>{report.vulnerabilities_count}</TableCell>
                    <TableCell>
                      <Badge variant="outline">
                        {report.environment || "prod"}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      {new Date(report.date).toLocaleDateString()}
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <Button
                          variant="outline"
                          size="sm"
                          className="flex items-center gap-1"
                          onClick={() => viewRemediation(report.id)}
                        >
                          <Eye className="h-3 w-3" />
                          View Fix
                        </Button>
                        
                        <div className="flex items-center gap-1">
                          <Select 
                            value={exportFormat} 
                            onValueChange={(v) => setExportFormat(v as any)}
                          >
                            <SelectTrigger className="h-8 w-[70px]">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="pdf">PDF</SelectItem>
                              <SelectItem value="csv">CSV</SelectItem>
                              <SelectItem value="json">JSON</SelectItem>
                            </SelectContent>
                          </Select>
                          
                          <Button 
                            variant="outline" 
                            size="sm"
                            disabled={exporting && currentReportId === report.id}
                            onClick={() => handleExport(report.id)}
                          >
                            {exporting && currentReportId === report.id ? (
                              <Loader2 className="h-3 w-3 animate-spin" />
                            ) : (
                              <FileDown className="h-3 w-3" />
                            )}
                          </Button>
                        </div>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </div>
      </motion.div>
    </div>
  )
}
