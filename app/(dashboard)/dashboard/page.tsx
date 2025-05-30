"use client"

import { useState, useEffect } from "react"
import { useScanSocket } from "@/hooks/use-scan-socket"
import { io, Socket } from "socket.io-client"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Switch } from "@/components/ui/switch"
import { Label } from "@/components/ui/label"
import { ThemeToggle } from "@/components/theme-toggle"
import { LiveClock } from "@/components/live-clock"
import { CircularProgress } from "@/components/circular-progress"
import { LineChart } from "@/components/line-chart"
import { BarChart } from "@/components/bar-chart"
import { DoughnutChart } from "@/components/doughnut-chart"
import { Counter } from "@/components/counter-animation"
import { StatusLog } from "@/components/status-log"
import { ProgressBar } from "@/components/progress-bar"
import { CubeLoader } from "@/components/cube-loader"
import { Shield, AlertTriangle, User, ChevronDown, Activity, Cpu, Zap, Clock, Network, Scan, Target, Brain, AlertCircle } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { motion } from "framer-motion"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"

export default function DashboardPage() {
  const [target, setTarget] = useState("");
  const [scanType, setScanType] = useState("basic");
  const { isScanning, scanProgress, scanResult, scanError, startScan } = useScanSocket();
  // --- State: Only live data, no demo values ---
  const [monitoringActive, setMonitoringActive] = useState<boolean>(() => {
    if (typeof window !== "undefined") {
      const saved = localStorage.getItem("monitoringActive");
      return saved === "true";
    }
    return false;
  });
  // monitorHost starts as empty string unless localStorage has a value
  const [monitorHost, setMonitorHost] = useState<string>(() => {
    if (typeof window !== "undefined") {
      return localStorage.getItem("monitorHost") || "";
    }
    return "";
  });
  const [monitorStats, setMonitorStats] = useState<any>(null);
  const [monitorError, setMonitorError] = useState<string | null>(null);
  const [mounted, setMounted] = useState(false);

  // --- Persist state to localStorage ---
  useEffect(() => {
    if (typeof window !== "undefined") {
      localStorage.setItem("monitoringActive", monitoringActive ? "true" : "false");
    }
  }, [monitoringActive]);
  useEffect(() => {
    if (typeof window !== "undefined") {
      localStorage.setItem("monitorHost", monitorHost);
    }
  }, [monitorHost]);

  // --- Restore state on mount and auto-resume monitoring ---
  useEffect(() => {
    setMounted(true);
    if (typeof window !== "undefined") {
      const savedActive = localStorage.getItem("monitoringActive");
      const savedHost = localStorage.getItem("monitorHost");
      if (savedActive === "true" && savedHost) {
        setMonitoringActive(true);
        setMonitorHost(savedHost);
      }
    }
  }, []);

  // --- Sync target (scan input) to monitorHost (passive monitoring input) ---
  useEffect(() => {
    // Only update monitorHost if monitoring is not active and user hasn't typed a different monitorHost
    if (!monitoringActive && (!monitorHost || monitorHost === "")) {
      if (target && target !== monitorHost) {
        setMonitorHost(target);
      }
    }
    // If user clears target, don't clear monitorHost (let user manually clear it)
    // If user starts monitoring, don't update monitorHost anymore
  }, [target]);

  // --- Utility: Compute total threats from monitorStats ---
  const totalThreats = monitorStats
    ? (Number(monitorStats.tcp || 0) + Number(monitorStats.udp || 0) + Number(monitorStats.icmp || 0))
    : 0;

  // --- Passive monitoring socket logic (only live data) ---
  useEffect(() => {
    if (!monitoringActive || !monitorHost) return;
    const socket: Socket = io("http://127.0.0.1:5001");
    console.log("Emitting start_passive_monitoring", { host: monitorHost });
    socket.emit("start_passive_monitoring", { host: monitorHost });
    socket.on("passive_stats_update", (data: any) => {
      console.log("Received passive_stats_update:", data);
      setMonitorStats(data);
      setMonitorError(null);
    });
    socket.on("passive_monitoring_error", (data: any) => {
      console.log("Received passive_monitoring_error:", data);
      setMonitorError(data.reason);
      setMonitorStats(null);
    });
    return () => {
      socket.emit("stop_passive_monitoring");
      socket.disconnect();
    };
  }, [monitoringActive, monitorHost]);

  // Risk prediction data (live only, fallback to 0)
  const riskPredictionData = {
    labels: ["Now", "+2h", "+4h", "+6h", "+8h", "+10h", "+12h", "+14h", "+16h", "+18h", "+20h", "+22h", "+24h"],
    datasets: [
      {
        label: "Predicted Risk",
        data: monitorStats && monitorStats.risk_prediction ? monitorStats.risk_prediction : Array(12).fill(0),
        borderColor: "#ffaa00",
        backgroundColor: "rgba(255, 170, 0, 0.1)",
        fill: true,
      },
    ],
  }

  useEffect(() => {
    setMounted(true)
  }, [])

  const handleStartScan = () => {
    startScan(target, scanType);
  }

  const toggleMonitoring = () => {
    setMonitoringActive(!monitoringActive)
  }

  if (!mounted) return null

  return (
    <div className="space-y-4">
      {/* Top Bar */}
      <div className="flex items-center justify-between bg-white dark:bg-black/20 p-4 rounded-lg shadow-sm border border-gray-200 dark:border-white/5">
        <h1 className="text-2xl font-bold tracking-tight text-gray-800 dark:text-white font-orbitron bg-clip-text text-transparent bg-gradient-to-r from-[#00d4b8] to-[#7b2cbf]">
          FinGuardAI Dashboard
        </h1>
        <div className="flex items-center space-x-4">
          <LiveClock />

          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                className="flex items-center gap-2 bg-gray-100 dark:bg-white/5 border border-gray-200 dark:border-white/10 hover:bg-gray-200 dark:hover:bg-white/10"
              >
                <User className="h-4 w-4 text-[#00d4b8]" />
                <span>Admin</span>
                <ChevronDown className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent
              align="end"
              className="bg-white dark:bg-[#161b22] border border-gray-200 dark:border-white/10"
            >
              <DropdownMenuLabel>My Account</DropdownMenuLabel>
              <DropdownMenuSeparator className="bg-gray-200 dark:bg-white/10" />
              <DropdownMenuItem className="hover:bg-gray-100 dark:hover:bg-white/5">Profile</DropdownMenuItem>
              <DropdownMenuItem className="hover:bg-gray-100 dark:hover:bg-white/5">Settings</DropdownMenuItem>
              <DropdownMenuItem className="hover:bg-gray-100 dark:hover:bg-white/5">Logout</DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>

          <ThemeToggle />
        </div>
      </div>

      {/* Main Dashboard Grid */}
      <div className="grid grid-cols-12 gap-4">
        {/* Scan Command Center */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3 }}
          className="col-span-12 lg:col-span-8"
        >
          <Card className="overflow-hidden border border-gray-200 dark:border-white/5 shadow-lg bg-white dark:bg-black/20">
            <CardHeader className="pb-2 bg-gradient-to-r from-[#00d4b8]/5 to-transparent border-b border-gray-200 dark:border-white/5">
              <CardTitle className="text-lg font-medium flex items-center font-orbitron">
                <Scan className="h-5 w-5 mr-2 text-[#00d4b8]" />
                <span className="bg-clip-text text-transparent bg-gradient-to-r from-[#00d4b8] to-[#7b2cbf]">
                  Quick Scan Launcher
                </span>
              </CardTitle>
            </CardHeader>
            <CardContent className="p-4">
              <div className="flex flex-col gap-4 items-center justify-center">
                <Input
                  id="quick-scan-target"
                  placeholder="Enter IP or hostname to scan"
                  value={target}
                  onChange={e => {
                    setTarget(e.target.value);
                    // If monitoring is not active and monitorHost is empty, sync monitorHost to this value
                    if (!monitoringActive && (!monitorHost || monitorHost === "")) {
                      setMonitorHost(e.target.value);
                    }
                  }}
                  className="bg-white/5 border-white/10 dark:text-white dark:placeholder:text-gray-500 focus:border-[#00d4b8] focus:ring-[#00d4b8] max-w-xs"
                />
                <Button
                  onClick={() => {
                    if (!target) return;
                    // Store in localStorage for scan page to pick up
                    localStorage.setItem("dashboardQuickScanTarget", target);
                    window.location.href = "/scan";
                  }}
                  className="bg-gradient-to-r from-[#00d4b8] to-[#7b2cbf] hover:from-[#00d4b8]/90 hover:to-[#7b2cbf]/90 text-white w-full max-w-xs"
                >
                  Send to Scan Page
                </Button>
                <div className="text-xs text-gray-400 text-center max-w-xs">
                  Enter a target and click. The scan will begin in the background on the Scan page. When the scan is complete, you'll see the results there.
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>

        {/* ML Predictive Matrix */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.1 }}
          className="col-span-12 lg:col-span-4"
        >
          <Card className="overflow-hidden border-0 shadow-lg h-full bg-white/5 backdrop-blur-md dark:bg-black/20 border border-white/5">
            <CardHeader className="pb-2 bg-gradient-to-r from-[#00d4b8]/5 to-transparent border-b border-white/5">
              <CardTitle className="text-lg font-medium flex items-center font-orbitron">
                <Cpu className="h-5 w-5 mr-2 text-[#00d4b8]" />
                <span className="bg-clip-text text-transparent bg-gradient-to-r from-[#00d4b8] to-[#7b2cbf]">
                  ML Prediction Matrix
                </span>
              </CardTitle>
            </CardHeader>
            <CardContent className="p-4">
              <div className="grid grid-cols-2 gap-4 mb-4">
                <div className="bg-black/20 backdrop-blur-sm rounded-lg p-3 text-center border border-white/5">
                  <div className="text-3xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-[#00d4b8] to-[#7b2cbf] drop-shadow-[0_0_5px_rgba(0,212,184,0.5)]">
                    <Counter from={0} to={monitorStats && monitorStats.predicted_threats !== undefined ? monitorStats.predicted_threats : 0} duration={1.5} />
                  </div>
                  <div className="text-xs text-gray-400 mt-1">Predicted Threats</div>
                </div>
                <div className="bg-black/20 backdrop-blur-sm rounded-lg p-3 text-center border border-white/5">
                  <div className="text-3xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-[#ff5555] to-[#ff9955] drop-shadow-[0_0_5px_rgba(255,85,85,0.5)]">
                    <Counter from={0} to={totalThreats} duration={1.5} />
                  </div>
                  <div className="text-xs text-gray-400 mt-1">Current Threats</div>
                </div>
              </div>

              <div className="space-y-2">
                <Label className="dark:text-gray-300 text-xs font-medium">Next 24h Risk Prediction</Label>
                <div className="h-[120px]">
                  <LineChart labels={riskPredictionData.labels} datasets={riskPredictionData.datasets} height="120px" />
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>

        {/* Passive Monitoring Core */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.2 }}
          className="col-span-12 lg:col-span-6"
        >
          <Card className="overflow-hidden border-0 shadow-lg bg-white/5 backdrop-blur-md dark:bg-black/20 border border-white/5">
            <CardHeader className="pb-2 bg-gradient-to-r from-[#00d4b8]/5 to-transparent border-b border-white/5">
              <CardTitle className="text-lg font-medium flex items-center justify-between font-orbitron">
                <div className="flex items-center">
                  <Shield className="h-5 w-5 mr-2 text-[#00d4b8]" />
                  <span className="bg-clip-text text-transparent bg-gradient-to-r from-[#00d4b8] to-[#7b2cbf]">
                    Passive Monitoring Core
                  </span>
                </div>
                <div className="flex items-center space-x-2">
                  <Input
                    id="monitor-host-input"
                    placeholder="Enter host/IP for monitoring"
                    value={monitorHost}
                    onChange={e => setMonitorHost(e.target.value)}
                    className="w-44 bg-white/5 border-white/10 dark:text-white dark:placeholder:text-gray-500 focus:border-[#00d4b8] focus:ring-[#00d4b8]"
                  />
                  <Button
                    onClick={() => {
                      if (!monitorHost) return;
                      setMonitoringActive(!monitoringActive);
                    }}
                    className={`ml-2 ${monitoringActive ? "bg-gradient-to-r from-[#ff5555] to-[#ffaa00]" : "bg-gradient-to-r from-[#00d4b8] to-[#7b2cbf]"}`}
                    disabled={!monitorHost}
                  >
                    {monitoringActive ? "Stop" : "Start"}
                  </Button>
                </div>
              </CardTitle>
            </CardHeader>
            <CardContent className="p-4">
              <div className="space-y-4">
                <div className="flex items-center justify-between text-sm dark:text-gray-300">
                  <span>Status:</span>
                  <span className={`font-medium ${monitoringActive ? "text-[#00d4b8]" : "text-gray-500"}`}>
                    {monitoringActive ? "Active" : "Inactive"}
                  </span>
                </div>

                {monitoringActive && (
                  <div className="flex items-center justify-center mb-2">
                    <CubeLoader isActive={monitoringActive} />
                  </div>
                )}

                <div className="h-[150px] w-full">
  <LineChart isActive={monitoringActive} height="150px" />
  {monitorStats && monitorStats.anomaly && (
    <div className="mt-2 p-2 bg-[#ff5555]/20 border border-[#ff5555]/40 rounded text-[#ff5555] text-xs font-semibold text-center animate-pulse">
      Anomaly Detected: {monitorStats.anomaly}
    </div>
  )}
</div>

                <div className="grid grid-cols-3 gap-4 text-center">
                  <div className="bg-black/20 backdrop-blur-sm rounded-lg p-2 border border-white/5">
                    <div className="text-lg font-bold text-transparent bg-clip-text bg-gradient-to-r from-[#00d4b8] to-[#7b2cbf] drop-shadow-[0_0_5px_rgba(0,212,184,0.5)]">
                      <Counter from={0} to={monitoringActive ? 120 : 0} duration={1} />
                    </div>
                    <div className="text-xs text-gray-400">Packets</div>
                  </div>
                  <div className="bg-black/20 backdrop-blur-sm rounded-lg p-2 border border-white/5">
                    <div className="text-lg font-bold text-transparent bg-clip-text bg-gradient-to-r from-[#ffaa00] to-[#ff5555] drop-shadow-[0_0_5px_rgba(255,170,0,0.5)]">
                      <Counter from={0} to={monitoringActive ? 3 : 0} duration={1} />
                    </div>
                    <div className="text-xs text-gray-400">Alerts</div>
                  </div>
                  <div className="bg-black/20 backdrop-blur-sm rounded-lg p-2 border border-white/5">
                    <div className="text-lg font-bold text-transparent bg-clip-text bg-gradient-to-r from-[#00d4b8] to-[#00a0e9] drop-shadow-[0_0_5px_rgba(0,212,184,0.5)]">
                      <Counter from={0} to={monitoringActive ? 8 : 0} duration={1} />
                    </div>
                    <div className="text-xs text-gray-400">Services</div>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>

        {/* Threat & Anomaly Analysis */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.3 }}
          className="col-span-12 lg:col-span-6"
        >
          <Card className="overflow-hidden border-0 shadow-lg bg-white/5 backdrop-blur-md dark:bg-black/20 border border-white/5">
            <CardHeader className="pb-2 bg-gradient-to-r from-[#00d4b8]/5 to-transparent border-b border-white/5">
              <CardTitle className="text-lg font-medium flex items-center font-orbitron">
                <AlertTriangle className="h-5 w-5 mr-2 text-[#00d4b8]" />
                <span className="bg-clip-text text-transparent bg-gradient-to-r from-[#00d4b8] to-[#7b2cbf]">
                  Threat & Anomaly Analysis
                </span>
              </CardTitle>
            </CardHeader>
            <CardContent className="p-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <div className="text-sm font-medium mb-2 dark:text-gray-300">Current Severity</div>
                  <div className="h-[150px]">
                    <BarChart data={{
                      high: monitorStats && monitorStats.tcp !== undefined ? monitorStats.tcp : 0,
                      medium: monitorStats && monitorStats.udp !== undefined ? monitorStats.udp : 0,
                      low: monitorStats && monitorStats.icmp !== undefined ? monitorStats.icmp : 0
                    }} height="150px" />
                  </div>
                </div>
                <div>
                  <div className="text-sm font-medium mb-2 dark:text-gray-300">Anomaly Detection</div>
                  <div className="h-[150px]">
                    <DoughnutChart data={{
                      normal: monitorStats && monitorStats.anomaly ? 0 : 100,
                      anomalous: monitorStats && monitorStats.anomaly ? 100 : 0
                    }} height="150px" />
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>

        {/* System Pulse Widgets */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.4 }}
          className="col-span-12 lg:col-span-3"
        >
          <Card className="overflow-hidden border-0 shadow-lg bg-white/5 backdrop-blur-md dark:bg-black/20 border border-white/5">
            <CardHeader className="pb-2 bg-gradient-to-r from-[#00d4b8]/5 to-transparent border-b border-white/5">
              <CardTitle className="text-lg font-medium flex items-center font-orbitron">
                <Network className="h-5 w-5 mr-2 text-[#00d4b8]" />
                <span className="bg-clip-text text-transparent bg-gradient-to-r from-[#00d4b8] to-[#7b2cbf]">
                  Open Ports
                </span>
              </CardTitle>
            </CardHeader>
            <CardContent className="p-4 flex flex-col items-center justify-center">
  <CircularProgress value={monitorStats && monitorStats.open_ports ? monitorStats.open_ports : 0} size={100} label="Detected" glowEffect={true} />
  <div className="mt-2 text-xs text-gray-400">
    Last scan: {monitorStats && monitorStats.last_scan_time ? monitorStats.last_scan_time : "-"}
  </div>
  {monitorStats && monitorStats.open_ports_list && monitorStats.open_ports_list.length > 0 && (
    <div className="w-full mt-4">
      <table className="min-w-full text-xs border border-white/10 rounded bg-black/10">
        <thead>
          <tr className="text-[#00d4b8]">
            <th className="px-2 py-1">Port</th>
            <th className="px-2 py-1">Proto</th>
            <th className="px-2 py-1">Service</th>
          </tr>
        </thead>
        <tbody>
          {monitorStats.open_ports_list.map((p: any, idx: number) => (
            <tr key={idx} className="border-t border-white/10">
              <td className="px-2 py-1">{p.port}</td>
              <td className="px-2 py-1">{p.proto}</td>
              <td className="px-2 py-1">{p.service}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )}
</CardContent>
          </Card>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.5 }}
          className="col-span-12 lg:col-span-3"
        >
          <Card className="overflow-hidden border-0 shadow-lg bg-white/5 backdrop-blur-md dark:bg-black/20 border border-white/5">
            <CardHeader className="pb-2 bg-gradient-to-r from-[#00d4b8]/5 to-transparent border-b border-white/5">
              <CardTitle className="text-lg font-medium flex items-center font-orbitron">
                <Activity className="h-5 w-5 mr-2 text-[#00d4b8]" />
                <span className="bg-clip-text text-transparent bg-gradient-to-r from-[#00d4b8] to-[#7b2cbf]">
                  Security Health
                </span>
              </CardTitle>
            </CardHeader>
            <CardContent className="p-4">
              <div className="flex flex-col items-center justify-center">
                <div className="text-3xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-[#00d4b8] to-[#7b2cbf] drop-shadow-[0_0_5px_rgba(0,212,184,0.5)] mb-2">
                  {monitorStats && monitorStats.security_health !== undefined ? monitorStats.security_health : 100}%
                </div>
                <ProgressBar value={monitorStats && monitorStats.security_health !== undefined ? monitorStats.security_health : 100} height={10} glowEffect={true} />
                <div className="mt-2 text-xs text-gray-400">
                  {monitorStats && monitorStats.risky_services && monitorStats.risky_services.length > 0
                    ? `Risky Services: ${monitorStats.risky_services.join(", ")}`
                    : "No risky services detected"}
                </div>
                <div className="mt-2 text-xs text-gray-400">
                  {monitorStats && monitorStats.cve_findings && monitorStats.cve_findings.length > 0
                    ? `${monitorStats.cve_findings.length} vulnerabilities found`
                    : "No known CVEs detected"}
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.6 }}
          className="col-span-12 lg:col-span-3"
        >
          <Card className="overflow-hidden border-0 shadow-lg bg-white/5 backdrop-blur-md dark:bg-black/20 border border-white/5">
            <CardHeader className="pb-2 bg-gradient-to-r from-[#00d4b8]/5 to-transparent border-b border-white/5">
              <CardTitle className="text-lg font-medium flex items-center font-orbitron">
                <Zap className="h-5 w-5 mr-2 text-[#00d4b8]" />
                <span className="bg-clip-text text-transparent bg-gradient-to-r from-[#00d4b8] to-[#7b2cbf]">
                  Risk Probability
                </span>
              </CardTitle>
            </CardHeader>
            <CardContent className="p-4">
              <div className="flex flex-col items-center justify-center">
                <div className="text-3xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-[#ffaa00] to-[#ff5555] drop-shadow-[0_0_5px_rgba(255,170,0,0.5)] mb-2">
                  {monitorStats && monitorStats.vulnerability_risk !== undefined ? monitorStats.vulnerability_risk : 0}%
                </div>
                <ProgressBar value={monitorStats && monitorStats.vulnerability_risk !== undefined ? monitorStats.vulnerability_risk : 0} color="url(#risk-gradient)" height={10} glowEffect={true} />
                <svg width="0" height="0">
                  <defs>
                    <linearGradient id="risk-gradient" x1="0%" y1="0%" x2="100%" y2="0%">
                      <stop offset="0%" stopColor="#ffaa00" />
                      <stop offset="100%" stopColor="#ff5555" />
                    </linearGradient>
                  </defs>
                </svg>
                <div className="mt-4 text-xs text-gray-400">ML-predicted risk score</div>
              </div>
            </CardContent>
          </Card>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.7 }}
          className="col-span-12 lg:col-span-3"
        >
          <Card className="overflow-hidden border-0 shadow-lg bg-white/5 backdrop-blur-md dark:bg-black/20 border border-white/5">
            <CardHeader className="pb-2 bg-gradient-to-r from-[#00d4b8]/5 to-transparent border-b border-white/5">
              <CardTitle className="text-lg font-medium flex items-center font-orbitron">
                <Clock className="h-5 w-5 mr-2 text-[#00d4b8]" />
                <span className="bg-clip-text text-transparent bg-gradient-to-r from-[#00d4b8] to-[#7b2cbf]">
                  Last Scan Time
                </span>
              </CardTitle>
            </CardHeader>
            <CardContent className="p-4">
              <div className="flex flex-col items-center justify-center h-full">
                <div className="text-xl font-medium text-gray-300 font-mono">
                  {monitorStats && monitorStats.last_scan_time ? monitorStats.last_scan_time : "-"}
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  className="mt-4 text-[#00d4b8] border-[#00d4b8]/20 hover:bg-[#00d4b8]/10"
                >
                  View Details
                </Button>
              </div>
            </CardContent>
          </Card>
        </motion.div>

        {/* --- FinGuardAI: ML Risk Prediction --- */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.8 }}
          className="col-span-12 lg:col-span-6"
        >
          <Card className="overflow-hidden border-0 shadow-lg bg-white/5 backdrop-blur-md dark:bg-black/20 border border-white/5">
            <CardHeader className="pb-2 bg-gradient-to-r from-[#7b2cbf]/5 to-transparent border-b border-white/5">
              <CardTitle className="text-lg font-medium flex items-center font-orbitron">
                <Target className="h-5 w-5 mr-2 text-[#7b2cbf]" />
                <span className="bg-clip-text text-transparent bg-gradient-to-r from-[#7b2cbf] to-[#00d4b8]">
                  AI Risk Prediction (1-Hour Forecast)
                </span>
              </CardTitle>
            </CardHeader>
            <CardContent className="p-4">
              {monitorStats && monitorStats.risk_prediction ? (
                <LineChart 
                  data={monitorStats.risk_prediction.map((value: number, index: number) => ({
                    name: `+${index * 5}min`,
                    value: value
                  }))}
                  height="210"
                  showLegend={false}
                  lineColor="#7b2cbf"
                  areaColor="rgba(123, 43, 191, 0.3)"
                  className="mt-2"
                />
              ) : (
                <div className="flex items-center justify-center h-[210px] text-gray-400">
                  No prediction data available
                </div>
              )}
            </CardContent>
          </Card>
        </motion.div>
        
        {/* --- FinGuardAI: AI-Detected Threats --- */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.85 }}
          className="col-span-12 lg:col-span-6">
          <Card className="overflow-hidden border-0 shadow-lg bg-white/5 backdrop-blur-md dark:bg-black/20 border border-white/5">
            <CardHeader className="pb-2 bg-gradient-to-r from-[#7b2cbf]/5 to-transparent border-b border-white/5">
              <CardTitle className="text-lg font-medium flex items-center font-orbitron">
                <AlertCircle className="h-5 w-5 mr-2 text-[#7b2cbf]" />
                <span className="bg-clip-text text-transparent bg-gradient-to-r from-[#7b2cbf] to-[#00d4b8]">
                  AI-Detected Threats
                </span>
              </CardTitle>
            </CardHeader>
            <CardContent className="p-4">
              {monitorStats && monitorStats.threat_details && monitorStats.threat_details.length > 0 ? (
                <div className="overflow-x-auto">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="text-[#7b2cbf]">Protocol</TableHead>
                        <TableHead className="text-[#7b2cbf]">Source</TableHead>
                        <TableHead className="text-[#7b2cbf]">Destination</TableHead>
                        <TableHead className="text-[#7b2cbf]">Probability</TableHead>
                        <TableHead className="text-[#7b2cbf]">Status</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {monitorStats.threat_details.filter((t: any) => t.is_threat || t.threat_probability > 0.3).map((threat: any, idx: number) => (
                        <TableRow key={idx} className="border-t border-white/10">
                          <TableCell>{threat.protocol}</TableCell>
                          <TableCell className="font-mono text-xs">{threat.src_ip}</TableCell>
                          <TableCell className="font-mono text-xs">{threat.dest_ip}</TableCell>
                          <TableCell>
                            <div className="w-full bg-black/30 rounded-full h-2">
                              <div
                                className={`h-2 rounded-full ${threat.threat_probability > 0.7 ? 'bg-red-500' : threat.threat_probability > 0.4 ? 'bg-yellow-500' : 'bg-green-500'}`}
                                style={{ width: `${Math.round(threat.threat_probability * 100)}%` }}
                              ></div>
                            </div>
                            <div className="text-xs text-right mt-1">{Math.round(threat.threat_probability * 100)}%</div>
                          </TableCell>
                          <TableCell>
                            <Badge 
                              className={`${threat.is_threat ? 'bg-red-500 hover:bg-red-600' : 'bg-green-500 hover:bg-green-600'}`}
                            >
                              {threat.is_threat ? 'THREAT' : 'SAFE'}
                            </Badge>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              ) : (
                <div className="flex items-center justify-center h-[210px] text-gray-400">
                  No threats detected by AI model
                </div>
              )}
            </CardContent>
          </Card>
        </motion.div>

        {/* --- FinGuardAI: Vulnerability Findings Table --- */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.9 }}
          className="col-span-12"
        >
          <Card className="overflow-hidden border-0 shadow-lg bg-white/5 backdrop-blur-md dark:bg-black/20 border border-white/5 mt-6">
            <CardHeader className="pb-2 bg-gradient-to-r from-[#00d4b8]/5 to-transparent border-b border-white/5">
              <CardTitle className="text-lg font-medium flex items-center font-orbitron">
                <Shield className="h-5 w-5 mr-2 text-[#00d4b8]" />
                <span className="bg-clip-text text-transparent bg-gradient-to-r from-[#00d4b8] to-[#7b2cbf]">
                  Vulnerability Findings (NVD)
                </span>
              </CardTitle>
            </CardHeader>
            <CardContent className="p-4">
              {monitorStats && monitorStats.cve_findings && monitorStats.cve_findings.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="min-w-full text-xs border border-white/10 rounded bg-black/10">
                    <thead>
                      <tr className="text-[#00d4b8]">
                        <th className="px-2 py-1">Service</th>
                        <th className="px-2 py-1">Port</th>
                        <th className="px-2 py-1">CVE</th>
                        <th className="px-2 py-1">Description</th>
                        <th className="px-2 py-1">Severity</th>
                      </tr>
                    </thead>
                    <tbody>
                      {monitorStats.cve_findings.map((cve: any, idx: number) => (
                        <tr key={idx} className="border-t border-white/10">
                          <td className="px-2 py-1">{cve.service}</td>
                          <td className="px-2 py-1">{cve.port}</td>
                          <td className="px-2 py-1">
                            <a href={`https://nvd.nist.gov/vuln/detail/${cve.cve}`} target="_blank" rel="noopener noreferrer" className="text-[#00d4b8] underline">{cve.cve}</a>
                          </td>
                          <td className="px-2 py-1">{cve.desc}</td>
                          <td className="px-2 py-1 font-bold" style={{color: cve.severity >= 9 ? '#ff5555' : cve.severity >= 7 ? '#ffaa00' : '#00d4b8'}}>{cve.severity}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="text-gray-400">No vulnerabilities detected for open services on this host.</div>
              )}
            </CardContent>
          </Card>
        </motion.div>
      </div>
    </div>
  )
}

