"use client"

import { useState, useEffect, useRef } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { ThemeToggle } from "@/components/theme-toggle"
import { CircularProgress } from "@/components/circular-progress"
import { StatusLog } from "@/components/status-log"
import { motion } from "framer-motion"
import { io, Socket } from "socket.io-client"

// Import our integrated scan component
import { IntegratedScan } from "@/components/integrated-scan"

export default function ScanPage() {
  const [mounted, setMounted] = useState(false)
  const [isScanning, setIsScanning] = useState(false)
  const [scanProgress, setScanProgress] = useState(0)
  const progressTimer = useRef<NodeJS.Timeout | null>(null)
  const [target, setTarget] = useState("")
  const [scanType, setScanType] = useState("integrated")
  const [scanResult, setScanResult] = useState<string[]>([])
  const [scanError, setScanError] = useState<string | null>(null)
  const [scanMode, setScanMode] = useState<"basic" | "integrated">("integrated")

  useEffect(() => {
    setMounted(true)
    // Check for dashboard-triggered scan
    const quickTarget = localStorage.getItem("dashboardQuickScanTarget");
    if (quickTarget) {
      setTarget(quickTarget);
      setTimeout(() => {
        startScanFromDashboard(quickTarget);
      }, 300); // Give React a tick to update input
    }
  }, [])

  // Helper for dashboard-triggered scan
  const [dashboardScanMsg, setDashboardScanMsg] = useState<string | null>(null);
  const socketRef = useRef<Socket | null>(null);
  
  const startScanFromDashboard = (quickTarget: string) => {
    setDashboardScanMsg("Scan started from Dashboard. Waiting for results...");
    setScanType("basic");
    setIsScanning(true);
    setScanProgress(0);
    setScanResult([]);
    setScanError(null);
    if (socketRef.current) {
      socketRef.current.disconnect();
    }
    if (progressTimer.current) {
      clearInterval(progressTimer.current);
    }
    progressTimer.current = setInterval(() => {
      setScanProgress(prev => (prev < 95 ? prev + 1 : 95));
    }, 200);
    const socket = io("http://127.0.0.1:5001");
    socketRef.current = socket;
    socket.emit("start_scan", { target: quickTarget, scan_type: "basic" });
    socket.on("scan_output", (data) => {
      if (typeof data.progress === "number") {
        setScanProgress(data.progress);
      }
      if (data.line === "SCAN_COMPLETE") {
        setIsScanning(false);
        setScanProgress(100);
        setDashboardScanMsg("Scan complete. You may review the results below.");
        localStorage.removeItem("dashboardQuickScanTarget");
        if (progressTimer.current) clearInterval(progressTimer.current);
      } else if (data.line.startsWith("Error:")) {
        setScanError(data.line);
        setIsScanning(false);
        setDashboardScanMsg(null);
        localStorage.removeItem("dashboardQuickScanTarget");
        if (progressTimer.current) clearInterval(progressTimer.current);
      } else {
        setScanResult((prev) => [...prev, data.line]);
      }
    });
    socket.on("disconnect", () => {
      setIsScanning(false);
      setDashboardScanMsg(null);
      localStorage.removeItem("dashboardQuickScanTarget");
      if (progressTimer.current) clearInterval(progressTimer.current);
    });
  };

  const startScan = async () => {
    if (!target) {
      setScanError("Please enter a target IP or hostname.");
      return;
    }
    setIsScanning(true);
    setScanProgress(0);
    setScanResult([]);
    setScanError(null);

    // Disconnect any previous socket
    if (socketRef.current) {
      socketRef.current.disconnect();
    }
    // Clear any previous timer
    if (progressTimer.current) {
      clearInterval(progressTimer.current);
    }
    // Start timer-based progress
    const interval = scanType === "deep" ? 400 : 200;
    progressTimer.current = setInterval(() => {
      setScanProgress(prev => (prev < 95 ? prev + 1 : 95));
    }, interval);

    const socket = io("http://127.0.0.1:5001");
    socketRef.current = socket;

    socket.emit("start_scan", { target, scan_type: scanType });
    socket.on("scan_output", (data) => {
      if (typeof data.progress === "number") {
        setScanProgress(data.progress);
      }
      if (data.line === "SCAN_COMPLETE") {
        setIsScanning(false);
        socket.disconnect();
        setScanProgress(100);
        if (progressTimer.current) {
          clearInterval(progressTimer.current);
        }
      } else if (data.line.startsWith("Error:")) {
        setScanError(data.line);
        setIsScanning(false);
        socket.disconnect();
        if (progressTimer.current) {
          clearInterval(progressTimer.current);
        }
      } else {
        setScanResult(prev => [...prev, data.line]);
      }
    });
    socket.on("disconnect", () => {
      setIsScanning(false);
      if (progressTimer.current) {
        clearInterval(progressTimer.current);
      }
    });
  }

  // Clean up timer if component unmounts
  useEffect(() => {
    return () => {
      if (progressTimer.current) {
        clearInterval(progressTimer.current);
      }
    };
  }, []);

  if (!mounted) return null

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between bg-white/10 dark:bg-black/20 p-4 rounded-lg shadow-sm">
        <h1 className="text-2xl font-bold tracking-tight dark:text-white">Security Scan</h1>
        <ThemeToggle />
      </div>
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }}>
        <div className="flex justify-end mb-2">
          <div className="inline-flex p-1 bg-muted rounded-md">
            <button 
              className={`px-3 py-1 text-sm rounded-md transition-colors ${scanMode === 'basic' ? 'bg-primary text-primary-foreground' : 'hover:bg-muted-foreground/10'}`}
              onClick={() => setScanMode('basic')}
            >
              Basic Scan
            </button>
            <button 
              className={`px-3 py-1 text-sm rounded-md transition-colors ${scanMode === 'integrated' ? 'bg-primary text-primary-foreground' : 'hover:bg-muted-foreground/10'}`}
              onClick={() => setScanMode('integrated')}
            >
              Integrated Scan
            </button>
          </div>
        </div>
        
        {scanMode === 'integrated' ? (
          <IntegratedScan />
        ) : (
          <Card className="w-full">
            <CardHeader className="pb-2">
              <CardTitle>Basic Vulnerability Scanner</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid gap-4">
                <div className="grid grid-cols-2 gap-4">
                  <div className="flex flex-col gap-2">
                    <Label htmlFor="scan-target">Target</Label>
                    <Input
                      id="scan-target"
                      placeholder="Enter IP or hostname"
                      disabled={isScanning}
                      value={target}
                      onChange={e => setTarget(e.target.value)}
                    />
                  </div>

                  <div className="flex flex-col gap-2">
                    <Label htmlFor="scan-type">Scan Type</Label>
                    <Select value={scanType} onValueChange={setScanType} disabled={isScanning}>
                      <SelectTrigger id="scan-type">
                        <SelectValue placeholder="Select scan type" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="basic">Basic</SelectItem>
                        <SelectItem value="deep">Deep</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>

                <Button 
                  onClick={startScan} 
                  disabled={isScanning || !target}
                  className="w-full"
                >
                  {isScanning ? "Scanning..." : "Start Scan"}
                </Button>

                {scanError && (
                  <div className="p-3 text-sm bg-red-100 border border-red-300 rounded text-red-800">
                    {scanError}
                  </div>
                )}

                {dashboardScanMsg && (
                  <div className="p-3 text-sm bg-blue-100 border border-blue-300 rounded text-blue-800">
                    {dashboardScanMsg}
                  </div>
                )}

                {isScanning && (
                  <div className="flex flex-col items-center gap-4 p-4">
                    <CircularProgress value={scanProgress} size="lg" />
                    <div className="text-center">
                      <p className="text-sm text-muted-foreground">
                        Scanning {target}... ({scanProgress}% complete)
                      </p>
                    </div>
                  </div>
                )}

                <StatusLog title="Scan Log" messages={scanResult} />
              </div>
            </CardContent>
          </Card>
        )}
      </motion.div>
    </div>
  )
}
