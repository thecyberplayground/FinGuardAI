import { useState, useRef, useEffect } from "react";
import { io, Socket } from "socket.io-client";

export interface ScanSocketState {
  isScanning: boolean;
  scanProgress: number;
  scanResult: string[];
  scanError: string | null;
  startScan: (target: string, scanType: string) => void;
}

export function useScanSocket(): ScanSocketState {
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanResult, setScanResult] = useState<string[]>([]);
  const [scanError, setScanError] = useState<string | null>(null);
  const socketRef = useRef<Socket | null>(null);

  const startScan = (target: string, scanType: string) => {
    if (!target) {
      setScanError("Please enter a target IP or hostname.");
      return;
    }
    setIsScanning(true);
    setScanProgress(0);
    setScanResult([]);
    setScanError(null);

    if (socketRef.current) {
      socketRef.current.disconnect();
    }
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
      } else if (data.line.startsWith("Error:")) {
        setScanError(data.line);
        setIsScanning(false);
        socket.disconnect();
      } else {
        setScanResult((prev) => [...prev, data.line]);
      }
    });
    socket.on("disconnect", () => {
      setIsScanning(false);
    });
  };

  useEffect(() => {
    return () => {
      if (socketRef.current) {
        socketRef.current.disconnect();
      }
    };
  }, []);

  return { isScanning, scanProgress, scanResult, scanError, startScan };
}
