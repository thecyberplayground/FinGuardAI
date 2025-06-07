"use client"

import { useEffect, useRef, useState } from "react"
import { motion } from "framer-motion"

interface StatusLogProps {
  title?: string
  isActive?: boolean
  maxLines?: number
  lines?: any[]
  error?: string | null
  messages?: any[]
}

// Helper function to safely stringify any value
const safeStringify = (value: any): string => {
  if (value === null || value === undefined) {
    return '';
  }
  if (typeof value === 'object') {
    try {
      return JSON.stringify(value);
    } catch (e) {
      return '[Object]';
    }
  }
  return String(value);
};

export function StatusLog({ title, isActive = false, maxLines = 10, lines, error, messages }: StatusLogProps) {
  // Create a single source of log messages with proper fallback
  const [demoLogs, setDemoLogs] = useState<string[]>([]);
  const logRef = useRef<HTMLDivElement>(null);
  
  // Generate demo log messages if isActive is true and no real logs provided
  useEffect(() => {
    if (!isActive || messages?.length || lines?.length) {
      return;
    }
    
    setDemoLogs(["System idle. Ready to scan."]);
    
    const scanMessages = [
      "Initializing scan...",
      "Checking network connectivity...",
      "Resolving target hostname...",
      "Scanning port 21 (FTP)...",
      "Scanning port 22 (SSH)...",
      "Scanning port 23 (Telnet)...",
      "Scanning port 25 (SMTP)...",
      "Scanning port 53 (DNS)...",
      "Scanning port 80 (HTTP)...",
      "Scanning port 443 (HTTPS)...",
      "Checking for SSL/TLS vulnerabilities...",
      "Analyzing response headers...",
      "Checking for outdated software versions...",
      "Running vulnerability database comparison...",
      "Checking for common misconfigurations...",
      "Analyzing firewall rules...",
      "Checking for open database ports...",
      "Running ML prediction models...",
      "Analyzing anomaly patterns...",
      "Generating threat assessment...",
      "Calculating risk scores...",
      "Scan complete. Generating report...",
    ];
    
    let currentIndex = 0;
    const interval = setInterval(() => {
      if (currentIndex < scanMessages.length) {
        setDemoLogs((prev) => {
          const timestamp = new Date().toLocaleTimeString();
          const newLog = `[${timestamp}] ${scanMessages[currentIndex]}`;
          return [...prev, newLog].slice(-maxLines);
        });
        currentIndex++;
      } else {
        clearInterval(interval);
      }
    }, 1000);
    
    return () => clearInterval(interval);
  }, [isActive, maxLines, messages, lines]);

  // Auto-scroll to bottom when logs update
  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [demoLogs, messages, lines]);

  // Determine which logs to display with priority: messages > lines > demoLogs
  const logsToDisplay = (messages && messages.length > 0) ? messages : 
                       (lines && lines.length > 0) ? lines : 
                       demoLogs || [];

  // Process logs to ensure they're all valid strings
  const processedLogs = logsToDisplay.map(log => safeStringify(log)).filter(Boolean);

  // Display the title if provided
  const titleElement = title ? (
    <div className="text-sm font-medium mb-2 text-gray-300">{title}</div>
  ) : null;

  return (
    <div className="space-y-2">
      {titleElement}
      <div
        ref={logRef}
        className="bg-black/20 backdrop-blur-sm rounded-md p-3 font-mono text-xs text-[#00d4b8] h-40 overflow-y-auto border border-white/5"
      >
        {processedLogs.map((log, index) => (
          <motion.div
            key={index}
            initial={{ opacity: 0, x: -5 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.3 }}
            className="mb-1"
          >
            {log}
          </motion.div>
        ))}
        {error && (
          <motion.div className="text-red-500 mt-2">{safeStringify(error)}</motion.div>
        )}
        {processedLogs.length === 0 && !error && (
          <div className="text-gray-400 italic">No log messages</div>
        )}
      </div>
    </div>
  );
}
