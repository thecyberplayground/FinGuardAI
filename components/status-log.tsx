"use client"

import { useEffect, useRef, useState } from "react"
import { motion } from "framer-motion"

interface StatusLogProps {
  isActive?: boolean
  maxLines?: number
  lines?: string[]
  error?: string | null
}

export function StatusLog({ isActive = false, maxLines = 10, lines, error }: StatusLogProps) {
  const [logs, setLogs] = useState<string[]>([])
  const logRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!isActive) {
      setLogs(["System idle. Ready to scan."])
      return
    }
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
    ]
    let currentIndex = 0
    const interval = setInterval(() => {
      if (currentIndex < scanMessages.length) {
        setLogs((prev) => {
          const timestamp = new Date().toLocaleTimeString()
          const newLog = `[${timestamp}] ${scanMessages[currentIndex]}`
          const updatedLogs = [...prev, newLog].slice(-maxLines)
          return updatedLogs
        })
        currentIndex++
      } else {
        clearInterval(interval)
      }
    }, 1000)
    return () => clearInterval(interval)
  }, [isActive, maxLines])

  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight
    }
  }, [logs, lines])

  if (lines && lines.length > 0) {
    return (
      <div
        ref={logRef}
        className="bg-black/20 backdrop-blur-sm rounded-md p-3 font-mono text-xs text-[#00d4b8] h-40 overflow-y-auto border border-white/5"
      >
        {lines.map((log, index) => (
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
          <motion.div className="text-red-500 mt-2">{error}</motion.div>
        )}
      </div>
    )
  }

  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [logs, lines]);

  // Always render the same structure; choose which lines to show
  const displayLines = (lines && lines.length > 0) ? lines : logs;

  return (
    <div
      ref={logRef}
      className="bg-black/20 backdrop-blur-sm rounded-md p-3 font-mono text-xs text-[#00d4b8] h-40 overflow-y-auto border border-white/5"
    >
      {displayLines.map((log, index) => (
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
        <motion.div className="text-red-500 mt-2">{error}</motion.div>
      )}
    </div>
  );
}

