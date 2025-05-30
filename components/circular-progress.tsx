"use client"

import { useEffect, useState } from "react"
import { motion } from "framer-motion"

interface CircularProgressProps {
  value: number
  size?: number
  strokeWidth?: number
  color?: string
  backgroundColor?: string
  showValue?: boolean
  label?: string
  glowEffect?: boolean
}

export function CircularProgress({
  value,
  size = 120,
  strokeWidth = 8,
  color = "url(#gradient)",
  backgroundColor = "rgba(255, 255, 255, 0.1)",
  showValue = true,
  label,
  glowEffect = true,
}: CircularProgressProps) {
  const [progress, setProgress] = useState(0)

  // Animate progress on mount or when value changes
  useEffect(() => {
    setProgress(value)
  }, [value])

  const radius = (size - strokeWidth) / 2
  const circumference = radius * 2 * Math.PI
  const strokeDashoffset = circumference - (progress / 100) * circumference

  return (
    <div className="relative" style={{ width: size, height: size }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="transform -rotate-90">
        {/* Gradient definition */}
        <defs>
          <linearGradient id="gradient" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#00d4b8" />
            <stop offset="100%" stopColor="#7b2cbf" />
          </linearGradient>

          {/* Glow filter */}
          {glowEffect && (
            <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="3" result="blur" />
              <feComposite in="SourceGraphic" in2="blur" operator="over" />
            </filter>
          )}
        </defs>

        {/* Background circle */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="transparent"
          stroke={backgroundColor}
          strokeWidth={strokeWidth}
          className="opacity-20"
        />

        {/* Progress circle */}
        <motion.circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="transparent"
          stroke={color}
          strokeWidth={strokeWidth}
          strokeDasharray={circumference}
          initial={{ strokeDashoffset: circumference }}
          animate={{ strokeDashoffset }}
          transition={{ duration: 1, ease: "easeInOut" }}
          strokeLinecap="round"
          filter={glowEffect ? "url(#glow)" : undefined}
        />
      </svg>

      {/* Percentage text */}
      {showValue && (
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <motion.span
            className="text-xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-[#00d4b8] to-[#7b2cbf]"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.5 }}
          >
            {Math.round(progress)}%
          </motion.span>
          {label && <span className="text-xs text-gray-400 mt-1">{label}</span>}
        </div>
      )}
    </div>
  )
}

