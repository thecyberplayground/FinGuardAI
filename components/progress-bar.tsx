"use client"

import { useEffect, useState } from "react"
import { motion } from "framer-motion"

interface ProgressBarProps {
  value: number
  color?: string
  backgroundColor?: string
  height?: number
  label?: string
  glowEffect?: boolean
}

export function ProgressBar({
  value,
  color = "url(#gradient)",
  backgroundColor = "rgba(255, 255, 255, 0.1)",
  height = 8,
  label,
  glowEffect = true,
}: ProgressBarProps) {
  const [progress, setProgress] = useState(0)

  useEffect(() => {
    setProgress(value)
  }, [value])

  return (
    <div className="w-full">
      {label && (
        <div className="flex justify-between text-xs mb-1">
          <span className="text-gray-400">{label}</span>
          <span className="text-gray-300">{progress}%</span>
        </div>
      )}
      <div className="relative">
        <svg width="0" height="0">
          <defs>
            <linearGradient id="gradient" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#00d4b8" />
              <stop offset="100%" stopColor="#7b2cbf" />
            </linearGradient>

            {/* Glow filter */}
            {glowEffect && (
              <filter id="glow-bar" x="-20%" y="-20%" width="140%" height="140%">
                <feGaussianBlur stdDeviation="2" result="blur" />
                <feComposite in="SourceGraphic" in2="blur" operator="over" />
              </filter>
            )}
          </defs>
        </svg>

        <div
          className="w-full rounded-full overflow-hidden"
          style={{
            backgroundColor: backgroundColor,
            height: `${height}px`,
          }}
        >
          <motion.div
            className="h-full rounded-full"
            style={{
              background: color,
              filter: glowEffect ? "url(#glow-bar)" : undefined,
            }}
            initial={{ width: 0 }}
            animate={{ width: `${progress}%` }}
            transition={{ duration: 0.5 }}
          />
        </div>
      </div>
    </div>
  )
}

