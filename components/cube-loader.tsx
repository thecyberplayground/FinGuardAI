"use client"

import { motion } from "framer-motion"

interface CubeLoaderProps {
  size?: number
  isActive?: boolean
}

export function CubeLoader({ size = 40, isActive = true }: CubeLoaderProps) {
  if (!isActive) return null

  return (
    <div className="flex items-center justify-center" style={{ height: size, width: size }}>
      <div className="relative" style={{ height: size, width: size }}>
        {/* Front face */}
        <motion.div
          className="absolute inset-0 bg-gradient-to-br from-[#00d4b8]/50 to-[#7b2cbf]/50 backdrop-blur-sm border border-white/10"
          animate={{
            rotateX: [0, 90, 180, 270, 360],
            rotateY: [0, 90, 180, 270, 360],
          }}
          transition={{
            duration: 4,
            ease: "linear",
            repeat: Number.POSITIVE_INFINITY,
          }}
          style={{
            transformStyle: "preserve-3d",
            transformOrigin: "center center",
          }}
        />

        {/* Glow effect */}
        <div
          className="absolute inset-0 bg-[#00d4b8]/20 blur-md rounded-full"
          style={{
            animation: "pulse 2s infinite",
          }}
        />
      </div>
    </div>
  )
}

