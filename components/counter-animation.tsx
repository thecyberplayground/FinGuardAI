"use client"

import { useEffect, useState } from "react"
import { useMotionValue, useTransform, animate } from "framer-motion"

interface CounterProps {
  from?: number
  to: number
  duration?: number
  className?: string
  label?: string
  prefix?: string
  suffix?: string
  glowEffect?: boolean
}

export function Counter({
  from = 0,
  to,
  duration = 2,
  className,
  label,
  prefix = "",
  suffix = "",
  glowEffect = true,
}: CounterProps) {
  const count = useMotionValue(from)
  const rounded = useTransform(count, (latest) => Math.round(latest))
  const [displayValue, setDisplayValue] = useState(from)

  useEffect(() => {
    const animation = animate(count, to, { duration })

    const unsubscribe = rounded.onChange(setDisplayValue)

    return () => {
      animation.stop()
      unsubscribe()
    }
  }, [count, rounded, to, duration])

  return (
    <div className="flex flex-col items-center justify-center">
      <span
        className={cn(
          "bg-clip-text text-transparent bg-gradient-to-r from-[#00d4b8] to-[#7b2cbf] font-bold",
          glowEffect && "drop-shadow-[0_0_5px_rgba(0,212,184,0.5)]",
          className,
        )}
      >
        {prefix}
        {displayValue}
        {suffix}
      </span>
      {label && <span className="text-xs text-gray-400 mt-1">{label}</span>}
    </div>
  )
}

function cn(...classes: (string | boolean | undefined)[]) {
  return classes.filter(Boolean).join(" ")
}

