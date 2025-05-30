"use client"

import { useState, useEffect } from "react"
import { motion } from "framer-motion"

export function LiveClock() {
  const [time, setTime] = useState<string>("")
  const [date, setDate] = useState<string>("")

  useEffect(() => {
    const updateTime = () => {
      const now = new Date()
      setTime(now.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }))
      setDate(
        now.toLocaleDateString(undefined, {
          weekday: "short",
          year: "numeric",
          month: "short",
          day: "numeric",
        }),
      )
    }

    updateTime()
    const interval = setInterval(updateTime, 1000)

    return () => clearInterval(interval)
  }, [])

  return (
    <div className="flex flex-col items-end">
      <motion.div
        className="text-sm font-medium bg-clip-text text-transparent bg-gradient-to-r from-[#00d4b8] to-[#7b2cbf] font-mono"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.5 }}
      >
        {time}
      </motion.div>
      <div className="text-xs text-gray-500 dark:text-gray-400">{date}</div>
    </div>
  )
}

