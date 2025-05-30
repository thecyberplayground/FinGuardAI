"use client"

import * as React from "react"
import { Moon, Sun } from "lucide-react"
import { useTheme } from "next-themes"
import { motion } from "framer-motion"

export function ThemeToggle() {
  const { setTheme, theme, resolvedTheme } = useTheme()
  const [mounted, setMounted] = React.useState(false)

  React.useEffect(() => {
    setMounted(true)
  }, [])

  if (!mounted) {
    return (
      <div className="w-12 h-6 rounded-full bg-gray-700/30 flex items-center p-1">
        <div className="w-4 h-4 rounded-full bg-gray-400"></div>
      </div>
    )
  }

  // Use resolvedTheme as a fallback for SSR
  const isDark = resolvedTheme === "dark"

  return (
    <button
      onClick={() => setTheme(isDark ? "light" : "dark")}
      className={`w-12 h-6 rounded-full flex items-center p-1 transition-colors duration-300 ${
        isDark
          ? "bg-gradient-to-r from-[#00d4b8]/30 to-[#7b2cbf]/30"
          : "bg-gradient-to-r from-[#00d4b8]/20 to-[#7b2cbf]/20"
      }`}
      aria-label={`Switch to ${isDark ? "light" : "dark"} mode`}
      type="button"
    >
      <motion.div
        className={`w-4 h-4 rounded-full flex items-center justify-center ${isDark ? "bg-[#00d4b8]" : "bg-[#7b2cbf]"}`}
        animate={{ x: isDark ? 0 : 24 }}
        transition={{ type: "spring", stiffness: 300, damping: 20 }}
      >
        {isDark ? <Moon className="h-3 w-3 text-[#0d1117]" /> : <Sun className="h-3 w-3 text-white" />}
      </motion.div>
    </button>
  )
}

