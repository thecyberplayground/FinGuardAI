"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import { cn } from "@/lib/utils"
import { Home, Search, FileText, Settings, LogOut, Shield, Database, AlertTriangle, Cpu, Activity } from "lucide-react"
import { motion } from "framer-motion"

const navItems = [
  {
    name: "Dashboard",
    href: "/dashboard",
    icon: Home,
  },
  {
    name: "Scan",
    href: "/scan",
    icon: Search,
  },
  {
    name: "Reports",
    href: "/reports",
    icon: FileText,
  },
  {
    name: "Analytics",
    href: "/analytics",
    icon: Activity,
  },
  {
    name: "Threats",
    href: "/threats",
    icon: AlertTriangle,
  },
  {
    name: "Network",
    href: "/network",
    icon: Database,
  },
  {
    name: "ML Models",
    href: "/models",
    icon: Cpu,
  },
  {
    name: "Settings",
    href: "/settings",
    icon: Settings,
  },
]

export default function Sidebar() {
  const pathname = usePathname()

  return (
    <div className="fixed inset-y-0 left-0 z-50 w-16 md:w-20 bg-white dark:bg-[#161b22] text-gray-800 dark:text-white transition-colors duration-200 border-r border-gray-200 dark:border-white/5">
      <div className="flex h-16 items-center justify-center border-b border-gray-200 dark:border-white/5">
        <Shield className="h-8 w-8 text-transparent bg-clip-text bg-gradient-to-r from-[#00d4b8] to-[#7b2cbf]" />
      </div>

      <div className="flex flex-col items-center py-4 space-y-4">
        {navItems.map((item) => {
          const isActive = pathname === item.href

          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "relative flex items-center justify-center w-10 h-10 rounded-md transition-all duration-200 group",
                isActive
                  ? "text-white dark:text-white"
                  : "text-gray-500 dark:text-gray-400 hover:text-gray-800 dark:hover:text-white",
              )}
            >
              {isActive && (
                <motion.div
                  layoutId="sidebar-indicator"
                  className="absolute inset-0 rounded-md bg-gradient-to-r from-[#00d4b8]/20 to-[#7b2cbf]/20"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ duration: 0.2 }}
                />
              )}

              <item.icon
                className={cn(
                  "h-5 w-5 transition-all duration-200",
                  isActive
                    ? "text-transparent bg-clip-text bg-gradient-to-r from-[#00d4b8] to-[#7b2cbf]"
                    : "text-gray-500 dark:text-gray-400 group-hover:text-gray-800 dark:group-hover:text-white",
                )}
              />

              {/* Tooltip */}
              <div className="absolute left-full ml-2 px-2 py-1 bg-white dark:bg-[#161b22] rounded text-xs whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity duration-200 pointer-events-none">
                {item.name}
              </div>

              {/* Glow effect for active item */}
              {isActive && (
                <div className="absolute inset-0 rounded-md bg-gradient-to-r from-[#00d4b8]/10 to-[#7b2cbf]/10 blur-sm" />
              )}
            </Link>
          )
        })}
      </div>

      <div className="absolute bottom-0 w-full flex justify-center pb-4">
        <Link
          href="/"
          className="flex items-center justify-center w-10 h-10 rounded-md text-gray-500 dark:text-gray-400 hover:text-gray-800 dark:hover:text-white transition-colors duration-200 group"
        >
          <LogOut className="h-5 w-5" />

          {/* Tooltip */}
          <div className="absolute left-full ml-2 px-2 py-1 bg-white dark:bg-[#161b22] rounded text-xs whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity duration-200 pointer-events-none">
            Logout
          </div>
        </Link>
      </div>
    </div>
  )
}

