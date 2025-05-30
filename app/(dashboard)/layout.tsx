import type React from "react"
import Sidebar from "@/components/sidebar"

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <div className="flex min-h-screen bg-gray-50 dark:bg-[#121620] transition-colors duration-200">
      <Sidebar />
      <div className="flex-1 ml-16 md:ml-20">
        <main className="p-4">{children}</main>
      </div>
    </div>
  )
}

