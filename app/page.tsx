"use client"

import type React from "react"

import { useState, useEffect } from "react"
import { useRouter } from "next/navigation"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardContent } from "@/components/ui/card"
import { Lock } from "lucide-react"
import { motion } from "framer-motion"
import ParticleBackground from "@/components/particle-background"

export default function LoginPage() {
  const [isLoading, setIsLoading] = useState(false)
  const router = useRouter()
  const [mounted, setMounted] = useState(false)

  useEffect(() => {
    setMounted(true)

    // Add the Orbitron font for the futuristic look
    const link = document.createElement("link")
    link.href = "https://fonts.googleapis.com/css2?family=Orbitron:wght@400;500;600;700&display=swap"
    link.rel = "stylesheet"
    document.head.appendChild(link)

    return () => {
      document.head.removeChild(link)
    }
  }, [])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsLoading(true)

    // Simulate authentication delay
    setTimeout(() => {
      setIsLoading(false)
      router.push("/dashboard")
    }, 1000)
  }

  if (!mounted) return null

  return (
    <div className="min-h-screen w-full flex items-center justify-center relative overflow-hidden bg-gray-50 dark:bg-[#121620]">
      {/* Particle Background */}
      <ParticleBackground />

      <motion.div
        initial={{ opacity: 0, scale: 0.9 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: 0.5, type: "spring", stiffness: 100 }}
        className="w-full max-w-md p-8 space-y-8 z-10"
      >
        <Card className="border border-gray-200 dark:border-white/10 shadow-xl bg-white/80 dark:bg-black/40 backdrop-blur-md overflow-hidden relative">
          {/* Gradient border effect */}
          <div className="absolute inset-0 rounded-lg p-[1px] bg-gradient-to-r from-[#00d4b8] to-[#7b2cbf] opacity-70"></div>

          <CardContent className="pt-6 relative z-10 bg-white/90 dark:bg-black/60 backdrop-blur-md rounded-b-lg">
            <form onSubmit={handleSubmit} className="space-y-6">
              <div className="flex justify-center mb-6">
                <div className="bg-gradient-to-r from-[#00d4b8]/30 to-[#7b2cbf]/30 p-4 rounded-full border border-white/20 shadow-lg">
                  <div className="relative">
                    <Lock className="h-12 w-12 text-gray-800 dark:text-white" />
                    <span className="absolute -top-1 -right-1 text-xl font-bold text-[#00d4b8]">$</span>
                    <span className="absolute -bottom-1 -left-1 text-xl font-bold text-[#7b2cbf]">$</span>
                  </div>
                </div>
              </div>

              <div className="text-center mb-6">
                <h1 className="text-2xl font-bold tracking-tight text-gray-800 dark:text-white font-orbitron bg-clip-text text-transparent bg-gradient-to-r from-[#00d4b8] to-[#7b2cbf] drop-shadow-[0_0_3px_rgba(0,212,184,0.8)]">
                  FinGuardAI Login
                </h1>
                <p className="mt-2 text-sm text-gray-600 dark:text-gray-300 drop-shadow-sm">
                  Sign in to access the cybersecurity dashboard
                </p>
              </div>

              <div className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="username" className="text-gray-700 dark:text-white font-medium">
                    Username
                  </Label>
                  <div className="relative">
                    <Input
                      id="username"
                      placeholder="Enter your username"
                      required
                      autoComplete="username"
                      className="bg-white/80 dark:bg-black/30 border border-gray-300 dark:border-white/20 focus:border-[#00d4b8] focus:ring-[#00d4b8] text-gray-800 dark:text-white placeholder:text-gray-400 pl-10 rounded-md"
                    />
                    <div className="absolute left-3 top-2.5 text-[#00d4b8]">
                      <svg
                        xmlns="http://www.w3.org/2000/svg"
                        width="16"
                        height="16"
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="2"
                        strokeLinecap="round"
                        strokeLinejoin="round"
                      >
                        <path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"></path>
                        <circle cx="12" cy="7" r="4"></circle>
                      </svg>
                    </div>
                  </div>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="password" className="text-gray-700 dark:text-white font-medium">
                    Password
                  </Label>
                  <div className="relative">
                    <Input
                      id="password"
                      type="password"
                      placeholder="Enter your password"
                      required
                      autoComplete="current-password"
                      className="bg-white/80 dark:bg-black/30 border border-gray-300 dark:border-white/20 focus:border-[#00d4b8] focus:ring-[#00d4b8] text-gray-800 dark:text-white placeholder:text-gray-400 pl-10 rounded-md"
                    />
                    <div className="absolute left-3 top-2.5 text-[#00d4b8]">
                      <Lock className="h-4 w-4" />
                    </div>
                  </div>
                </div>

                <Button
                  type="submit"
                  className="w-full bg-gradient-to-r from-[#00d4b8] to-[#7b2cbf] hover:from-[#00d4b8]/90 hover:to-[#7b2cbf]/90 text-white font-medium relative overflow-hidden group"
                  disabled={isLoading}
                >
                  {/* Pulsating effect */}
                  <span className="absolute inset-0 bg-gradient-to-r from-[#00d4b8] to-[#7b2cbf] opacity-0 group-hover:opacity-30 animate-pulse"></span>

                  {isLoading ? (
                    <div className="flex items-center">
                      <svg
                        className="animate-spin -ml-1 mr-3 h-4 w-4 text-white"
                        xmlns="http://www.w3.org/2000/svg"
                        fill="none"
                        viewBox="0 0 24 24"
                      >
                        <circle
                          className="opacity-25"
                          cx="12"
                          cy="12"
                          r="10"
                          stroke="currentColor"
                          strokeWidth="4"
                        ></circle>
                        <path
                          className="opacity-75"
                          fill="currentColor"
                          d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                        ></path>
                      </svg>
                      Logging in...
                    </div>
                  ) : (
                    "Login"
                  )}
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
      </motion.div>
    </div>
  )
}

