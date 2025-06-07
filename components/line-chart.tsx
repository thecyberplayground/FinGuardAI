"use client"

import { useEffect, useRef, useState } from "react"
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Filler,
  type ChartData,
  type ChartOptions,
} from "chart.js"
import { Line } from "react-chartjs-2"

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Title, Tooltip, Legend, Filler)

interface LineChartProps {
  isActive?: boolean
  title?: string
  labels?: string[]
  datasets?: {
    label: string
    data: number[]
    borderColor?: string
    backgroundColor?: string
    borderWidth?: number
    fill?: boolean
    tension?: number
  }[]
  height?: string
  futuristic?: boolean
}

export function LineChart({
  isActive = false,
  title,
  labels: initialLabels,
  datasets: initialDatasets,
  height = "200px",
  futuristic = true,
}: LineChartProps) {
  const chartRef = useRef<ChartJS<"line">>(null)
  const [chartData, setChartData] = useState<ChartData<"line">>({
    labels: initialLabels || [],
    datasets: initialDatasets || [
      {
        label: "Packet Activity",
        data: [],
        borderColor: "#00d4b8",
        backgroundColor: "rgba(0, 212, 184, 0.2)",
        tension: 0.4,
        fill: true,
        borderWidth: 2,
      },
    ],
  })

  // Apply gradient to chart
  useEffect(() => {
    const chart = chartRef.current

    if (!chart || !futuristic) return

    const ctx = chart.ctx
    const gradient = ctx.createLinearGradient(0, 0, 0, chart.height)
    gradient.addColorStop(0, "rgba(0, 212, 184, 0.5)")
    gradient.addColorStop(1, "rgba(123, 44, 191, 0.1)")

    const updatedDatasets = chart.data.datasets.map((dataset) => ({
      ...dataset,
      backgroundColor: gradient,
    }))

    chart.data.datasets = updatedDatasets
    chart.update()
  }, [futuristic])

  const options: ChartOptions<"line"> = {
    responsive: true,
    maintainAspectRatio: false,
    animation: {
      duration: 1000,
    },
    scales: {
      y: {
        beginAtZero: true,
        grid: {
          color: "rgba(255, 255, 255, 0.05)",
        },
        ticks: {
          color: "#a0aec0",
          font: {
            size: 10,
          },
        },
        border: {
          display: false,
        },
      },
      x: {
        grid: {
          display: false,
        },
        ticks: {
          color: "#a0aec0",
          font: {
            size: 10,
          },
        },
        border: {
          display: false,
        },
      },
    },
    plugins: {
      legend: {
        display: !!title,
        position: "top",
        labels: {
          color: "#a0aec0",
          font: {
            size: 10,
          },
          usePointStyle: true,
          pointStyle: "circle",
        },
      },
      tooltip: {
        backgroundColor: "rgba(0, 0, 0, 0.7)",
        titleFont: {
          size: 12,
        },
        bodyFont: {
          size: 11,
        },
        padding: 8,
        cornerRadius: 4,
        displayColors: false,
      },
      title: {
        display: !!title,
        text: title || "",
        color: "#a0aec0",
        font: {
          size: 12,
        },
      },
    },
  }

  useEffect(() => {
    if (initialLabels && initialDatasets) {
      setChartData({
        labels: initialLabels,
        datasets: initialDatasets,
      })
      return
    }

    if (!isActive) {
      setChartData({
        labels: ["00:00", "00:05", "00:10", "00:15", "00:20"],
        datasets: [
          {
            label: "Packet Activity",
            data: [0, 0, 0, 0, 0],
            borderColor: "#00d4b8",
            backgroundColor: "rgba(0, 212, 184, 0.2)",
            tension: 0.4,
            fill: true,
            borderWidth: 2,
          },
        ],
      })
      return
    }

    const interval = setInterval(() => {
      const now = new Date()
      const timeString = now.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })

      setChartData((prevData) => {
        const newLabels = [...(prevData.labels as string[]), timeString].slice(-20)
        const newData = [...(prevData.datasets[0].data as number[]), Math.floor(Math.random() * 50) + 10].slice(-20)

        return {
          labels: newLabels,
          datasets: [
            {
              ...prevData.datasets[0],
              data: newData,
            },
          ],
        }
      })
    }, 1000)

    return () => clearInterval(interval)
  }, [isActive, initialLabels, initialDatasets])

  return (
    <div style={{ height, width: "100%" }} className="relative">
      {/* Futuristic overlay grid */}
      {futuristic && (
        <div className="absolute inset-0 pointer-events-none">
          <div className="w-full h-full bg-[linear-gradient(rgba(0,212,184,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(0,212,184,0.03)_1px,transparent_1px)] bg-[size:20px_20px]"></div>
        </div>
      )}
      <Line ref={chartRef} options={options} data={chartData} />
    </div>
  )
}

