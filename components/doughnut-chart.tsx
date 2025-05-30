"use client"

import { useRef } from "react"
import { Chart as ChartJS, ArcElement, Tooltip, Legend, type ChartData, type ChartOptions } from "chart.js"
import { Doughnut } from "react-chartjs-2"

ChartJS.register(ArcElement, Tooltip, Legend)

interface DoughnutChartProps {
  data: {
    normal: number
    anomalous: number
  }
  title?: string
  height?: string
  futuristic?: boolean
}

export function DoughnutChart({ data, title, height = "200px", futuristic = true }: DoughnutChartProps) {
  const chartRef = useRef<ChartJS>(null)

  const chartData: ChartData<"doughnut"> = {
    labels: ["Normal", "Anomalous"],
    datasets: [
      {
        data: [data.normal, data.anomalous],
        backgroundColor: [
          "rgba(0, 204, 153, 0.8)", // Green for Normal
          "rgba(255, 85, 85, 0.8)", // Red for Anomalous
        ],
        borderColor: ["rgb(0, 204, 153)", "rgb(255, 85, 85)"],
        borderWidth: 1,
        hoverOffset: 4,
      },
    ],
  }

  const options: ChartOptions<"doughnut"> = {
    responsive: true,
    maintainAspectRatio: false,
    animation: {
      animateRotate: true,
      animateScale: true,
      duration: 1000,
    },
    cutout: "70%",
    plugins: {
      legend: {
        position: "bottom",
        labels: {
          color: "#a0aec0",
          padding: 10,
          font: {
            size: 11,
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
        callbacks: {
          label: (context) => {
            const total = context.dataset.data.reduce((a: number, b: number) => a + b, 0)
            const value = context.raw as number
            const percentage = Math.round((value / total) * 100)
            return `${context.label}: ${percentage}%`
          },
        },
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

  return (
    <div style={{ height, width: "100%" }} className="relative">
      {/* Futuristic overlay */}
      {futuristic && (
        <div className="absolute inset-0 pointer-events-none">
          <div className="w-full h-full bg-[linear-gradient(rgba(0,212,184,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(0,212,184,0.03)_1px,transparent_1px)] bg-[size:20px_20px]"></div>
        </div>
      )}
      <Doughnut ref={chartRef} options={options} data={chartData} />
    </div>
  )
}

