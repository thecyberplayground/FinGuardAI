"use client"

import { useRef } from "react"
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
  type ChartData,
  type ChartOptions,
} from "chart.js"
import { Bar } from "react-chartjs-2"

ChartJS.register(CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend)

interface BarChartProps {
  data: {
    high: number
    medium: number
    low: number
  }
  title?: string
  height?: string
  futuristic?: boolean
}

export function BarChart({ data, title, height = "200px", futuristic = true }: BarChartProps) {
  const chartRef = useRef<ChartJS<"bar">>(null)

  const chartData: ChartData<"bar"> = {
    labels: ["High", "Medium", "Low"],
    datasets: [
      {
        label: "Threat Count",
        data: [data.high, data.medium, data.low],
        backgroundColor: [
          "rgba(255, 85, 85, 0.8)", // Red for High
          "rgba(255, 170, 0, 0.8)", // Yellow for Medium
          "rgba(0, 204, 153, 0.8)", // Green for Low
        ],
        borderColor: ["rgb(255, 85, 85)", "rgb(255, 170, 0)", "rgb(0, 204, 153)"],
        borderWidth: 1,
        borderRadius: 4,
      },
    ],
  }

  const options: ChartOptions<"bar"> = {
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
        display: false,
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
        displayColors: true,
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
      {/* Futuristic overlay grid */}
      {futuristic && (
        <div className="absolute inset-0 pointer-events-none">
          <div className="w-full h-full bg-[linear-gradient(rgba(0,212,184,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(0,212,184,0.03)_1px,transparent_1px)] bg-[size:20px_20px]"></div>
        </div>
      )}
      <Bar ref={chartRef} options={options} data={chartData} />
    </div>
  )
}

