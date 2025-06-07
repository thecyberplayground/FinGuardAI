"use client"

import { useRef } from "react"
import { Chart as ChartJS, ArcElement, Tooltip, Legend, type ChartData, type ChartOptions } from "chart.js"
import { Pie } from "react-chartjs-2"

ChartJS.register(ArcElement, Tooltip, Legend)

interface PieChartProps {
  data: {
    high: number
    medium: number
    low: number
  }
  title?: string
  height?: string
}

export function PieChart({ data, title, height = "200px" }: PieChartProps) {
  const chartRef = useRef<ChartJS<"pie">>(null)

  const chartData: ChartData<"pie"> = {
    labels: ["High", "Medium", "Low"],
    datasets: [
      {
        data: [data.high, data.medium, data.low],
        backgroundColor: [
          "rgba(220, 53, 69, 0.8)", // Red for High
          "rgba(255, 193, 7, 0.8)", // Yellow for Medium
          "rgba(40, 167, 69, 0.8)", // Green for Low
        ],
        borderColor: ["rgb(220, 53, 69)", "rgb(255, 193, 7)", "rgb(40, 167, 69)"],
        borderWidth: 1,
      },
    ],
  }

  const options: ChartOptions<"pie"> = {
    responsive: true,
    maintainAspectRatio: false,
    animation: {
      animateRotate: true,
      animateScale: true,
      duration: 1000,
    },
    plugins: {
      legend: {
        position: "right",
        labels: {
          color: "#a0aec0",
          padding: 20,
          font: {
            size: 12,
          },
        },
      },
      tooltip: {
        callbacks: {
          label: (context) => {
            const total = context.dataset.data.reduce((a: number, b: number) => a + b, 0)
            const value = context.raw as number
            const percentage = Math.round((value / total) * 100)
            return `${context.label}: ${value} (${percentage}%)`
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
    <div style={{ height, width: "100%" }}>
      <Pie ref={chartRef} options={options} data={chartData} />
    </div>
  )
}

