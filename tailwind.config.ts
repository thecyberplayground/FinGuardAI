import type { Config } from "tailwindcss"

const config = {
  darkMode: ["class"],
  content: [
    "./pages/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
    "./app/**/*.{ts,tsx}",
    "./src/**/*.{ts,tsx}",
    "*.{js,ts,jsx,tsx,mdx}",
  ],
  prefix: "",
  theme: {
    container: {
      center: true,
      padding: "2rem",
      screens: {
        "2xl": "1400px",
      },
    },
    extend: {
      colors: {
        border: "hsl(var(--border))",
        input: "hsl(var(--input))",
        ring: "hsl(var(--ring))",
        background: "hsl(var(--background))",
        foreground: "hsl(var(--foreground))",
        primary: {
          DEFAULT: "hsl(var(--primary))",
          foreground: "hsl(var(--primary-foreground))",
        },
        secondary: {
          DEFAULT: "hsl(var(--secondary))",
          foreground: "hsl(var(--secondary-foreground))",
        },
        destructive: {
          DEFAULT: "hsl(var(--destructive))",
          foreground: "hsl(var(--destructive-foreground))",
        },
        muted: {
          DEFAULT: "hsl(var(--muted))",
          foreground: "hsl(var(--muted-foreground))",
        },
        accent: {
          DEFAULT: "hsl(var(--accent))",
          foreground: "hsl(var(--accent-foreground))",
        },
        popover: {
          DEFAULT: "hsl(var(--popover))",
          foreground: "hsl(var(--popover-foreground))",
        },
        card: {
          DEFAULT: "hsl(var(--card))",
          foreground: "hsl(var(--card-foreground))",
        },
        // Custom colors
        teal: {
          DEFAULT: "#00d4b8",
          50: "#e0fff9",
          100: "#b3fff0",
          200: "#80ffe6",
          300: "#4dffdc",
          400: "#1affd3",
          500: "#00e6c3",
          600: "#00d4b8",
          700: "#00b39c",
          800: "#009380",
          900: "#007264",
        },
        purple: {
          DEFAULT: "#7b2cbf",
          50: "#f5e9ff",
          100: "#e0c2ff",
          200: "#cb9aff",
          300: "#b673ff",
          400: "#a14bff",
          500: "#8c24ff",
          600: "#7b2cbf",
          700: "#6a1f9f",
          800: "#59137f",
          900: "#48065f",
        },
      },
      fontFamily: {
        sans: ["var(--font-poppins)"],
        mono: ["Consolas", "Monaco", "Courier New", "monospace"],
        orbitron: ["var(--font-orbitron)"],
        poppins: ["var(--font-poppins)"],
      },
      borderRadius: {
        lg: "var(--radius)",
        md: "calc(var(--radius) - 2px)",
        sm: "calc(var(--radius) - 4px)",
      },
      keyframes: {
        "accordion-down": {
          from: { height: "0" },
          to: { height: "var(--radix-accordion-content-height)" },
        },
        "accordion-up": {
          from: { height: "var(--radix-accordion-content-height)" },
          to: { height: "0" },
        },
      },
      animation: {
        "accordion-down": "accordion-down 0.2s ease-out",
        "accordion-up": "accordion-up 0.2s ease-out",
      },
      backgroundImage: {
        "gradient-radial": "radial-gradient(var(--tw-gradient-stops))",
        "grid-pattern":
          "linear-gradient(rgba(0, 212, 184, 0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(0, 212, 184, 0.03) 1px, transparent 1px)",
      },
      boxShadow: {
        neon: "0 0 5px rgba(0, 212, 184, 0.5), 0 0 10px rgba(0, 212, 184, 0.3), 0 0 15px rgba(0, 212, 184, 0.1)",
        "neon-purple":
          "0 0 5px rgba(123, 44, 191, 0.5), 0 0 10px rgba(123, 44, 191, 0.3), 0 0 15px rgba(123, 44, 191, 0.1)",
      },
    },
  },
  plugins: [require("tailwindcss-animate")],
} satisfies Config

export default config

