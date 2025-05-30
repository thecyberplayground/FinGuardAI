/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
  reactStrictMode: true,
  transpilePackages: ["lucide-react"],
  async rewrites() {
    return [
      {
        source: '/api/:path*',
        destination: process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5001/:path*'
      }
    ]
  },
  // Ensure compatibility with Docker
  experimental: {
    // This enables the serverless builds
    esmExternals: 'loose',
  }
}

module.exports = nextConfig
