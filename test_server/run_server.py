#!/usr/bin/env python3
"""
Simple HTTP Server for Testing Vulnerability Scanner

This server serves the test files and adds some custom headers to simulate
vulnerabilities that can be detected by the scanner.
"""

import os
import sys
import http.server
import socketserver
import argparse

class VulnerableHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    """Custom HTTP request handler with added headers to simulate vulnerabilities"""
    
    def end_headers(self):
        # Add headers that simulate an older server with potential vulnerabilities
        self.send_header("Server", "Apache/2.4.41 (Ubuntu)")
        self.send_header("X-Powered-By", "PHP/7.4.3")
        
        # Deliberately missing security headers
        # A proper server should include these
        # self.send_header("X-Frame-Options", "DENY")
        # self.send_header("X-Content-Type-Options", "nosniff")
        # self.send_header("Content-Security-Policy", "default-src 'self'")
        
        super().end_headers()

def run_server(port=8080, directory=None):
    """Run the test HTTP server"""
    handler = VulnerableHTTPRequestHandler
    
    if directory:
        os.chdir(directory)
    
    with socketserver.TCPServer(("", port), handler) as httpd:
        print(f"Server running at http://localhost:{port}/")
        print("Press Ctrl+C to stop the server")
        httpd.serve_forever()

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Run a test HTTP server with simulated vulnerabilities")
    parser.add_argument("--port", "-p", type=int, default=8080, 
                        help="Port to run the server on")
    parser.add_argument("--directory", "-d", default=None,
                        help="Directory to serve files from")
    
    args = parser.parse_args()
    
    try:
        run_server(args.port, args.directory)
    except KeyboardInterrupt:
        print("\nServer stopped")
        sys.exit(0)

if __name__ == "__main__":
    main()
