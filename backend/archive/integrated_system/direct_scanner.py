"""
Direct Vulnerability Scanner

This module provides a direct interface to the vulnerability scanner without demo data.
"""

import os
import sys
import json
import logging
import datetime
import argparse
from typing import Dict, List, Any, Optional

# Import the actual vulnerability scanner
from vulnerability_scanner import VulnerabilityScanner

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("finguardai.direct_scanner")

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="FinGuardAI Direct Vulnerability Scanner")
    parser.add_argument("target", help="Target to scan (IP, hostname, or URL)")
    parser.add_argument("--ports", "-p", default="80,443,8080,3306,5432,22", 
                        help="Ports to scan (comma-separated list or ranges)")
    parser.add_argument("--intensity", "-i", choices=["stealthy", "normal", "aggressive"], 
                        default="normal", help="Scan intensity")
    parser.add_argument("--output", "-o", help="Output file for the results (JSON)")
    args = parser.parse_args()
    
    # Initialize the actual vulnerability scanner
    scanner = VulnerabilityScanner()
    
    try:
        # Run the actual vulnerability scan
        logger.info(f"Starting vulnerability scan on {args.target} with ports {args.ports}")
        scan_results = scanner.scan_target(args.target, args.ports, args.intensity)
        
        # Print summary to console
        vuln_count = len(scan_results.get("vulnerabilities", []))
        open_ports = len(scan_results.get("open_ports", {}))
        logger.info(f"Scan completed. Found {vuln_count} vulnerabilities and {open_ports} open ports.")
        
        # Save results if output file specified
        if args.output:
            with open(args.output, "w") as f:
                json.dump(scan_results, f, indent=2)
            logger.info(f"Scan results saved to {args.output}")
            
            # Also print results to console
            print(json.dumps(scan_results, indent=2))
        else:
            # Print results to console
            print(json.dumps(scan_results, indent=2))
            
    except Exception as e:
        logger.error(f"Error during vulnerability scan: {str(e)}")
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
