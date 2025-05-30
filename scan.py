#!/usr/bin/env python3
"""
FinGuardAI - One-Command Vulnerability Scanner

Just provide a host, and we'll handle the rest!
"""

import os
import sys
import json
import logging
import argparse
import datetime
import subprocess
from typing import Dict, Any, Optional

# Set up path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import scanner components
from backend.integrated_system.vulnerability_scanner import VulnerabilityScanner
from backend.integrated_system.enhanced_report import EnhancedReportGenerator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("finguardai.scan")

def scan_target(target: str, output_dir: str = "reports", args: Optional[Dict[str, Any]] = None, env: str = "prod") -> str:
    """
    Run a full vulnerability scan on the target and generate a report
    
    Args:
        target: Target to scan (hostname, IP, or URL)
        output_dir: Directory to save reports
        args: Optional scan arguments
        
    Returns:
        Path to the generated report
    """
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    # Parse arguments
    if args is None:
        args = {}
    
    # Kill any previous running scans
    _cleanup_previous_scans()
    
    # Load environment-specific configuration
    config = _load_environment_config(env)
    
    # Use config values with args as override
    ports = args.get('ports', config.get('ports', "1-1000,3306,5432,8080-8090,27017,21,22,23,25,53"))
    intensity = args.get('intensity', config.get('intensity', "normal"))
    report_format = args.get('format', config.get('format', "html"))
    
    try:
        # Initialize components
        scanner = VulnerabilityScanner(output_dir=output_dir)
        report_generator = EnhancedReportGenerator(report_dir=output_dir)
        
        # Run the scan
        logger.info(f"Starting vulnerability scan on {target}")
        start_time = datetime.datetime.now()
        
        # Perform the actual scan
        scan_results = scanner.scan_target(target, ports, intensity)
        
        # Calculate duration
        duration = (datetime.datetime.now() - start_time).total_seconds()
        logger.info(f"Scan completed in {duration:.2f} seconds")
        
        # Generate the report
        report_path = report_generator.generate_report(
            scan_results, 
            target=target,
            report_format=report_format
        )
        
        logger.info(f"Report generated: {report_path}")
        return report_path
        
    except Exception as e:
        logger.error(f"Error during scan: {str(e)}")
        error_file = os.path.join(output_dir, f"error_{target}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
        
        with open(error_file, 'w') as f:
            f.write(f"Error scanning {target}: {str(e)}\n")
            f.write(f"Time: {datetime.datetime.now().isoformat()}\n")
            f.write(f"Arguments: {json.dumps(args, indent=2)}\n")
        
        logger.info(f"Error details saved to {error_file}")
        return error_file

def _cleanup_previous_scans():
    """Kill any previous running scans to avoid conflicts"""
    try:
        # Windows command to kill any running nmap processes
        subprocess.run("taskkill /F /IM nmap.exe /T", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        # Ignore errors, as there might not be any running scans
        pass

def _load_environment_config(env: str) -> Dict[str, Any]:
    """Load configuration for the specified environment"""
    config_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config")
    os.makedirs(config_dir, exist_ok=True)
    
    config_file = os.path.join(config_dir, f"{env}.json")
    
    # Default configurations for different environments
    default_configs = {
        "dev": {
            "ports": "80,443,8080,3306,5432",  # Limited ports for faster scans
            "intensity": "stealthy",
            "format": "text"
        },
        "test": {
            "ports": "1-1000,3306,5432,8080-8090",  # Standard test coverage
            "intensity": "normal",
            "format": "html"
        },
        "prod": {
            "ports": "1-1000,3306,5432,8080-8090,27017,21,22,23,25,53",  # Comprehensive
            "intensity": "normal",
            "format": "html"
        }
    }
    
    # Use default config if env-specific one doesn't exist
    default_config = default_configs.get(env, default_configs["prod"])
    
    # Try to load the config file if it exists
    if os.path.exists(config_file):
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Error loading config file {config_file}: {str(e)}")
            logger.warning(f"Using default {env} configuration")
    else:
        # Create the default config file for future use
        try:
            with open(config_file, 'w') as f:
                json.dump(default_config, f, indent=2)
            logger.info(f"Created default {env} configuration file: {config_file}")
        except Exception as e:
            logger.warning(f"Error creating config file {config_file}: {str(e)}")
    
    return default_config

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="FinGuardAI - One-Command Vulnerability Scanner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("target", help="Target to scan (hostname, IP, or URL)")
    parser.add_argument("--ports", "-p", 
                        help="Ports to scan (comma-separated list or ranges)")
    parser.add_argument("--intensity", "-i", 
                        choices=["stealthy", "normal", "aggressive"],
                        help="Scan intensity")
    parser.add_argument("--format", "-f", 
                        choices=["html", "text", "json"],
                        help="Report format")
    parser.add_argument("--output-dir", "-o",
                        default="reports",
                        help="Directory to save reports")
    parser.add_argument("--env", "-e",
                        choices=["dev", "test", "prod"],
                        default="prod",
                        help="Environment to use for configuration")
    args = parser.parse_args()
    
    # Build args dict with only specified arguments (not None)
    scan_args = {}
    if args.ports is not None:
        scan_args['ports'] = args.ports
    if args.intensity is not None:
        scan_args['intensity'] = args.intensity
    if args.format is not None:
        scan_args['format'] = args.format
    
    # Run the scan
    report_path = scan_target(
        args.target,
        output_dir=args.output_dir,
        args=scan_args,
        env=args.env
    )
    
    # Output result
    if os.path.exists(report_path):
        print(f"\nScan completed successfully!")
        print(f"Report saved to: {os.path.abspath(report_path)}")
        
        # For text reports, also display the content
        if args.format == "text" and report_path.endswith(".txt"):
            print("\n=== REPORT CONTENT ===\n")
            with open(report_path, 'r') as f:
                print(f.read())
    else:
        print(f"\nScan failed. Check the logs for details.")

if __name__ == "__main__":
    main()
