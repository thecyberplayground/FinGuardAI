#!/usr/bin/env python3
"""
FinGuardAI Vulnerability Scan Runner

This script provides a simple command line interface to run the enhanced 
vulnerability scanning system.
"""

import os
import sys
import json
import argparse
import logging
from typing import Dict, Any, Optional

from .integrated_analyzer import IntegratedAnalyzer
from .config import DEFAULT_SCAN_PARAMS, DEFAULT_ANALYSIS_PARAMS

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("finguardai.scan_runner")

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="FinGuardAI Enhanced Vulnerability Scanner")
    parser.add_argument("target", help="Target to scan (IP address, hostname, or URL)")
    parser.add_argument("--output", "-o", help="Output file for the report")
    parser.add_argument("--format", "-f", 
                        choices=["text", "json", "html"], 
                        help="Report format (text, json, or html)")
    parser.add_argument("--ports", "-p", 
                        help="Port range to scan (e.g., '1-1000,3306,8080')")
    parser.add_argument("--intensity", "-i",
                        choices=["stealthy", "normal", "aggressive"],
                        help="Scan intensity")
    parser.add_argument("--include-financial", 
                        action="store_true",
                        help="Include financial impact analysis")
    parser.add_argument("--timeframes",
                        help="Timeframes for vulnerability trend analysis (comma-separated)")
    parser.add_argument("--env", "-e",
                        choices=["dev", "test", "prod"],
                        default="prod",
                        help="Environment to use (loads config from config/<env>.json)")
    return parser.parse_args()

def run_scan(target: str, 
             output_file: Optional[str] = None,
             report_format: str = "text",
             scan_params: Optional[Dict[str, Any]] = None,
             analysis_params: Optional[Dict[str, Any]] = None,
             env: str = "prod") -> str:
    """
    Run a vulnerability scan on the specified target
    
    Args:
        target: Target to scan (IP address, hostname, or URL)
        output_file: Path to save the report
        report_format: Report format (text, json, or html)
        scan_params: Scan parameters
        analysis_params: Analysis parameters
        
    Returns:
        Path to the generated report
    """
    # Create output directory if needed
    output_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "reports"))
    os.makedirs(output_dir, exist_ok=True)
    
    # Load environment-specific configuration
    config = _load_environment_config(env)
    
    # Initialize the analyzer with environment
    analyzer = IntegratedAnalyzer(output_dir=output_dir, env=env)
    
    # Set default parameters if not provided, using environment config
    scan_params = scan_params or config.get("scan_params", DEFAULT_SCAN_PARAMS)
    analysis_params = analysis_params or config.get("analysis_params", DEFAULT_ANALYSIS_PARAMS)
    
    # Run the analysis
    logger.info(f"Starting vulnerability scan on {target}")
    results = analyzer.analyze_target(target, scan_params, analysis_params)
    
    # Generate report
    report = analyzer.generate_report(results, format=report_format)
    
    # Save report if output file specified
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(report)
        logger.info(f"Scan report saved to {output_file}")
    
    return report

def _load_environment_config(env: str) -> Dict[str, Any]:
    """Load environment-specific configuration"""
    # Look for config file in project config directory
    config_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "config"))
    config_file = os.path.join(config_dir, f"{env}.json")
    
    # Default configurations
    default_configs = {
        "dev": {
            "scan_params": {
                "ports": "80,443,8080,3306,5432",
                "intensity": "stealthy"
            },
            "analysis_params": {
                "include_financial": False,
                "timeframes": ["30_days"]
            }
        },
        "test": {
            "scan_params": {
                "ports": "1-1000,3306,5432,8080-8090",
                "intensity": "normal"
            },
            "analysis_params": {
                "include_financial": True,
                "timeframes": ["30_days", "90_days"]
            }
        },
        "prod": {
            "scan_params": {
                "ports": "1-1000,3306,5432,8080-8090,27017,21,22,23,25,53",
                "intensity": "normal"
            },
            "analysis_params": {
                "include_financial": True,
                "timeframes": ["30_days", "90_days", "365_days"]
            }
        }
    }
    
    # Load default config for this environment
    config = default_configs.get(env, default_configs["prod"])
    
    # If config file exists, override defaults with values from file
    if os.path.exists(config_file):
        try:
            with open(config_file, 'r') as f:
                file_config = json.load(f)
                # Merge configurations
                if "scan_params" in file_config:
                    config["scan_params"].update(file_config["scan_params"])
                if "analysis_params" in file_config:
                    config["analysis_params"].update(file_config["analysis_params"])
            logger.info(f"Loaded configuration from {config_file}")
        except Exception as e:
            logger.warning(f"Error loading config file {config_file}: {str(e)}")
            logger.warning(f"Using default {env} configuration")
    else:
        # Create the default config file for future use
        try:
            os.makedirs(config_dir, exist_ok=True)
            with open(config_file, 'w') as f:
                json.dump(config, f, indent=2)
            logger.info(f"Created default {env} configuration file: {config_file}")
        except Exception as e:
            logger.warning(f"Error creating config file {config_file}: {str(e)}")
    
    return config

def main():
    """Main entry point"""
    args = parse_args()
    
    # Load environment configuration
    env = args.env
    config = _load_environment_config(env)
    
    # Start with environment config
    scan_params = config.get("scan_params", DEFAULT_SCAN_PARAMS).copy()
    analysis_params = config.get("analysis_params", DEFAULT_ANALYSIS_PARAMS).copy()
    
    # Override with command line arguments if specified
    if args.ports is not None:
        scan_params["ports"] = args.ports
    if args.intensity is not None:
        scan_params["intensity"] = args.intensity
    if args.format is not None:
        report_format = args.format
    else:
        report_format = config.get("report_format", "text")
    
    # Configure analysis parameters
    analysis_params["include_financial"] = args.include_financial
    if args.timeframes is not None:
        analysis_params["timeframes"] = args.timeframes.split(",")
    
    # Run the scan
    report = run_scan(
        args.target,
        output_file=args.output,
        report_format=report_format,
        scan_params=scan_params,
        analysis_params=analysis_params,
        env=env
    )
    
    # Print report to console if no output file specified
    if not args.output:
        print(report)

if __name__ == "__main__":
    main()
