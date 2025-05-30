#!/usr/bin/env python3
"""
FinGuardAI Integrated Vulnerability Analysis System

This is the main entry point for the integrated vulnerability analysis system
that combines active scanning, passive monitoring, and NVD-powered vulnerability 
predictions into a comprehensive solution.
"""

import os
import sys
import json
import time
import logging
import argparse
from typing import Dict, List, Any, Optional

# Add the parent directory to sys.path to resolve imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.integrated_system.integrated_analyzer import IntegratedAnalyzer
from backend.integrated_system.config import logger

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="FinGuardAI Integrated Vulnerability Analysis System")
    
    # Target specification
    parser.add_argument("--target", "-t", required=True, help="Target to analyze (domain, IP, or URL)")
    
    # Output options
    parser.add_argument("--output", "-o", help="Output report file path")
    parser.add_argument("--format", "-f", choices=["text", "json", "html"], default="text", 
                      help="Output format (default: text)")
    
    # Analysis options
    parser.add_argument("--timeframes", choices=["short", "medium", "long", "comprehensive"], default="medium",
                      help="Timeframe preset: short (1-day), medium (1-day, 1-week), long (1-day, 1-week, 30-days), "
                           "comprehensive (1-day, 1-week, 10-days, 30-days, 90-days)")
    parser.add_argument("--min-cvss", type=float, default=7.0, 
                      help="Minimum CVSS score for highlighting vulnerabilities (default: 7.0)")
    parser.add_argument("--no-exploits", action="store_true", 
                      help="Skip checking for exploitable vulnerabilities")
    parser.add_argument("--no-trends", action="store_true", 
                      help="Skip vulnerability trend analysis")
    
    # Scanning options
    parser.add_argument("--ports", help="Comma-separated list of ports to scan (default: common web ports)")
    parser.add_argument("--scan-speed", choices=["fast", "normal", "thorough"], default="normal",
                      help="Scan speed/intensity (default: normal)")
    
    return parser.parse_args()

def get_timeframe_set(timeframe_preset):
    """Get the set of timeframes based on the preset option"""
    timeframe_sets = {
        "short": ["1_day"],
        "medium": ["1_day", "1_week"],
        "long": ["1_day", "1_week", "30_days"],
        "comprehensive": ["1_day", "1_week", "10_days", "30_days", "90_days"]
    }
    return timeframe_sets.get(timeframe_preset, ["1_day", "1_week"])

def main():
    """Main entry point"""
    args = parse_arguments()
    
    # Configure scan parameters
    scan_params = {
        "scan_speed": args.scan_speed
    }
    
    # Add custom ports if specified
    if args.ports:
        scan_params["ports"] = args.ports
    
    # Configure analysis parameters
    analysis_params = {
        "timeframes": get_timeframe_set(args.timeframes),
        "min_cvss_score": args.min_cvss,
        "check_exploits": not args.no_exploits,
        "include_trends": not args.no_trends
    }
    
    try:
        logger.info(f"Starting integrated analysis of {args.target}")
        print(f"FinGuardAI: Starting integrated analysis of {args.target}...")
        
        # Initialize and run analyzer
        analyzer = IntegratedAnalyzer()
        start_time = time.time()
        results = analyzer.analyze_target(args.target, scan_params=scan_params, analysis_params=analysis_params)
        elapsed_time = time.time() - start_time
        
        # Generate report
        report = analyzer.generate_report(results, format=args.format)
        
        # Output report
        if args.output:
            with open(args.output, 'w') as f:
                if args.format == "json":
                    json.dump(results, f, indent=2)
                else:
                    f.write(report)
            print(f"Report saved to {args.output}")
        else:
            print(report)
        
        logger.info(f"Analysis completed in {elapsed_time:.2f} seconds")
        print(f"Analysis completed in {elapsed_time:.2f} seconds")
        
        # Print summary of findings
        critical_count = results.get("vulnerability_predictions", {}).get("summary", {}).get("critical_vulnerabilities", 0)
        high_count = results.get("vulnerability_predictions", {}).get("summary", {}).get("high_vulnerabilities", 0)
        
        print("\nSummary:")
        print(f"- Critical vulnerabilities: {critical_count}")
        print(f"- High vulnerabilities: {high_count}")
        print(f"- Technologies analyzed: {len(results.get('technologies', []))}")
        
        if results.get("exploit_analysis", {}).get("total_exploits", 0) > 0:
            print(f"⚠️ WARNING: Found {results['exploit_analysis']['total_exploits']} exploitable vulnerabilities!")
    
    except KeyboardInterrupt:
        logger.warning("Analysis interrupted by user")
        print("\nAnalysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error during analysis: {e}")
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
