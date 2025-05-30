"""
Scan Bridge Module

This module serves as a bridge between the standalone scan.py functionality
and the Flask API backend. It allows the web application to leverage the
full capabilities of the comprehensive scanner.
"""

import os
import sys
import json
import logging
import re
from urllib.parse import urlparse
from typing import Dict, Any, Optional

# Add parent directory to path to allow importing scan.py
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(parent_dir)

# Import the scan functionality from the root scan.py
from scan import scan_target, _load_environment_config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("finguardai.scan_bridge")

def run_integrated_scan(target: str, scan_options: Dict[str, Any] = None, env: str = "prod") -> Dict[str, Any]:
    """
    Run an integrated scan using the comprehensive scan.py functionality
    
    Args:
        target: Target to scan (hostname, IP, or URL)
        scan_options: Scan options (ports, intensity, etc.)
        env: Environment to use (dev, test, prod)
        
    Returns:
        Dictionary with scan results and report path
    """
    if scan_options is None:
        scan_options = {}
        
    # Process the target - extract domain from URL if needed
    processed_target = target
    
    # Check if target is a URL
    if target.startswith('http://') or target.startswith('https://') or '://' in target:
        # Parse the URL to extract the domain
        parsed_url = urlparse(target)
        processed_target = parsed_url.netloc
        
        # Remove port if present
        if ':' in processed_target:
            processed_target = processed_target.split(':')[0]
            
        logger.info(f"Converted URL '{target}' to domain '{processed_target}' for scanning")
    
    # If the domain still has www. prefix, remove it
    if processed_target.startswith('www.'):
        processed_target = processed_target[4:]
        logger.info(f"Removed 'www.' prefix, using '{processed_target}' for scanning")
    
    # Normalize options
    options = {
        "ports": scan_options.get("ports"),
        "intensity": scan_options.get("intensity", "normal"),
        "format": scan_options.get("format", "json")
    }
    
    # Filter out None values
    options = {k: v for k, v in options.items() if v is not None}
    
    # Set appropriate output directory
    output_dir = os.path.join(parent_dir, "reports", processed_target.replace(".", "_"))
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        # Run the scan using the main scan.py functionality
        report_path = scan_target(
            target=processed_target,
            output_dir=output_dir,
            args=options,
            env=env
        )
        
        # Load and parse the report
        if report_path.endswith(".json"):
            with open(report_path, "r") as f:
                results = json.load(f)
        else:
            # If report is not JSON, provide basic info and path
            results = {
                "status": "completed",
                "target": target,
                "report_path": report_path,
                "report_format": options.get("format", "html")
            }
            
        return {
            "status": "success",
            "results": results,
            "report_path": report_path,
            "original_target": target,
            "processed_target": processed_target
        }
    
    except Exception as e:
        logger.error(f"Error during integrated scan: {str(e)}")
        return {
            "status": "error",
            "error": str(e),
            "original_target": target,
            "processed_target": processed_target
        }

def get_scan_environments() -> Dict[str, Any]:
    """
    Get available scan environments and their configurations
    
    Returns:
        Dictionary with environment configurations
    """
    environments = {}
    for env in ["dev", "test", "prod"]:
        environments[env] = _load_environment_config(env)
    
    return environments
