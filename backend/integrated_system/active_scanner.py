"""
Active Scanning Component for FinGuardAI

This module handles active scanning of targets to identify technologies and potential vulnerabilities.
"""

import os
import json
import logging
import subprocess
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional

from .config import DEFAULT_SCAN_PARAMS, logger

class ActiveScanner:
    """Active scanning component that handles direct scanning of targets"""
    
    def __init__(self, output_dir: str = None):
        """
        Initialize the active scanner
        
        Args:
            output_dir: Directory to store scan results
        """
        self.output_dir = output_dir or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
            "scan_results"
        )
        os.makedirs(self.output_dir, exist_ok=True)
        self.logger = logging.getLogger("finguardai.active_scanner")
    
    def scan_target(self, target: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Perform an active scan on the target
        
        Args:
            target: Target to scan (IP, hostname, or URL)
            params: Optional scan parameters to override defaults
            
        Returns:
            Dictionary with scan results
        """
        scan_params = DEFAULT_SCAN_PARAMS.copy()
        if params:
            scan_params.update(params)
            
        self.logger.info(f"Starting active scan of {target}")
        
        # For demonstration purposes, we'll simulate the scan result
        # In a real implementation, this would call nmap or another scanning tool
        
        scan_output_file = os.path.join(self.output_dir, f"{target.replace('.', '_')}_scan.json")
        
        # Simulated scan result based on common technologies
        scan_result = self._simulate_scan_for_target(target)
        
        # Save scan results
        with open(scan_output_file, 'w') as f:
            json.dump(scan_result, f, indent=4)
        
        self.logger.info(f"Completed active scan of {target}, found {len(scan_result.get('technologies', []))} technologies")
        return scan_result
    
    def _simulate_scan_for_target(self, target: str) -> Dict[str, Any]:
        """
        Simulate scan results for a given target
        
        In a real implementation, this would parse nmap/other scanner output
        
        Args:
            target: Target that was scanned
            
        Returns:
            Dictionary with simulated scan results
        """
        # Common technology patterns seen in scans
        common_technologies = {
            "apache": {"versions": ["2.4.51", "2.4.46", "2.4.41"]},
            "nginx": {"versions": ["1.20.1", "1.18.0", "1.16.1"]},
            "php": {"versions": ["8.0.10", "7.4.21", "7.4.3"]},
            "mysql": {"versions": ["8.0.26", "5.7.36", "5.5.62"]},
            "openssh": {"versions": ["8.2p1", "7.9p1", "7.6p1"]},
            "nodejs": {"versions": ["16.9.1", "14.17.6", "12.22.6"]},
            "windows": {"versions": ["10.0.19044", "6.3.9600", "6.1.7601"]},
            "ubuntu": {"versions": ["20.04", "18.04", "16.04"]},
            "centos": {"versions": ["8.4.2105", "7.9.2009", "6.10"]},
        }
        
        # Domain-specific technologies
        domain_specific = {
            ".edu": ["moodle", "blackboard", "canvas"],
            ".gov": ["drupal", "wordpress", "joomla"],
            ".com": ["wordpress", "magento", "shopify"],
            ".org": ["wordpress", "drupal", "mediawiki"],
        }
        
        # Determine which technologies to include based on the target
        selected_technologies = []
        
        # Select based on domain
        for domain_suffix, techs in domain_specific.items():
            if target.endswith(domain_suffix):
                for tech in techs:
                    if tech in common_technologies:
                        tech_data = common_technologies[tech].copy()
                        tech_data["name"] = tech
                        tech_data["version"] = tech_data["versions"][0]  # Use latest version
                        del tech_data["versions"]
                        selected_technologies.append(tech_data)
        
        # Always include some base technologies
        base_techs = ["apache" if "apache" not in [t["name"] for t in selected_technologies] else "nginx",
                     "php",
                     "mysql" if target.endswith((".edu", ".gov")) else "postgresql",
                     "openssh"]
        
        for tech in base_techs:
            if tech in common_technologies and tech not in [t["name"] for t in selected_technologies]:
                tech_data = common_technologies[tech].copy()
                tech_data["name"] = tech
                tech_data["version"] = tech_data["versions"][0]  # Use latest version
                del tech_data["versions"]
                selected_technologies.append(tech_data)
        
        # Create the scan result
        ports = {}
        if "apache" in [t["name"] for t in selected_technologies]:
            ports["80"] = {
                "service": "http",
                "product": "Apache httpd",
                "version": next((t["version"] for t in selected_technologies if t["name"] == "apache"), "")
            }
            ports["443"] = {
                "service": "https",
                "product": "Apache httpd",
                "version": next((t["version"] for t in selected_technologies if t["name"] == "apache"), "")
            }
        elif "nginx" in [t["name"] for t in selected_technologies]:
            ports["80"] = {
                "service": "http",
                "product": "nginx",
                "version": next((t["version"] for t in selected_technologies if t["name"] == "nginx"), "")
            }
            ports["443"] = {
                "service": "https",
                "product": "nginx",
                "version": next((t["version"] for t in selected_technologies if t["name"] == "nginx"), "")
            }
        
        if "mysql" in [t["name"] for t in selected_technologies]:
            ports["3306"] = {
                "service": "mysql",
                "product": "MySQL",
                "version": next((t["version"] for t in selected_technologies if t["name"] == "mysql"), "")
            }
        
        if "openssh" in [t["name"] for t in selected_technologies]:
            ports["22"] = {
                "service": "ssh",
                "product": "OpenSSH",
                "version": next((t["version"] for t in selected_technologies if t["name"] == "openssh"), "")
            }
        
        return {
            "target": target,
            "scan_time": "2025-05-17T12:00:00Z",
            "technologies": selected_technologies,
            "ports": ports,
            "os": {
                "name": "Ubuntu",
                "version": "20.04"
            }
        }
    
    def extract_technologies(self, scan_result: Dict[str, Any]) -> List[Dict[str, str]]:
        """
        Extract technologies from scan results
        
        Args:
            scan_result: Scan result dictionary
            
        Returns:
            List of technologies with name and version
        """
        technologies = []
        
        # Extract from technologies section
        if "technologies" in scan_result:
            for tech in scan_result.get("technologies", []):
                if isinstance(tech, dict) and "name" in tech and "version" in tech:
                    technologies.append({
                        "name": tech["name"],
                        "version": tech["version"]
                    })
        
        # Extract from ports section
        if "ports" in scan_result:
            for port, details in scan_result.get("ports", {}).items():
                if "product" in details and "version" in details and details["version"]:
                    # Clean up the product name to be more standardized
                    product = details["product"].lower()
                    if "apache" in product:
                        product = "apache"
                    elif "nginx" in product:
                        product = "nginx"
                    
                    # Add if not already in the list
                    tech_entry = {"name": product, "version": details["version"]}
                    if tech_entry not in technologies:
                        technologies.append(tech_entry)
        
        # Extract OS info
        if "os" in scan_result and "name" in scan_result["os"] and "version" in scan_result["os"]:
            os_name = scan_result["os"]["name"].lower()
            os_version = scan_result["os"]["version"]
            
            technologies.append({
                "name": os_name,
                "version": os_version
            })
        
        return technologies
