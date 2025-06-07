"""
NVD-Enhanced Vulnerability Scanner

This module enhances the vulnerability scanner by integrating with the NVD API
to provide high-quality vulnerability data based on detected technologies.
"""

import os
import re
import json
import logging
from typing import Dict, List, Any, Optional, Set, Tuple

# Try both relative and absolute imports to handle different import scenarios
try:
    # Try relative imports first
    from .vulnerability_scanner import VulnerabilityScanner
    from .nvd_integration import NVDIntegration
    from .config import NVD_API_KEY, logger
except ImportError:
    try:
        # Try absolute imports if relative imports fail
        import sys
        import os
        sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        
        from integrated_system.vulnerability_scanner import VulnerabilityScanner
        from integrated_system.nvd_integration import NVDIntegration
        from integrated_system.config import NVD_API_KEY, logger
    except ImportError:
        # Direct imports as last resort
        from vulnerability_scanner import VulnerabilityScanner
        import nvd_integration
        NVDIntegration = nvd_integration.NVDIntegration
        
        # If config module is missing, define defaults
        try:
            from config import NVD_API_KEY, logger
        except ImportError:
            import logging
            logger = logging.getLogger('finguardai.nvd_scanner')
            NVD_API_KEY = None

class NVDVulnerabilityScanner(VulnerabilityScanner):
    """
    Enhanced vulnerability scanner that integrates with NVD API for
    more accurate vulnerability data instead of using CICIDS-based ML predictions.
    """
    
    def __init__(self, output_dir: Optional[str] = None, nvd_api_key: Optional[str] = None):
        """
        Initialize the NVD-enhanced vulnerability scanner
        
        Args:
            output_dir: Directory to store scan results
            nvd_api_key: NVD API key for higher rate limits
        """
        super().__init__(output_dir=output_dir)
        self.nvd_integration = NVDIntegration(api_key=nvd_api_key or NVD_API_KEY)
        self.logger = logging.getLogger("finguardai.nvd_scanner")
    
    def scan_target(self, target: str, ports: str = "1-1000", intensity: str = "normal") -> Dict[str, Any]:
        """
        Perform a comprehensive vulnerability scan on the target with NVD integration
        
        Args:
            target: Target to scan (IP, hostname, or URL)
            ports: Port specification (e.g., "21-25,80,443,3306,8080-8090")
            intensity: Scan intensity (normal, aggressive, or stealthy)
            
        Returns:
            Dictionary with scan results
        """
        # First, perform the base scan using the parent class
        scan_results = super().scan_target(target, ports, intensity)
        
        # If the scan was successful, enhance it with NVD data
        if "error" not in scan_results:
            self.logger.info(f"Base scan completed successfully. Enhancing with NVD data...")
            scan_results = self._enhance_with_nvd_data(scan_results)
        
        return scan_results
    
    def _enhance_with_nvd_data(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enhance scan results with NVD vulnerability data
        
        Args:
            scan_results: Base scan results from nmap
            
        Returns:
            Enhanced scan results with NVD data
        """
        # Extract technologies from the scan results
        technologies = self._extract_technologies(scan_results)
        self.logger.info(f"Extracted technologies: {technologies}")
        
        # Get NVD data for each technology
        nvd_vulnerabilities = {}
        for tech, version in technologies.items():
            self.logger.info(f"Fetching NVD data for {tech} {version}...")
            vulns = self.nvd_integration.get_vulnerabilities_for_technology(tech, version)
            if vulns:
                nvd_vulnerabilities[f"{tech} {version}"] = vulns
        
        # Add NVD vulnerabilities to the scan results
        scan_results["nvd_vulnerabilities"] = nvd_vulnerabilities
        
        # Count total vulnerabilities
        total_vulns = sum(len(vulns) for vulns in nvd_vulnerabilities.values())
        scan_results["total_nvd_vulnerabilities"] = total_vulns
        
        # Update vulnerability data based on NVD findings
        if "vulnerabilities" not in scan_results:
            scan_results["vulnerabilities"] = []
            
        # Consolidate existing vulnerabilities with NVD data
        for tech, vulns in nvd_vulnerabilities.items():
            for vuln in vulns:
                # Get the CVE ID
                cve_id = vuln.get("cve", {}).get("id")
                if not cve_id:
                    continue
                    
                # Extract CVSS data
                cvss_data = {}
                metrics = vuln.get("cve", {}).get("metrics", {})
                if "cvssMetricV31" in metrics:
                    cvss_v3 = metrics["cvssMetricV31"][0].get("cvssData", {})
                    cvss_data = {
                        "version": "3.1",
                        "score": cvss_v3.get("baseScore", 0),
                        "severity": cvss_v3.get("baseSeverity", "UNKNOWN"),
                        "vector": cvss_v3.get("vectorString", "")
                    }
                elif "cvssMetricV30" in metrics:
                    cvss_v3 = metrics["cvssMetricV30"][0].get("cvssData", {})
                    cvss_data = {
                        "version": "3.0",
                        "score": cvss_v3.get("baseScore", 0),
                        "severity": cvss_v3.get("baseSeverity", "UNKNOWN"),
                        "vector": cvss_v3.get("vectorString", "")
                    }
                elif "cvssMetricV2" in metrics:
                    cvss_v2 = metrics["cvssMetricV2"][0].get("cvssData", {})
                    cvss_data = {
                        "version": "2.0",
                        "score": cvss_v2.get("baseScore", 0),
                        "severity": self._v2_score_to_severity(cvss_v2.get("baseScore", 0)),
                        "vector": cvss_v2.get("vectorString", "")
                    }
                
                # Get description
                descriptions = vuln.get("cve", {}).get("descriptions", [])
                description = ""
                for desc in descriptions:
                    if desc.get("lang") == "en":
                        description = desc.get("value", "")
                        break
                
                # Format to be consistent with existing vulnerabilities format
                formatted_vuln = {
                    "id": cve_id,
                    "technology": tech.split(" ")[0] if " " in tech else tech,
                    "version": tech.split(" ")[1] if " " in tech else "",
                    "title": description[:50] + "..." if len(description) > 50 else description,
                    "description": description,
                    "cvss": cvss_data,
                    "source": "nvd",
                    "references": vuln.get("cve", {}).get("references", []),
                    "published": vuln.get("cve", {}).get("published", ""),
                    "last_modified": vuln.get("cve", {}).get("lastModified", "")
                }
                
                # Add to vulnerabilities list
                scan_results["vulnerabilities"].append(formatted_vuln)
        
        return scan_results
    
    def _extract_technologies(self, scan_results: Dict[str, Any]) -> Dict[str, str]:
        """
        Extract technologies and their versions from scan results
        
        Args:
            scan_results: Scan results
            
        Returns:
            Dictionary of technology name to version
        """
        technologies = {}
        
        # Extract from open ports and services
        for port, data in scan_results.get("open_ports", {}).items():
            service = data.get("service", "")
            version = data.get("version", "")
            
            if service:
                # Clean up service name
                service_name = service.lower().split()[0]  # e.g., "apache" from "apache httpd"
                technologies[service_name] = version
                
                # Special handling for web servers
                if service_name in ["http", "https"]:
                    # Check for server header
                    if "apache" in service.lower():
                        technologies["apache"] = version
                    elif "nginx" in service.lower():
                        technologies["nginx"] = version
                    elif "iis" in service.lower():
                        technologies["iis"] = version
        
        # Extract from OS detection
        os_info = scan_results.get("os", {})
        if os_info and "name" in os_info:
            os_name = os_info["name"].lower()
            os_version = os_info.get("version", "")
            
            if "linux" in os_name:
                technologies["linux"] = os_version
            elif "windows" in os_name:
                technologies["windows"] = os_version
            elif "freebsd" in os_name:
                technologies["freebsd"] = os_version
            elif "macos" in os_name:
                technologies["macos"] = os_version
        
        return technologies
    
    def _v2_score_to_severity(self, score: float) -> str:
        """
        Convert CVSS v2 score to severity string
        
        Args:
            score: CVSS v2 base score
            
        Returns:
            Severity string
        """
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score > 0.0:
            return "LOW"
        else:
            return "NONE"
