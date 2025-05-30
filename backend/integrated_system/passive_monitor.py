"""
Passive Monitoring Component for FinGuardAI

This module handles passive monitoring of targets to identify technologies without direct scanning.
"""

import os
import json
import logging
import requests
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse

from .config import logger

class PassiveMonitor:
    """
    Passive monitoring component that identifies technologies without direct scanning
    """
    
    def __init__(self, output_dir: str = None):
        """
        Initialize the passive monitor
        
        Args:
            output_dir: Directory to store monitoring results
        """
        self.output_dir = output_dir or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
            "monitoring_results"
        )
        os.makedirs(self.output_dir, exist_ok=True)
        self.logger = logging.getLogger("finguardai.passive_monitor")
    
    def monitor_target(self, target: str) -> Dict[str, Any]:
        """
        Passively monitor a target to identify technologies
        
        Args:
            target: Target URL or domain
            
        Returns:
            Dictionary with monitoring results
        """
        self.logger.info(f"Starting passive monitoring of {target}")
        
        # Format target as URL if needed
        if not target.startswith(('http://', 'https://')):
            target_url = f"https://{target}"
        else:
            target_url = target
        
        # Extract domain
        domain = urlparse(target_url).netloc
        
        # Output file
        output_file = os.path.join(self.output_dir, f"{domain.replace('.', '_')}_passive.json")
        
        # For demonstration purposes, we simulate the monitoring
        # In a real implementation, this would use passive detection techniques
        results = self._simulate_passive_detection(target_url)
        
        # Save results
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=4)
        
        self.logger.info(f"Completed passive monitoring of {target}, found {len(results.get('technologies', []))} technologies")
        return results
    
    def _simulate_passive_detection(self, target_url: str) -> Dict[str, Any]:
        """
        Simulate passive detection of technologies
        
        Args:
            target_url: URL of the target
            
        Returns:
            Dictionary with simulated passive detection results
        """
        domain = urlparse(target_url).netloc
        
        # Technology signatures by domain type
        edu_signatures = {
            "moodle": {"version": "3.11.4", "confidence": 80},
            "php": {"version": "7.4.21", "confidence": 90},
            "apache": {"version": "2.4.51", "confidence": 85},
            "mysql": {"version": "5.7.36", "confidence": 70}
        }
        
        gov_signatures = {
            "drupal": {"version": "9.2.6", "confidence": 75},
            "php": {"version": "7.4.21", "confidence": 90},
            "apache": {"version": "2.4.51", "confidence": 85},
            "mysql": {"version": "5.7.36", "confidence": 70}
        }
        
        com_signatures = {
            "wordpress": {"version": "5.8.2", "confidence": 85},
            "php": {"version": "8.0.10", "confidence": 90},
            "nginx": {"version": "1.20.1", "confidence": 80},
            "mysql": {"version": "8.0.26", "confidence": 70}
        }
        
        org_signatures = {
            "wordpress": {"version": "5.8.1", "confidence": 80},
            "php": {"version": "7.4.21", "confidence": 85},
            "apache": {"version": "2.4.46", "confidence": 75},
            "mysql": {"version": "5.7.36", "confidence": 70}
        }
        
        # Select signatures based on domain
        if domain.endswith('.edu'):
            signatures = edu_signatures
        elif domain.endswith('.gov'):
            signatures = gov_signatures
        elif domain.endswith('.org'):
            signatures = org_signatures
        else:
            signatures = com_signatures
        
        # Create technologies list
        technologies = []
        for name, details in signatures.items():
            technologies.append({
                "name": name,
                "version": details["version"],
                "confidence": details["confidence"]
            })
        
        # Add common server technologies
        if "apache" in [t["name"] for t in technologies]:
            server_tech = {
                "name": "ubuntu",
                "version": "20.04",
                "confidence": 60
            }
        else:
            server_tech = {
                "name": "centos",
                "version": "8.4",
                "confidence": 60
            }
        technologies.append(server_tech)
        
        # Additional javascript frameworks that might be detected
        if "wordpress" in [t["name"] for t in technologies]:
            js_techs = [
                {"name": "jquery", "version": "3.5.1", "confidence": 95},
                {"name": "bootstrap", "version": "4.6.0", "confidence": 90}
            ]
        else:
            js_techs = [
                {"name": "react", "version": "17.0.2", "confidence": 85},
                {"name": "bootstrap", "version": "5.1.1", "confidence": 80}
            ]
        technologies.extend(js_techs)
        
        return {
            "target": target_url,
            "domain": domain,
            "scan_time": "2025-05-17T12:30:00Z",
            "technologies": technologies,
            "headers": {
                "server": "Apache/2.4.51" if "apache" in [t["name"] for t in technologies] else "nginx/1.20.1",
                "x-powered-by": "PHP/7.4.21" if "php" in [t["name"] for t in technologies] else None
            }
        }
    
    def extract_technologies(self, passive_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract standardized technology information from passive monitoring
        
        Args:
            passive_result: Results from passive monitoring
            
        Returns:
            List of technologies with name, version and confidence
        """
        technologies = []
        
        # Extract from technologies section
        if "technologies" in passive_result:
            for tech in passive_result["technologies"]:
                if "name" in tech and "version" in tech:
                    technologies.append({
                        "name": tech["name"],
                        "version": tech["version"],
                        "confidence": tech.get("confidence", 100)
                    })
        
        # Extract from headers
        if "headers" in passive_result:
            headers = passive_result["headers"]
            if "server" in headers and headers["server"]:
                server = headers["server"]
                if "Apache" in server:
                    name = "apache"
                    version = server.split("/")[1] if "/" in server else ""
                elif "nginx" in server:
                    name = "nginx"
                    version = server.split("/")[1] if "/" in server else ""
                else:
                    name = server.split("/")[0].lower() if "/" in server else server.lower()
                    version = server.split("/")[1] if "/" in server else ""
                
                if version and {"name": name, "version": version} not in technologies:
                    technologies.append({
                        "name": name,
                        "version": version,
                        "confidence": 90,
                        "source": "headers"
                    })
            
            if "x-powered-by" in headers and headers["x-powered-by"]:
                powered_by = headers["x-powered-by"]
                if "PHP" in powered_by:
                    name = "php"
                    version = powered_by.split("/")[1] if "/" in powered_by else ""
                    
                    if version and {"name": name, "version": version} not in technologies:
                        technologies.append({
                            "name": name,
                            "version": version,
                            "confidence": 90,
                            "source": "headers"
                        })
        
        return technologies
