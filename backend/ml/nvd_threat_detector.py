"""
FinGuardAI - NVD-Based Threat Detection Module

This module provides threat detection based on NVD vulnerability data instead of CICIDS dataset.
It integrates with the scan results to provide comprehensive threat information and recommendations.
"""

import os
import json
import logging
from typing import Dict, List, Any, Optional, Tuple

# Import NVD-related modules
from .remediation.nvd_vulnerability_predictor import NVDVulnerabilityPredictor
from .remediation.nvd_client import NVDClient
from .remediation.cvss_analyzer import extract_cvss_from_vulnerability, assess_financial_impact

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('finguardai.nvd_threat_detection')

class NVDThreatDetector:
    """Provides threat detection based on NVD vulnerability data."""
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize the NVD-based threat detector.
        
        Args:
            api_key: Optional NVD API key for higher rate limits
        """
        self.api_key = api_key
        self.nvd_client = NVDClient(api_key=self.api_key)
        self.vulnerability_predictor = NVDVulnerabilityPredictor(api_key=self.api_key)
        
    def detect_threats_from_scan_result(self, scan_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process scan results and detect threats using NVD data.
        
        Args:
            scan_result: Results from vulnerability scanner
            
        Returns:
            Enhanced scan results with threat predictions
        """
        # Extract technologies from scan results
        technologies = self._extract_technologies(scan_result)
        logger.info(f"Extracted technologies from scan: {technologies}")
        
        # Get predictions for each technology
        predictions = []
        for tech_name, tech_version in technologies.items():
            tech_predictions = self._get_predictions_for_technology(tech_name, tech_version)
            if tech_predictions:
                predictions.extend(tech_predictions)
        
        # Add predictions to scan results
        scan_result['ml_predictions'] = predictions
        scan_result['total_predictions'] = len(predictions)
        
        # Calculate overall risk score
        risk_score = self._calculate_risk_score(predictions)
        scan_result['risk_score'] = risk_score
        
        logger.info(f"Generated {len(predictions)} predictions with overall risk score {risk_score}")
        return scan_result
    
    def _extract_technologies(self, scan_result: Dict[str, Any]) -> Dict[str, str]:
        """
        Extract technology information from scan results.
        
        Args:
            scan_result: Results from vulnerability scanner
            
        Returns:
            Dictionary of technology name to version
        """
        technologies = {}
        
        # Extract from open ports and services
        for port, data in scan_result.get("open_ports", {}).items():
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
        os_info = scan_result.get("os", {})
        if os_info and "name" in os_info:
            os_name = os_info["name"].lower()
            os_version = os_info.get("version", "")
            
            if "linux" in os_name:
                technologies["linux"] = os_version
            elif "windows" in os_name:
                technologies["windows"] = os_version
        
        return technologies
    
    def _get_predictions_for_technology(self, tech_name: str, tech_version: str) -> List[Dict[str, Any]]:
        """
        Get vulnerability predictions for a specific technology.
        
        Args:
            tech_name: Technology name
            tech_version: Technology version
            
        Returns:
            List of prediction dictionaries
        """
        try:
            # Get vulnerability predictions
            raw_predictions = self.vulnerability_predictor.predict_vulnerabilities(tech_name, tech_version)
            
            # Format predictions
            formatted_predictions = []
            for i, pred in enumerate(raw_predictions):
                # Extract CVE ID
                cve_id = pred.get("cve", {}).get("id", f"PREDICTED-{tech_name}-{i}")
                
                # Extract description
                description = ""
                for desc in pred.get("cve", {}).get("descriptions", []):
                    if desc.get("lang") == "en":
                        description = desc.get("value", "")
                        break
                
                # Extract CVSS data and severity
                cvss_data = extract_cvss_from_vulnerability(pred)
                severity = cvss_data.get("severity", "medium").lower()
                
                # Calculate financial impact
                financial_impact = assess_financial_impact(cvss_data, tech_name)
                
                # Format prediction
                formatted_prediction = {
                    "id": cve_id,
                    "type": "vulnerability",
                    "name": f"{tech_name} {tech_version} vulnerability",
                    "confidence": cvss_data.get("score", 5.0) / 10.0,  # Convert to 0-1 scale
                    "severity": severity,
                    "description": description or f"Potential vulnerability in {tech_name} {tech_version}",
                    "technology": tech_name,
                    "version": tech_version,
                    "cvss": cvss_data,
                    "cve_id": cve_id,
                    "financial_impact": financial_impact
                }
                
                formatted_predictions.append(formatted_prediction)
            
            return formatted_predictions
            
        except Exception as e:
            logger.error(f"Error getting predictions for {tech_name} {tech_version}: {str(e)}")
            return []
    
    def _calculate_risk_score(self, predictions: List[Dict[str, Any]]) -> float:
        """
        Calculate overall risk score based on predictions.
        
        Args:
            predictions: List of prediction dictionaries
            
        Returns:
            Risk score from 0-100
        """
        if not predictions:
            return 0.0
        
        # Calculate weighted score based on severity and confidence
        severity_weights = {
            "critical": 1.0,
            "high": 0.8,
            "medium": 0.5,
            "low": 0.2
        }
        
        total_weight = 0.0
        weighted_sum = 0.0
        
        for pred in predictions:
            severity = pred.get("severity", "medium").lower()
            confidence = pred.get("confidence", 0.5)
            
            weight = severity_weights.get(severity, 0.5) * confidence
            weighted_sum += weight
            total_weight += severity_weights.get(severity, 0.5)
        
        if total_weight == 0:
            return 0.0
        
        # Scale to 0-100
        normalized_score = (weighted_sum / total_weight) * 100
        
        return round(normalized_score, 1)
