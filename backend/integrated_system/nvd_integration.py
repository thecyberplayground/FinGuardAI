"""
NVD API Integration Component for FinGuardAI

This module integrates our existing NVD client with enhanced features to provide
comprehensive vulnerability data and predictions.
"""

import os
import json
import time
import logging
import datetime
from typing import Dict, List, Any, Optional, Tuple

# Import existing NVD client and enhanced capabilities
try:
    # Try relative imports first
    from ..ml.remediation.nvd_client import NVDClient
    from ..ml.remediation.nvd_advanced_search import NVDAdvancedSearch
    from ..ml.remediation.cvss_analyzer import extract_cvss_from_vulnerability, assess_financial_impact
    from .config import NVD_API_KEY, NVD_CACHE_TTL, logger
except ImportError:
    # Fall back to absolute imports
    import sys
    import os
    backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if backend_dir not in sys.path:
        sys.path.append(backend_dir)
    
    try:
        from ml.remediation.nvd_client import NVDClient
        from ml.remediation.nvd_advanced_search import NVDAdvancedSearch
        from ml.remediation.cvss_analyzer import extract_cvss_from_vulnerability, assess_financial_impact
        from integrated_system.config import NVD_API_KEY, NVD_CACHE_TTL, logger
    except ImportError:
        # Direct imports as last resort
        import logging
        logger = logging.getLogger('finguardai.nvd_integration')
        
        try:
            from nvd_client import NVDClient
            from nvd_advanced_search import NVDAdvancedSearch
            from cvss_analyzer import extract_cvss_from_vulnerability, assess_financial_impact
        except ImportError:
            # Define stubs if modules can't be imported
            class NVDClient:
                def __init__(self, *args, **kwargs):
                    pass
                def get_cves_for_cpe(self, *args, **kwargs):
                    return []
            
            class NVDAdvancedSearch:
                def __init__(self, *args, **kwargs):
                    pass
                def search(self, *args, **kwargs):
                    return []
            
            def extract_cvss_from_vulnerability(vuln):
                return {"base_score": 0}
                
            def assess_financial_impact(cvss_data):
                return {"financial_impact": "Unknown"}
        
        # Define defaults if config is missing
        NVD_API_KEY = None
        NVD_CACHE_TTL = 86400

class NVDIntegration:
    """
    Integration with the NVD API for enhanced vulnerability data
    """
    
    def __init__(self, api_key: Optional[str] = None, cache_dir: Optional[str] = None):
        """
        Initialize NVD integration
        
        Args:
            api_key: Optional NVD API key
            cache_dir: Optional cache directory
        """
        self.api_key = api_key or NVD_API_KEY
        self.cache_dir = cache_dir or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
            "cache", "nvd"
        )
        os.makedirs(self.cache_dir, exist_ok=True)
        
        self.logger = logging.getLogger("finguardai.nvd_integration")
        
        # Create NVD clients
        self.nvd_client = NVDClient(api_key=self.api_key)
        self.advanced_search = NVDAdvancedSearch(api_key=self.api_key, base_client=self.nvd_client)
        
    def get_vulnerabilities_for_technology(self, 
                                          technology: str, 
                                          version: str, 
                                          days_back: int = 365) -> List[Dict[str, Any]]:
        """
        Get vulnerabilities for a specific technology and version
        
        Args:
            technology: Technology name
            version: Technology version
            days_back: Number of days to look back
            
        Returns:
            List of vulnerabilities
        """
        self.logger.info(f"Fetching vulnerabilities for {technology} {version}")
        
        # Calculate start date
        start_date = (datetime.datetime.now() - datetime.timedelta(days=days_back)).strftime("%Y-%m-%d")
        
        # Build search parameters
        params = {
            "keywordSearch": f"{technology} {version}",
            "pubStartDate": start_date + "T00:00:00.000",
            "resultsPerPage": 50
        }
        
        # Make the request
        try:
            results = self.nvd_client.get_vulnerabilities(params)
            
            # Enhance each vulnerability with CVSS analysis
            enhanced_results = []
            for vuln in results:
                vuln["enhanced_cvss"] = extract_cvss_from_vulnerability(vuln)
                enhanced_results.append(vuln)
            
            self.logger.info(f"Found {len(enhanced_results)} vulnerabilities for {technology} {version}")
            return enhanced_results
            
        except Exception as e:
            self.logger.error(f"Error fetching vulnerabilities for {technology} {version}: {e}")
            return []
    
    def get_vulnerabilities_by_timeframe(self, technologies: List[Dict[str, str]], 
                                        timeframes: List[str]) -> Dict[str, Any]:
        """
        Get vulnerabilities organized by timeframe
        
        Args:
            technologies: List of technologies with name and version
            timeframes: List of timeframes (e.g., ["1_day", "7_days", "30_days"])
            
        Returns:
            Dictionary with vulnerabilities by timeframe
        """
        self.logger.info(f"Getting vulnerabilities by timeframe for {len(technologies)} technologies")
        
        # Map timeframe names to days
        timeframe_days = {
            "1_day": 1,
            "1_week": 7,
            "7_days": 7,
            "10_days": 10,
            "30_days": 30,
            "60_days": 60,
            "90_days": 90,
            "180_days": 180,
            "1_year": 365
        }
        
        # Initialize results structure
        results = {
            "technologies": technologies,
            "timeframes": {},
            "summary": {}
        }
        
        # Initialize counters for summary
        total_vulns = 0
        critical_vulns = 0
        high_vulns = 0
        exploitable_vulns = 0
        
        # Process each timeframe
        for timeframe in timeframes:
            days = timeframe_days.get(timeframe, 30)  # Default to 30 days
            
            timeframe_results = {
                "days": days,
                "vulnerabilities_by_technology": {},
                "total_count": 0,
                "critical_count": 0,
                "high_count": 0
            }
            
            # Process each technology
            for tech in technologies:
                tech_name = tech["name"]
                tech_version = tech["version"]
                
                # Get vulnerabilities for this technology and timeframe
                vulns = self.get_vulnerabilities_for_technology(tech_name, tech_version, days)
                
                # Count by severity
                critical = 0
                high = 0
                
                for vuln in vulns:
                    metrics = vuln.get("metrics", {})
                    
                    # Check CVSS v3.1 first, then v3.0
                    v31 = metrics.get("cvssMetricV31", [{}])[0] if metrics.get("cvssMetricV31") else {}
                    v30 = metrics.get("cvssMetricV30", [{}])[0] if metrics.get("cvssMetricV30") else {}
                    
                    # Get severity from v3.1 or v3.0
                    severity = (v31.get("cvssData", {}).get("baseSeverity") or 
                               v30.get("cvssData", {}).get("baseSeverity") or "").upper()
                    
                    if severity == "CRITICAL":
                        critical += 1
                    elif severity == "HIGH":
                        high += 1
                
                # Add to timeframe results
                if vulns:
                    timeframe_results["vulnerabilities_by_technology"][f"{tech_name} {tech_version}"] = {
                        "vulnerabilities": vulns,
                        "count": len(vulns),
                        "critical": critical,
                        "high": high
                    }
                    
                    # Update timeframe counters
                    timeframe_results["total_count"] += len(vulns)
                    timeframe_results["critical_count"] += critical
                    timeframe_results["high_count"] += high
                    
                    # Update total counters for summary
                    total_vulns += len(vulns)
                    critical_vulns += critical
                    high_vulns += high
            
            # Add timeframe results to main results
            results["timeframes"][timeframe] = timeframe_results
        
        # Create summary
        results["summary"] = {
            "total_vulnerabilities": total_vulns,
            "critical_vulnerabilities": critical_vulns,
            "high_vulnerabilities": high_vulns,
            "technologies_count": len(technologies),
            "timeframes_count": len(timeframes)
        }
        
        self.logger.info(f"Found {total_vulns} total vulnerabilities across all timeframes")
        return results
    
    def get_remediation_recommendations(self, technology: str, version: str) -> Dict[str, Any]:
        """
        Get remediation recommendations for a specific technology and version
        
        Args:
            technology: Technology name
            version: Technology version
            
        Returns:
            Dictionary with remediation recommendations
        """
        self.logger.info(f"Getting remediation recommendations for {technology} {version}")
        
        # Get vulnerabilities from the last year
        vulns = self.get_vulnerabilities_for_technology(technology, version, 365)
        
        if not vulns:
            return {
                "technology": technology,
                "version": version,
                "status": "No vulnerabilities found",
                "recommendations": ["Keep the system updated with the latest patches"]
            }
        
        # Count severities
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        
        for vuln in vulns:
            metrics = vuln.get("metrics", {})
            
            # Check CVSS v3.1 first, then v3.0
            v31 = metrics.get("cvssMetricV31", [{}])[0] if metrics.get("cvssMetricV31") else {}
            v30 = metrics.get("cvssMetricV30", [{}])[0] if metrics.get("cvssMetricV30") else {}
            
            # Get severity from v3.1 or v3.0
            severity = (v31.get("cvssData", {}).get("baseSeverity") or 
                       v30.get("cvssData", {}).get("baseSeverity") or "").upper()
            
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Check for known exploits
        exploited_vulns = self.advanced_search.search_exploited_vulnerabilities(technology)
        applicable_exploits = [v for v in exploited_vulns if technology.lower() in v.get("cve", {}).get("descriptions", [{}])[0].get("value", "").lower()]
        
        # Generate recommendations
        recommendations = []
        
        # Basic recommendation if outdated
        if severity_counts["CRITICAL"] > 0 or severity_counts["HIGH"] > 3:
            recommendations.append(f"Upgrade {technology} to the latest stable version immediately")
        elif severity_counts["HIGH"] > 0 or severity_counts["MEDIUM"] > 5:
            recommendations.append(f"Consider upgrading {technology} to a more recent version")
        else:
            recommendations.append(f"Monitor for new vulnerabilities in {technology} {version}")
        
        # Add specific recommendations based on findings
        if applicable_exploits:
            recommendations.append("Apply security patches immediately as exploits exist for this version")
            
        if severity_counts["CRITICAL"] > 0:
            recommendations.append("Implement additional security controls to mitigate critical vulnerabilities")
            
        # Add general recommendations
        recommendations.extend([
            "Ensure regular security updates are applied",
            "Consider implementing a web application firewall",
            "Review configuration for security best practices"
        ])
        
        return {
            "technology": technology,
            "version": version,
            "vulnerability_count": len(vulns),
            "severity_counts": severity_counts,
            "exploitable": len(applicable_exploits) > 0,
            "recommendations": recommendations,
            "upgrade_urgency": "high" if severity_counts["CRITICAL"] > 0 or applicable_exploits else 
                              "medium" if severity_counts["HIGH"] > 0 else "low"
        }
