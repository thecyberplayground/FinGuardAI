"""
Enhanced NVD Search Capabilities

This module provides advanced search functionality for the NVD API,
extending our basic NVD client with more powerful search capabilities.
"""

import os
import re
import json
import time
import logging
import datetime
import requests
from typing import Dict, List, Any, Optional, Set, Tuple

# Import basic NVD client
from .nvd_client import NVDClient

# Import CVSS analyzer
from .cvss_analyzer import extract_cvss_from_vulnerability, assess_financial_impact

# Configure logging
logger = logging.getLogger("finguardai.nvd_advanced")

class NVDAdvancedSearch:
    """Advanced search capabilities for NVD data"""
    
    def __init__(self, api_key: Optional[str] = None, base_client: Optional[NVDClient] = None):
        """
        Initialize advanced search capabilities
        
        Args:
            api_key: Optional NVD API key
            base_client: Optional existing NVDClient instance
        """
        self.api_key = api_key
        self.base_client = base_client or NVDClient(api_key=api_key)
        self.cache_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "cache")
        os.makedirs(self.cache_dir, exist_ok=True)
    
    def search_by_keywords(self, keywords: List[str], published_after: Optional[str] = None,
                          max_results: int = 50) -> List[Dict[str, Any]]:
        """
        Search NVD by keywords with advanced filtering
        
        Args:
            keywords: List of keywords to search for
            published_after: Optional ISO date string (YYYY-MM-DD)
            max_results: Maximum number of results to return
            
        Returns:
            List of vulnerability dictionaries
        """
        # Construct keyword search string
        keyword_query = " AND ".join(keywords)
        
        # Build parameters
        params = {
            "keywordSearch": keyword_query,
            "resultsPerPage": min(max_results, 100)  # NVD API limits to 100 max
        }
        
        # Add date filter if provided
        if published_after:
            params["pubStartDate"] = published_after + "T00:00:00.000"
        
        # Make the request through base client
        try:
            logger.info(f"Performing keyword search with: {keyword_query}")
            vulnerabilities = self.base_client.get_vulnerabilities(params)
            
            # Process vulnerabilities with enhanced metadata
            results = []
            for vuln in vulnerabilities[:max_results]:
                # Enhance with CVSS analysis
                vuln["enhanced_cvss"] = extract_cvss_from_vulnerability(vuln)
                results.append(vuln)
            
            return results
        
        except Exception as e:
            logger.error(f"Error in keyword search: {e}")
            return []
    
    def search_by_cwe(self, cwe_ids: List[str], max_results: int = 50) -> List[Dict[str, Any]]:
        """
        Search for vulnerabilities by Common Weakness Enumeration (CWE) IDs
        
        Args:
            cwe_ids: List of CWE IDs (e.g., ['CWE-79', 'CWE-89'])
            max_results: Maximum number of results to return
            
        Returns:
            List of vulnerabilities matching the CWEs
        """
        results = []
        
        try:
            for cwe_id in cwe_ids:
                # Clean CWE ID format
                if not cwe_id.startswith("CWE-"):
                    cwe_id = f"CWE-{cwe_id}"
                
                # Build parameters
                params = {
                    "cweId": cwe_id,
                    "resultsPerPage": min(max_results, 50)  # Keep request size reasonable
                }
                
                logger.info(f"Searching for vulnerabilities with {cwe_id}")
                vulns = self.base_client.get_vulnerabilities(params)
                
                # Process results
                for vuln in vulns:
                    # Add the matching CWE for reference
                    vuln["matched_cwe"] = cwe_id
                    # Enhance with CVSS analysis
                    vuln["enhanced_cvss"] = extract_cvss_from_vulnerability(vuln)
                    results.append(vuln)
                
                # Respect rate limits
                time.sleep(0.6)  # Ensure we don't exceed rate limits
                
                # Stop if we've reached max results
                if len(results) >= max_results:
                    break
        
        except Exception as e:
            logger.error(f"Error searching by CWE: {e}")
        
        return results[:max_results]
    
    def search_recent_critical_vulnerabilities(self, days_back: int = 30, min_cvss_score: float = 9.0,
                                              technology_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Search for recent critical vulnerabilities
        
        Args:
            days_back: How many days back to search
            min_cvss_score: Minimum CVSS score to consider critical
            technology_filter: Optional technology to filter by
            
        Returns:
            List of recent critical vulnerabilities
        """
        # Calculate start date
        start_date = (datetime.datetime.now() - datetime.timedelta(days=days_back)).strftime("%Y-%m-%d")
        
        # Build parameters
        params = {
            "pubStartDate": start_date + "T00:00:00.000",
            "cvssV3Severity": "CRITICAL",  # Focus on critical severity
            "resultsPerPage": 100  # Get more results for filtering
        }
        
        # Add technology filter if provided
        if technology_filter:
            params["keywordSearch"] = technology_filter
        
        try:
            logger.info(f"Searching for recent critical vulnerabilities since {start_date}")
            vulnerabilities = self.base_client.get_vulnerabilities(params)
            
            # Further filter by CVSS score
            results = []
            for vuln in vulnerabilities:
                # Extract CVSS data
                metrics = vuln.get("metrics", {})
                
                # Check v3.1 score
                cvss_v3_1 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}) if metrics.get("cvssMetricV31") else {}
                score_v3_1 = cvss_v3_1.get("baseScore", 0)
                
                # Check v3.0 score if v3.1 isn't available
                cvss_v3_0 = metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {}) if metrics.get("cvssMetricV30") and score_v3_1 == 0 else {}
                score_v3_0 = cvss_v3_0.get("baseScore", 0)
                
                # Use highest available score
                score = max(score_v3_1, score_v3_0)
                
                # Filter by minimum score
                if score >= min_cvss_score:
                    # Add enhanced CVSS analysis
                    vuln["enhanced_cvss"] = extract_cvss_from_vulnerability(vuln)
                    
                    # Add financial impact assessment
                    if vuln["enhanced_cvss"].get("analysis"):
                        vuln["financial_impact"] = assess_financial_impact(vuln["enhanced_cvss"]["analysis"])
                    
                    results.append(vuln)
            
            return results
            
        except Exception as e:
            logger.error(f"Error searching recent critical vulns: {e}")
            return []
    
    def search_exploited_vulnerabilities(self, technology: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Search for vulnerabilities with known exploits
        
        Args:
            technology: Optional technology to filter by
            
        Returns:
            List of vulnerabilities with known exploits
        """
        # The NVD API has a has_exploit parameter we can use
        params = {
            "hasExploit": True,
            "resultsPerPage": 100
        }
        
        # Add technology filter if provided
        if technology:
            params["keywordSearch"] = technology
        
        try:
            logger.info(f"Searching for vulnerabilities with known exploits")
            exploitable_vulns = self.base_client.get_vulnerabilities(params)
            
            # Enhance with CVSS analysis
            results = []
            for vuln in exploitable_vulns:
                vuln["enhanced_cvss"] = extract_cvss_from_vulnerability(vuln)
                
                # Add exploit details if available
                if "references" in vuln.get("cve", {}):
                    exploit_refs = []
                    for ref in vuln["cve"]["references"]:
                        tags = ref.get("tags", [])
                        if "Exploit" in tags or "Exploit Code" in tags:
                            exploit_refs.append({
                                "url": ref.get("url"),
                                "source": ref.get("source"),
                                "tags": tags
                            })
                    
                    if exploit_refs:
                        vuln["exploit_references"] = exploit_refs
                
                results.append(vuln)
            
            return results
            
        except Exception as e:
            logger.error(f"Error searching for exploited vulnerabilities: {e}")
            return []
    
    def get_vulnerability_trends(self, technology: str, time_periods: int = 3) -> Dict[str, Any]:
        """
        Analyze vulnerability trends for a technology over time
        
        Args:
            technology: Technology name to analyze
            time_periods: Number of time periods (months) to analyze
            
        Returns:
            Dictionary with trend analysis
        """
        trends = {
            "technology": technology,
            "time_periods": [],
            "total_vulnerabilities": 0,
            "critical_count": 0,
            "high_count": 0,
            "increasing_trend": False,
            "period_data": []
        }
        
        try:
            # Calculate time periods (months)
            for i in range(time_periods):
                end_date = datetime.datetime.now() - datetime.timedelta(days=30*i)
                start_date = end_date - datetime.timedelta(days=30)
                
                period = {
                    "start_date": start_date.strftime("%Y-%m-%d"),
                    "end_date": end_date.strftime("%Y-%m-%d"),
                    "vulnerabilities": []
                }
                
                # Search for vulnerabilities in this period
                params = {
                    "keywordSearch": technology,
                    "pubStartDate": period["start_date"] + "T00:00:00.000",
                    "pubEndDate": period["end_date"] + "T23:59:59.999",
                    "resultsPerPage": 50
                }
                
                # Get vulnerabilities
                vulns = self.base_client.get_vulnerabilities(params)
                period["count"] = len(vulns)
                
                # Count by severity
                critical = 0
                high = 0
                
                for vuln in vulns:
                    metrics = vuln.get("metrics", {})
                    
                    # Check v3.1 severity
                    cvss_v3_1 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}) if metrics.get("cvssMetricV31") else {}
                    severity = cvss_v3_1.get("baseSeverity", "")
                    
                    if severity == "CRITICAL":
                        critical += 1
                    elif severity == "HIGH":
                        high += 1
                
                period["critical"] = critical
                period["high"] = high
                trends["period_data"].append(period)
                
                # Update totals
                trends["total_vulnerabilities"] += period["count"]
                trends["critical_count"] += critical
                trends["high_count"] += high
                
                # Respect rate limits
                time.sleep(0.6)
            
            # Determine if there's an increasing trend
            if len(trends["period_data"]) >= 2:
                latest = trends["period_data"][0]["count"]
                previous = trends["period_data"][1]["count"]
                trends["increasing_trend"] = latest > previous
            
            return trends
            
        except Exception as e:
            logger.error(f"Error analyzing vulnerability trends: {e}")
            return {"error": str(e), "technology": technology}
