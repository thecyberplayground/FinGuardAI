"""
FinGuardAI - NVD API Client

This module provides a client for interacting with the National Vulnerability Database (NVD) API.
It handles authentication, rate limiting, and caching of vulnerability data.
"""

import os
import json
import time
import logging
import datetime
import requests
from typing import Dict, List, Any, Optional, Union

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("finguardai.nvd_client")

# NVD API base URL
NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Path to cache directory
CACHE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "cache")
os.makedirs(CACHE_DIR, exist_ok=True)

class NVDClient:
    """Client for interacting with the NVD API"""
    
    def __init__(self, api_key: Optional[str] = None, cache_duration_hours: int = 24):
        """
        Initialize the NVD API client
        
        Args:
            api_key: NVD API key for authentication and higher rate limits
            cache_duration_hours: How long to cache results before refreshing
        """
        self.api_key = api_key
        self.cache_duration_hours = cache_duration_hours
    
    def get_vulnerabilities(self, 
                           params: Dict[str, Any],
                           cache_key: Optional[str] = None) -> Dict[str, Any]:
        """
        Get vulnerabilities from the NVD API with caching
        
        Args:
            params: Query parameters for the API request
            cache_key: Key for caching results
            
        Returns:
            Dictionary with vulnerability data
        """
        # Use provided cache key or generate one based on params
        if not cache_key:
            cache_key = f"nvd_search_{hash(str(sorted(params.items())))}"
        
        # Sanitize cache key to ensure it's a valid filename
        safe_cache_key = self._sanitize_filename(cache_key)
        
        cache_file = os.path.join(CACHE_DIR, f"{safe_cache_key}.json")
        
        # Check if we have a valid cache
        if self._is_cache_valid(cache_file):
            logger.info(f"Using cached NVD data for {cache_key}")
            return self._load_cache(cache_file)
        
        # Set up headers
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        
        logger.info(f"Fetching vulnerabilities from NVD API with params: {params}")
        
        try:
            # Make the request
            response = requests.get(NVD_API_BASE_URL, params=params, headers=headers)
            
            # Handle rate limiting
            if response.status_code == 403:
                logger.warning("NVD API rate limit exceeded, using cached data if available")
                if os.path.exists(cache_file):
                    return self._load_cache(cache_file)
                else:
                    logger.error("No cached data available and rate limit exceeded")
                    return {"vulnerabilities": []}
            
            # Check for other errors
            response.raise_for_status()
            
            # Parse the response
            data = response.json()
            
            # Cache the results
            self._save_cache(cache_file, data)
            
            return data
            
        except Exception as e:
            logger.error(f"Error fetching vulnerabilities from NVD API: {e}")
            
            # Fallback to cached data if available
            if os.path.exists(cache_file):
                logger.info("Falling back to cached data")
                return self._load_cache(cache_file)
            
            return {"vulnerabilities": []}
    
    def get_vulnerabilities_by_cpe(self,
                                  cpe_name: str,
                                  last_mod_start_date: Optional[str] = None,
                                  max_results: int = 100) -> List[Dict[str, Any]]:
        """
        Get vulnerabilities for a specific CPE
        
        Args:
            cpe_name: CPE name to search for (e.g., cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*)
            last_mod_start_date: Only return vulnerabilities modified after this date
            max_results: Maximum number of results to return
            
        Returns:
            List of vulnerability dictionaries
        """
        # Build query parameters
        params = {
            "cpeName": cpe_name,
            "resultsPerPage": min(max_results, 2000)  # API limit is 2000
        }
        
        # Add last_mod_start_date if provided
        if last_mod_start_date:
            params["lastModStartDate"] = last_mod_start_date
        
        # Generate cache key
        cache_key = f"cpe_{cpe_name.replace(':', '_')}"
        
        # Get vulnerabilities
        result = self.get_vulnerabilities(params, cache_key)
        
        # Extract vulnerabilities
        return result.get("vulnerabilities", [])
    
    def get_vulnerabilities_by_keyword(self,
                                      keyword: str,
                                      max_results: int = 100) -> List[Dict[str, Any]]:
        """
        Get vulnerabilities for a specific keyword
        
        Args:
            keyword: Keyword to search for
            max_results: Maximum number of results to return
            
        Returns:
            List of vulnerability dictionaries
        """
        # Build query parameters
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": min(max_results, 2000)  # API limit is 2000
        }
        
        # Generate cache key
        cache_key = f"keyword_{keyword}"
        
        # Get vulnerabilities
        result = self.get_vulnerabilities(params, cache_key)
        
        # Extract vulnerabilities
        return result.get("vulnerabilities", [])
    
    def get_recent_vulnerabilities(self, days: int = 30, max_results: int = 100) -> List[Dict[str, Any]]:
        """
        Get recent vulnerabilities
        
        Args:
            days: Number of days to look back
            max_results: Maximum number of results to return
            
        Returns:
            List of vulnerability dictionaries
        """
        # Calculate start date
        start_date = datetime.datetime.now() - datetime.timedelta(days=days)
        pub_start_date = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        
        # Build query parameters
        params = {
            "pubStartDate": pub_start_date,
            "resultsPerPage": min(max_results, 2000)  # API limit is 2000
        }
        
        # Generate cache key
        cache_key = f"recent_{days}days"
        
        # Get vulnerabilities
        result = self.get_vulnerabilities(params, cache_key)
        
        # Extract vulnerabilities
        return result.get("vulnerabilities", [])
    
    def get_cve_details(self, cve_id: str) -> Dict[str, Any]:
        """
        Get details for a specific CVE ID
        
        Args:
            cve_id: CVE ID (e.g., CVE-2021-44228)
            
        Returns:
            Dictionary with CVE details or empty dict if not found
        """
        # Build query parameters - using exact match for CVE ID
        params = {
            "cveId": cve_id
        }
        
        # Generate cache key
        cache_key = f"cve_details_{cve_id}"
        
        # Get vulnerability data
        result = self.get_vulnerabilities(params, cache_key)
        
        # Extract the vulnerability if found
        vulnerabilities = result.get("vulnerabilities", [])
        if vulnerabilities and len(vulnerabilities) > 0:
            return vulnerabilities[0]
        
        logger.warning(f"CVE details not found for {cve_id}")
        return {}
    
    def get_remediation_info(self, cve_id: str) -> Dict[str, Any]:
        """
        Extract remediation information for a CVE
        
        Args:
            cve_id: CVE ID to get remediation for
            
        Returns:
            Dictionary with remediation information
        """
        # Get the CVE details
        cve_data = self.get_cve_details(cve_id)
        
        # Initialize remediation info with default values
        remediation_info = {
            "id": f"rem_{cve_id}",
            "vulnerability_id": cve_id,
            "recommendation": "Update affected components to the latest secure version.",
            "difficulty": "medium",
            "estimated_time": "4h",
            "priority": "high",
            "references": [
                f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
            ]
        }
        
        # If we found data for this CVE
        if cve_data:
            cve_item = cve_data.get("cve", {})
            
            # Extract descriptions
            descriptions = cve_item.get("descriptions", [])
            for desc in descriptions:
                if desc.get("lang") == "en":
                    # Get full description
                    full_desc = desc.get("value", "")
                    remediation_info["description"] = full_desc
                    
                    # Look for remediation information in description
                    remediation_text = ""
                    for remedy_indicator in ["fix", "patch", "update", "upgrade", "mitigate", "workaround", "remediation"]:
                        if remedy_indicator in full_desc.lower():
                            # Extract sentences containing remediation info
                            sentences = full_desc.split(". ")
                            for sentence in sentences:
                                if remedy_indicator in sentence.lower():
                                    remediation_text += sentence + ". "
                    
                    if remediation_text:
                        remediation_info["recommendation"] = remediation_text
            
            # Extract references for more detailed information
            references = cve_item.get("references", [])
            if references:
                ref_links = []
                for ref in references:
                    ref_url = ref.get("url")
                    if ref_url:
                        ref_links.append(ref_url)
                if ref_links:
                    remediation_info["references"] = ref_links[:5]  # Limit to 5 references
            
            # Extract metrics to determine priority and difficulty
            metrics = cve_item.get("metrics", {})
            cvss_v31 = metrics.get("cvssMetricV31", [{}])[0] if "cvssMetricV31" in metrics else {}
            cvss_v30 = metrics.get("cvssMetricV30", [{}])[0] if "cvssMetricV30" in metrics else {}
            cvss_v2 = metrics.get("cvssMetricV2", [{}])[0] if "cvssMetricV2" in metrics else {}
            
            # Use the most recent CVSS version available
            cvss_data = cvss_v31 or cvss_v30 or cvss_v2 or {}
            cvss_data = cvss_data.get("cvssData", {})
            
            # Set priority based on base score
            base_score = cvss_data.get("baseScore")
            if base_score is not None:
                if base_score >= 9.0:
                    remediation_info["priority"] = "critical"
                    remediation_info["cost_of_inaction"] = 100000
                    remediation_info["difficulty"] = "high"
                    remediation_info["estimated_time"] = "24h"
                elif base_score >= 7.0:
                    remediation_info["priority"] = "high"
                    remediation_info["cost_of_inaction"] = 50000
                    remediation_info["difficulty"] = "medium"
                    remediation_info["estimated_time"] = "12h"
                elif base_score >= 4.0:
                    remediation_info["priority"] = "medium"
                    remediation_info["cost_of_inaction"] = 25000
                    remediation_info["difficulty"] = "medium"
                    remediation_info["estimated_time"] = "8h"
                else:
                    remediation_info["priority"] = "low"
                    remediation_info["cost_of_inaction"] = 10000
                    remediation_info["difficulty"] = "easy"
                    remediation_info["estimated_time"] = "4h"
            
            # Look for code examples or configurations in references
            for ref in references:
                tags = ref.get("tags", [])
                if "Patch" in tags or "Vendor Advisory" in tags:
                    remediation_info["patch_available"] = True
        
        return remediation_info
    
    def _is_cache_valid(self, cache_file: str) -> bool:
        """
        Check if the cached data is still valid
        
        Args:
            cache_file: Path to cache file
            
        Returns:
            True if cache is valid, False otherwise
        """
        if not os.path.exists(cache_file):
            return False
        
        # Check file modification time
        mod_time = os.path.getmtime(cache_file)
        mod_datetime = datetime.datetime.fromtimestamp(mod_time)
        
        # Calculate how old the cache is
        age = datetime.datetime.now() - mod_datetime
        
        # Convert cache duration to seconds
        max_age_seconds = self.cache_duration_hours * 3600
        
        return age.total_seconds() < max_age_seconds
    
    def _load_cache(self, cache_file: str) -> Dict[str, Any]:
        """
        Load data from cache
        
        Args:
            cache_file: Path to cache file
            
        Returns:
            Cached data
        """
        try:
            with open(cache_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading cache file {cache_file}: {e}")
            return {"vulnerabilities": []}
    
    def _save_cache(self, cache_file: str, data: Dict[str, Any]) -> None:
        """
        Save data to cache
        
        Args:
            cache_file: Path to cache file
            data: Data to cache
        """
        try:
            with open(cache_file, 'w') as f:
                json.dump(data, f, indent=2)
            logger.info(f"Saved NVD data to cache file {cache_file}")
        except Exception as e:
            logger.error(f"Error saving to cache file {cache_file}: {e}")
            
    def _sanitize_filename(self, filename: str) -> str:
        """
        Sanitize a string to be used as a filename
        
        Args:
            filename: String to sanitize
            
        Returns:
            Sanitized string safe to use as a filename
        """
        # Replace characters that are invalid in filenames
        invalid_chars = ['<', '>', ':', '"', '/', '\\', '|', '?', '*']
        for char in invalid_chars:
            filename = filename.replace(char, '_')
            
        # Also replace any other non-alphanumeric characters to be safe
        import re
        filename = re.sub(r'[^a-zA-Z0-9_.-]', '_', filename)
        
        # Limit the length to avoid path length issues
        if len(filename) > 100:
            filename = filename[:100]
            
        return filename


def generate_cpe_name(tech: str, version: str) -> str:
    """
    Generate a CPE name for a technology and version
    
    Args:
        tech: Technology name (e.g., apache, nginx)
        version: Version string
        
    Returns:
        CPE name
    """
    # CPE name mappings for common technologies
    cpe_patterns = {
        "apache": f"cpe:2.3:a:apache:http_server:{version}:*:*:*:*:*:*:*",
        "nginx": f"cpe:2.3:a:nginx:nginx:{version}:*:*:*:*:*:*:*",
        "mysql": f"cpe:2.3:a:oracle:mysql:{version}:*:*:*:*:*:*:*",
        "openssh": f"cpe:2.3:a:openbsd:openssh:{version}:*:*:*:*:*:*:*",
        "php": f"cpe:2.3:a:php:php:{version}:*:*:*:*:*:*:*"
    }
    
    return cpe_patterns.get(tech.lower(), f"cpe:2.3:a:*:{tech}:{version}:*:*:*:*:*:*:*")
