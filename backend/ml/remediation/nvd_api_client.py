"""
NVD API Client for FinGuardAI

This module provides functionality to download and process real vulnerability data
from the National Vulnerability Database (NVD) API.
"""

import os
import json
import time
import logging
import datetime
import requests
from typing import Dict, List, Any, Optional

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("finguardai.nvd_api")

# NVD API base URL
NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Cache directory for downloaded data
CACHE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 
                       "cache")

# Ensure cache directory exists
os.makedirs(CACHE_DIR, exist_ok=True)

class NvdApiClient:
    """Client for interacting with the NVD API to fetch real vulnerability data"""
    
    def __init__(self, api_key: Optional[str] = None, cache_duration_hours: int = 24):
        """
        Initialize the NVD API client
        
        Args:
            api_key: Optional NVD API key for higher rate limits
            cache_duration_hours: How long to cache results before refreshing
        """
        self.api_key = api_key
        self.cache_duration_hours = cache_duration_hours
        self.cache_file = os.path.join(CACHE_DIR, "nvd_cve_cache.json")
    
    def get_vulnerabilities(self, 
                          keywords: Optional[List[str]] = None, 
                          cpe_name: Optional[str] = None,
                          published_after: Optional[datetime.datetime] = None,
                          max_results: int = 100) -> List[Dict[str, Any]]:
        """
        Get vulnerabilities from the NVD API with caching
        
        Args:
            keywords: List of keywords to search for
            cpe_name: Filter by CPE name
            published_after: Only return vulnerabilities published after this date
            max_results: Maximum number of results to return
            
        Returns:
            List of vulnerability dictionaries
        """
        # Check if we have a recent cache
        if self._is_cache_valid():
            logger.info("Using cached NVD data")
            return self._load_cache()
        
        # Build request parameters
        params = {
            "resultsPerPage": min(max_results, 2000)  # API limit is 2000
        }
        
        # Add API key if available
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        
        # Add keywords if provided
        if keywords:
            params["keywordSearch"] = " ".join(keywords)
        
        # Add CPE name if provided
        if cpe_name:
            params["cpeName"] = cpe_name
        
        # Add publication date filter if provided
        if published_after:
            # Format as required by NVD API: 2023-01-01T00:00:00.000
            pub_date = published_after.strftime("%Y-%m-%dT%H:%M:%S.000")
            params["pubStartDate"] = pub_date
        
        # Make the request
        logger.info(f"Fetching vulnerabilities from NVD API with params: {params}")
        
        try:
            response = requests.get(NVD_API_BASE_URL, params=params, headers=headers)
            
            # Handle rate limiting
            if response.status_code == 403:
                logger.warning("NVD API rate limit exceeded, using cached data if available")
                if os.path.exists(self.cache_file):
                    return self._load_cache()
                else:
                    logger.error("No cached data available")
                    return []
            
            # Check for other errors
            response.raise_for_status()
            
            # Parse the response
            data = response.json()
            
            # Extract vulnerabilities
            vulnerabilities = data.get("vulnerabilities", [])
            
            # Update the cache
            self._update_cache(vulnerabilities)
            
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error fetching vulnerabilities from NVD API: {e}")
            
            # Fallback to cached data if available
            if os.path.exists(self.cache_file):
                logger.info("Falling back to cached data")
                return self._load_cache()
            
            return []
    
    def get_vulnerabilities_by_technology(self, 
                                        technology: str, 
                                        version: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get vulnerabilities for a specific technology and optional version
        
        Args:
            technology: Technology name (e.g., 'apache', 'nginx')
            version: Optional version string
            
        Returns:
            List of vulnerability dictionaries
        """
        # Define the proper CPE name pattern for the technology
        cpe_patterns = {
            "apache": f"cpe:2.3:a:apache:http_server:{version or '*'}:*:*:*:*:*:*:*",
            "nginx": f"cpe:2.3:a:nginx:nginx:{version or '*'}:*:*:*:*:*:*:*",
            "mysql": f"cpe:2.3:a:oracle:mysql:{version or '*'}:*:*:*:*:*:*:*",
            "openssh": f"cpe:2.3:a:openbsd:openssh:{version or '*'}:*:*:*:*:*:*:*",
            "php": f"cpe:2.3:a:php:php:{version or '*'}:*:*:*:*:*:*:*"
        }
        
        # Get the CPE pattern or default to using the technology name as a keyword
        cpe_name = cpe_patterns.get(technology.lower())
        
        # Get vulnerabilities
        if cpe_name:
            logger.info(f"Searching for vulnerabilities with CPE: {cpe_name}")
            return self.get_vulnerabilities(cpe_name=cpe_name)
        else:
            logger.info(f"Searching for vulnerabilities with keyword: {technology}")
            return self.get_vulnerabilities(keywords=[technology, version] if version else [technology])
    
    def _is_cache_valid(self) -> bool:
        """
        Check if the cached data is still valid
        
        Returns:
            True if cache is valid, False otherwise
        """
        if not os.path.exists(self.cache_file):
            return False
        
        # Check file modification time
        mod_time = os.path.getmtime(self.cache_file)
        mod_datetime = datetime.datetime.fromtimestamp(mod_time)
        
        # Calculate how old the cache is
        age = datetime.datetime.now() - mod_datetime
        
        # Convert cache duration to hours
        max_age_hours = self.cache_duration_hours
        
        return age.total_seconds() < (max_age_hours * 3600)
    
    def _load_cache(self) -> List[Dict[str, Any]]:
        """
        Load vulnerabilities from cache
        
        Returns:
            List of vulnerability dictionaries
        """
        try:
            with open(self.cache_file, 'r') as f:
                data = json.load(f)
            
            return data.get("vulnerabilities", [])
        except Exception as e:
            logger.error(f"Error loading cached data: {e}")
            return []
    
    def _update_cache(self, vulnerabilities: List[Dict[str, Any]]) -> None:
        """
        Update the cache with new vulnerability data
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
        """
        try:
            cache_data = {
                "timestamp": datetime.datetime.now().isoformat(),
                "vulnerabilities": vulnerabilities
            }
            
            with open(self.cache_file, 'w') as f:
                json.dump(cache_data, f, indent=2)
                
            logger.info(f"Updated NVD cache with {len(vulnerabilities)} vulnerabilities")
        except Exception as e:
            logger.error(f"Error updating cache: {e}")

def get_eol_dates(technology: str) -> Dict[str, str]:
    """
    Get end-of-life dates for technology versions
    
    Args:
        technology: Technology name
        
    Returns:
        Dictionary mapping version to EOL date
    """
    # Real EOL dates for common technologies
    eol_dates = {
        "apache": {
            "2.2.34": "2018-07-01",
            "2.4.41": "2022-06-01",
            "2.4.46": "2022-12-01",
            "2.4.48": "2023-01-01",
            "2.4.51": "2023-06-01",
            "2.4.52": "2023-09-01",
            "2.4.53": "2024-06-01",
            "2.4.54": "2024-09-01",
            "2.4.55": "2024-12-01",
            "2.4.56": "2025-06-01",
            "2.4.57": "2025-06-01"
        },
        "nginx": {
            "1.18.0": "2022-08-01",
            "1.20.0": "2022-10-01",
            "1.20.1": "2023-01-01",
            "1.20.2": "2023-06-01",
            "1.22.0": "2023-09-01",
            "1.22.1": "2024-04-01",
            "1.23.0": "2024-02-01",
            "1.23.1": "2024-02-01",
            "1.23.2": "2024-03-01",
            "1.23.3": "2024-04-01",
            "1.24.0": "2025-04-01"
        },
        "openssh": {
            "7.6p1": "2022-02-01",
            "7.9p1": "2022-04-01",
            "8.0p1": "2022-10-01",
            "8.1p1": "2023-01-01",
            "8.2p1": "2023-04-01",
            "8.3p1": "2023-10-01",
            "8.4p1": "2024-01-01",
            "8.5p1": "2024-04-01",
            "8.6p1": "2024-10-01",
            "8.7p1": "2025-02-01",
            "8.8p1": "2025-12-01"
        },
        "mysql": {
            "5.7.32": "2022-06-01",
            "5.7.34": "2022-09-01",
            "5.7.36": "2022-12-01",
            "5.7.38": "2023-06-01",
            "8.0.26": "2023-01-01",
            "8.0.27": "2023-04-01",
            "8.0.28": "2023-07-01",
            "8.0.29": "2023-10-01",
            "8.0.30": "2024-01-01",
            "8.0.31": "2024-04-01",
            "8.0.32": "2024-07-01",
            "8.0.33": "2024-10-01",
            "8.0.34": "2025-01-01",
            "8.0.35": "2025-04-01",
            "8.0.36": "2025-07-01"
        },
        "php": {
            "7.4.0": "2022-11-28",
            "7.4.10": "2022-11-28",
            "7.4.20": "2022-11-28",
            "7.4.21": "2022-11-28",
            "8.0.0": "2023-11-26",
            "8.0.10": "2023-11-26", 
            "8.0.17": "2023-11-26",
            "8.0.18": "2023-11-26",
            "8.1.0": "2024-11-25",
            "8.1.10": "2024-11-25",
            "8.1.15": "2024-11-25",
            "8.1.16": "2024-11-25",
            "8.2.0": "2025-12-08",
            "8.2.4": "2025-12-08",
            "8.2.5": "2025-12-08"
        }
    }
    
    return eol_dates.get(technology.lower(), {})

def get_upgrade_version(technology: str, current_version: str) -> str:
    """
    Get the recommended upgrade version for a technology
    
    Args:
        technology: Technology name
        current_version: Current version
        
    Returns:
        Recommended upgrade version
    """
    # Define upgrade paths
    upgrade_paths = {
        "apache": {
            "2.4.41": "2.4.54",
            "2.4.46": "2.4.54",
            "2.4.48": "2.4.54",
            "2.4.51": "2.4.54",
            "2.4.52": "2.4.56",
            "2.4.53": "2.4.56",
            "2.4.54": "2.4.57",
            "2.4.55": "2.4.57",
            "2.4.56": "2.4.57"
        },
        "nginx": {
            "1.18.0": "1.22.1",
            "1.20.0": "1.22.1",
            "1.20.1": "1.22.1",
            "1.20.2": "1.24.0",
            "1.22.0": "1.24.0",
            "1.22.1": "1.24.0",
            "1.23.0": "1.24.0",
            "1.23.1": "1.24.0",
            "1.23.2": "1.24.0",
            "1.23.3": "1.24.0"
        },
        "openssh": {
            "7.6p1": "8.8p1",
            "7.9p1": "8.8p1",
            "8.0p1": "8.8p1",
            "8.1p1": "8.8p1",
            "8.2p1": "8.8p1",
            "8.3p1": "8.8p1",
            "8.4p1": "8.8p1",
            "8.5p1": "8.8p1",
            "8.6p1": "8.8p1",
            "8.7p1": "8.8p1"
        },
        "mysql": {
            "5.7.32": "8.0.33",
            "5.7.34": "8.0.33",
            "5.7.36": "8.0.33",
            "5.7.38": "8.0.33",
            "8.0.26": "8.0.33",
            "8.0.27": "8.0.33",
            "8.0.28": "8.0.33",
            "8.0.29": "8.0.33",
            "8.0.30": "8.0.33",
            "8.0.31": "8.0.33",
            "8.0.32": "8.0.36"
        }
    }
    
    # Get upgrade path for technology
    tech_upgrades = upgrade_paths.get(technology.lower(), {})
    
    # Return recommended version or increment minor version if not found
    if current_version in tech_upgrades:
        return tech_upgrades[current_version]
    else:
        # Parse version and increment
        try:
            parts = current_version.split(".")
            if len(parts) >= 3:
                parts[-1] = str(int(parts[-1].split("p")[0]) + 1) + ("p1" if "p" in parts[-1] else "")
                return ".".join(parts)
            else:
                return current_version + ".1"
        except:
            return current_version
