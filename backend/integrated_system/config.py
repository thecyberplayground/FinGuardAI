"""
FinGuardAI - Integrated System Configuration

This module contains configuration settings for the integrated vulnerability analysis system.
"""

import os
import logging
from typing import Dict, Any

# Base directories
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE_DIR = os.path.join(BASE_DIR, "cache")
LOG_DIR = os.path.join(BASE_DIR, "logs")
OUTPUT_DIR = os.path.join(BASE_DIR, "reports")

# Ensure directories exist
for directory in [CACHE_DIR, LOG_DIR, OUTPUT_DIR]:
    os.makedirs(directory, exist_ok=True)

# NVD API settings
NVD_API_KEY = os.environ.get("NVD_API_KEY", "7a30b327-dc77-4262-acc6-399171f7dacb")
NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CACHE_TTL = 24 * 60 * 60  # 24 hours in seconds

# Logging configuration
LOG_FILE = os.path.join(LOG_DIR, "integrated_analyzer.log")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("finguardai.integrated")

# Known technology mappings for specific targets
TECHNOLOGY_MAPPINGS = {
    "stampduty.gov.ng": {
        "apache": "2.4.51",
        "php": "7.4.21",
        "mysql": "5.7.36",
        "openssh": "8.2p1"
    },
    "portal.lcu.edu.ng": {
        "nginx": "1.20.1",
        "php": "8.0.10"
    },
    "tryhackme.com": {
        "nginx": "1.18.0",
        "php": "7.4.3"
    }
}

# Scan parameters
DEFAULT_SCAN_PARAMS = {
    "ports": "21,22,25,53,80,443,3306,8080",
    "scan_speed": "normal",
    "service_detection": True,
    "os_detection": True
}

# Analysis parameters
DEFAULT_ANALYSIS_PARAMS = {
    "nvd_max_results": 50,
    "min_cvss_score": 7.0,
    "check_exploits": True,
    "timeframes": ["1_day", "1_week", "10_days"],
    "include_trends": True
}

# Financial sector specific settings
FINANCIAL_REGULATORY_FRAMEWORKS = [
    "PCI DSS",
    "SOX",
    "GDPR",
    "GLBA",
    "Basel III"
]
