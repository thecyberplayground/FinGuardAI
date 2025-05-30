"""
FinGuardAI - Scan-to-Remediation Test Script

This script demonstrates how scan data from a target is processed 
and converted into financial-specific remediation recommendations.
"""

import os
import sys
import json
import logging
from typing import Dict, Any
import time

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('finguardai.test')

# Add the backend directory to the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import the scan processor module
try:
    from ml.remediation.scan_processor import get_recommendations_from_scan, process_scan_file
    HAS_MODULES = True
except ImportError as e:
    logger.error(f"Error importing required modules: {e}")
    HAS_MODULES = False

def print_section_header(title):
    """Print a section header for better readability"""
    width = 80
    logger.info("\n" + "="*width)
    logger.info(title.center(width))
    logger.info("="*width + "\n")

def test_with_sample_scan():
    """Test with a sample scan string"""
    print_section_header("Testing with Sample Scan Data")
    
    # Sample Nmap scan output for a financial institution
    sample_scan = """
Nmap scan report for banking.example.com (203.0.113.42)
Host is up (0.054s latency).
Not shown: 992 filtered ports
PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH 7.6p1 (protocol 2.0)
| ssh-hostkey: 
|   2048 2a:8d:53:d3:10:6f:33:f9:09:f3:5d:cc:0f:19:10:67 (RSA)
|_  256 ef:28:1f:2b:4e:9f:77:46:4a:d7:42:a1:fe:e2:57:61 (ECDSA)
25/tcp   open  smtp          Postfix smtpd
|_ssl-date: TLS randomness does not represent time
80/tcp   open  http          Apache httpd 2.4.29
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Banking Portal Login
443/tcp  open  https         Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Banking Portal Login
| ssl-cert: Subject: commonName=banking.example.com
| Not valid before: 2022-01-01T00:00:00
|_Not valid after:  2023-01-01T00:00:00
| ssl-cert: Subject: commonName=banking.example.com
| Not valid before: 2022-01-01T00:00:00
|_Not valid after:  2023-01-01T00:00:00
|_ssl-date: TLS randomness does not represent time
| ssl-enum-ciphers: 
|   TLSv1.0: 
|     ciphers: 
|       TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (secp256r1) - A
|       TLS_RSA_WITH_AES_256_CBC_SHA (rsa 2048) - A
|       TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (secp256r1) - A
|       TLS_RSA_WITH_AES_128_CBC_SHA (rsa 2048) - A
|     compressors: 
|       NULL
|_  least strength: A
1433/tcp open  ms-sql-s      Microsoft SQL Server 2016 13.00.1601.00
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2020-01-01T00:00:00
|_Not valid after:  2025-01-01T00:00:00
|_ssl-date: TLS randomness does not represent time
3306/tcp open  mysql         MySQL 5.7.36-0ubuntu0.18.04.1
| mysql-info: 
|   Protocol: 10
|   Version: 5.7.36-0ubuntu0.18.04.1
|   Thread ID: 10
|_  Service: MySQL
8080/tcp open  http-proxy    nginx 1.18.0
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: nginx/1.18.0
|_http-title: Payment Gateway API
8443/tcp open  https-alt     nginx 1.18.0
| http-auth: 
|_  ERROR: Could not negotiate a supported auth mechanism with the server
|_http-server-header: nginx/1.18.0
|_http-title: Payment Processing Backend
| ssl-cert: Subject: commonName=api.banking.example.com
| Not valid before: 2022-01-01T00:00:00
|_Not valid after:  2023-01-01T00:00:00
|_ssl-date: TLS randomness does not represent time
| vulners: 
|   nginx 1.18.0: 
|     	CVE-2021-23017	7.5	https://vulners.com/cve/CVE-2021-23017
OS details: Ubuntu 18.04 (Linux 4.15)
    """
    
    # Process the sample scan data
    logger.info("Processing sample scan data...")
    results = get_recommendations_from_scan(sample_scan)
    
    # Display results
    logger.info(f"Target: {results['scan_analysis'].get('host', 'Unknown')}")
    logger.info(f"OS: {results['scan_analysis'].get('os', 'Unknown')}")
    logger.info(f"Financial Risk Level: {results['scan_analysis'].get('financial_risk_level', 'Unknown')}")
    
    # Display financial services found
    if results['scan_analysis'].get('financial_services'):
        logger.info("\nFinancial Services Identified:")
        for service in results['scan_analysis']['financial_services']:
            logger.info(f"  - Port {service['port']}/{service['service']}: {service['description']}")
            logger.info(f"    Financial Impact: {service['impact']}")
    
    # Display vulnerabilities found
    if results['scan_analysis'].get('vulnerabilities'):
        logger.info("\nVulnerabilities Identified:")
        for i, vuln in enumerate(results['scan_analysis']['vulnerabilities'], 1):
            logger.info(f"  {i}. {vuln['description']} (Severity: {vuln['severity']})")
            if 'evidence' in vuln:
                logger.info(f"     Evidence: {vuln['evidence']}")
    
    # Display recommendations
    logger.info("\nFinancial-Specific Recommendations:")
    logger.info(f"Overall Severity: {results['recommendations']['severity']}")
    
    logger.info("\nFinancial Threat Types:")
    for threat_type in results['recommendations']['financial_threat_types']:
        logger.info(f"  - {threat_type}")
    
    if results['recommendations'].get('financial_technical_controls'):
        logger.info("\nFinancial Technical Controls:")
        for i, control in enumerate(results['recommendations']['financial_technical_controls'], 1):
            logger.info(f"  {i}. {control}")
    
    if results['recommendations'].get('regulations'):
        logger.info("\nRegulatory Compliance:")
        for regulation in results['recommendations']['regulations']:
            logger.info(f"  - {regulation}")

def test_with_real_scan_files():
    """Test with actual Nmap scan files from the system"""
    print_section_header("Testing with Real Scan Files")
    
    # Look for Nmap scan files in the backend directory
    nmap_files = []
    backend_dir = os.path.dirname(os.path.abspath(__file__))
    
    for file in os.listdir(backend_dir):
        if file.startswith("nmap_") and file.endswith(".txt"):
            nmap_files.append(os.path.join(backend_dir, file))
    
    if not nmap_files:
        logger.info("No real Nmap scan files found in the backend directory.")
        return
    
    for nmap_file in nmap_files:
        logger.info(f"\nProcessing scan file: {os.path.basename(nmap_file)}")
        
        # Process the scan file
        results = process_scan_file(nmap_file)
        
        if "error" in results:
            logger.error(f"Error processing file: {results['error']}")
            continue
        
        # Display results
        logger.info(f"Target: {results['scan_analysis'].get('host', 'Unknown')}")
        logger.info(f"Financial Risk Level: {results['scan_analysis'].get('financial_risk_level', 'Unknown')}")
        logger.info(f"Total Vulnerabilities: {results['recommendations'].get('total_vulnerabilities', 0)}")
        
        # Display top recommendations
        if results['recommendations'].get('financial_technical_controls'):
            logger.info("\nTop Financial Technical Controls:")
            for i, control in enumerate(results['recommendations']['financial_technical_controls'][:5], 1):
                logger.info(f"  {i}. {control}")
        
        # Small delay between processing files
        time.sleep(1)

def main():
    """Main test function"""
    if not HAS_MODULES:
        logger.error("Required modules not available. Exiting.")
        return
    
    logger.info("FinGuardAI - Scan-to-Remediation Pipeline Test")
    logger.info("==========================================")
    
    # Test with sample scan data
    test_with_sample_scan()
    
    # Test with real scan files if available
    test_with_real_scan_files()
    
    logger.info("\nAll tests completed.")

if __name__ == "__main__":
    main()
