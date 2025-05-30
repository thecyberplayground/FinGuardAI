"""
FinGuardAI - Detailed Financial Sector Analysis for portal.lcu.edu.ng

This script provides a detailed security analysis of portal.lcu.edu.ng
with financial-specific remediation recommendations.
"""

import os
import sys
import json
import logging
from typing import Dict, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('portal_lcu_analysis.log')
    ]
)
logger = logging.getLogger('finguardai.analysis')

# Add the backend directory to the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import scan processor module
try:
    from ml.remediation.scan_processor import process_scan_file, get_recommendations_from_scan
    HAS_MODULES = True
except ImportError as e:
    logger.error(f"Error importing required modules: {e}")
    HAS_MODULES = False

def analyze_portal_lcu():
    """Analyze portal.lcu.edu.ng with financial-specific remediations"""
    logger.info("=" * 80)
    logger.info(f"FinGuardAI - Financial Security Analysis for portal.lcu.edu.ng".center(80))
    logger.info("=" * 80)
    
    # Path to scan file
    scan_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'nmap_portal.lcu.edu.ng.txt')
    
    if not os.path.exists(scan_file):
        logger.error(f"Scan file not found: {scan_file}")
        return
    
    # Process the scan file
    logger.info(f"Processing scan file: {scan_file}")
    results = process_scan_file(scan_file)
    
    if "error" in results:
        logger.error(f"Error processing file: {results['error']}")
        return
    
    # Display basic scan information
    logger.info("\n🔍 SCAN SUMMARY")
    logger.info(f"Target: {results['scan_analysis'].get('host', 'Unknown')}")
    logger.info(f"OS: {results['scan_analysis'].get('os', 'Unknown')}")
    logger.info(f"Financial Risk Level: {results['scan_analysis'].get('financial_risk_level', 'Unknown')}")
    logger.info(f"Open Ports: {len(results['scan_analysis'].get('open_ports', []))}")
    
    # Display financial services
    if results['scan_analysis'].get('financial_services'):
        logger.info("\n💰 FINANCIAL SERVICES IDENTIFIED")
        for service in results['scan_analysis']['financial_services']:
            logger.info(f"  - Port {service['port']}/{service['service']}: {service['description']}")
            logger.info(f"    Financial Impact: {service['impact']}")
    else:
        logger.info("\n💰 FINANCIAL SERVICES IDENTIFIED: None")
    
    # Display vulnerabilities
    vulnerabilities = results['scan_analysis'].get('vulnerabilities', [])
    logger.info(f"\n⚠️ VULNERABILITIES DETECTED: {len(vulnerabilities)}")
    if vulnerabilities:
        for i, vuln in enumerate(vulnerabilities, 1):
            logger.info(f"  {i}. {vuln['description']} (Severity: {vuln['severity'].upper()})")
            
            for key, value in vuln.items():
                if key not in ['description', 'severity']:
                    logger.info(f"     - {key}: {value}")
    else:
        logger.info("  No specific vulnerabilities detected in the scan")
    
    # Display financial threat types
    fin_threat_types = results['recommendations'].get('financial_threat_types', [])
    if fin_threat_types:
        logger.info("\n🏦 FINANCIAL THREAT TYPES")
        for threat_type in fin_threat_types:
            logger.info(f"  - {threat_type}")
    
    # Display financial technical controls
    fin_controls = results['recommendations'].get('financial_technical_controls', [])
    if fin_controls:
        logger.info("\n🛡️ FINANCIAL TECHNICAL CONTROLS")
        for i, control in enumerate(fin_controls, 1):
            logger.info(f"  {i}. {control}")
    
    # Display general recommendations
    gen_recs = results['recommendations'].get('general_recommendations', [])
    if gen_recs:
        logger.info("\n📋 GENERAL RECOMMENDATIONS")
        for i, rec in enumerate(gen_recs, 1):
            logger.info(f"  {i}. {rec}")
    
    # Display regulations
    regulations = results['recommendations'].get('regulations', [])
    if regulations:
        logger.info("\n📜 REGULATORY COMPLIANCE")
        for reg in regulations:
            logger.info(f"  - {reg}")
    
    # Financial exposure assessment
    logger.info("\n🔒 FINANCIAL EXPOSURE ASSESSMENT")
    
    # Analyze open ports for financial implications
    financial_ports = [p for p in results['scan_analysis'].get('open_ports', []) 
                      if p.get('financial_relevant', False)]
    
    if financial_ports:
        logger.info("  Financial Service Exposure:")
        for port in financial_ports:
            service_name = port.get('service', 'unknown')
            port_num = port.get('port', 0)
            logger.info(f"  - Port {port_num}/{service_name}: {FINANCIAL_PORTS.get(port_num, {}).get('description', 'Unknown service')}")
            
            # Specific recommendations based on service
            if service_name == 'http':
                logger.info("    Recommendation: Switch to HTTPS with valid certificates and HSTS")
            elif service_name == 'ftp':
                logger.info("    Recommendation: Replace FTP with SFTP or FTPS for secure financial data transfer")
            elif service_name == 'ssh':
                logger.info("    Recommendation: Implement key-based authentication and disable password login")
    
    # Overall security posture
    logger.info("\n📊 OVERALL SECURITY POSTURE")
    logger.info(f"  Financial Security Risk Level: {results['recommendations'].get('severity', 'Unknown').upper()}")
    
    # Custom recommendations for educational institution with financial services
    logger.info("\n🎓 SPECIFIC RECOMMENDATIONS FOR EDUCATIONAL PORTAL")
    logger.info("  1. Implement separate network segments for financial data (student payments, scholarships)")
    logger.info("  2. Use dedicated payment processors rather than handling financial data directly")
    logger.info("  3. Ensure compliance with educational sector financial regulations")
    logger.info("  4. Implement strong session management for portal access")
    logger.info("  5. Deploy data loss prevention tools focused on student financial records")
    
    logger.info("\n" + "=" * 80)

# Financial ports definitions (simplified version)
FINANCIAL_PORTS = {
    21: {"service": "ftp", "description": "FTP - Potential financial data transfer risk"},
    22: {"service": "ssh", "description": "SSH - Admin access to financial systems"},
    80: {"service": "http", "description": "HTTP - Unencrypted web portal (payment risks)"},
    443: {"service": "https", "description": "HTTPS - Secure web portal (payment gateway)"}
}

if __name__ == "__main__":
    if not HAS_MODULES:
        print("ERROR: Required modules not available")
        sys.exit(1)
    
    analyze_portal_lcu()
