"""
FinGuardAI - Predictive Vulnerability Analysis Test

This script tests the predictive vulnerability analysis system on existing scan data,
demonstrating how to identify future potential security issues based on current infrastructure.
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
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger('finguardai.test')

# Add the backend directory to the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import modules
try:
    from ml.remediation.scan_processor import parse_nmap_scan, process_scan_file
    from ml.remediation.predictive_vulnerabilities import get_predictive_analysis, extract_technologies
    HAS_MODULES = True
except ImportError as e:
    logger.error(f"Error importing required modules: {e}")
    HAS_MODULES = False

def print_section_header(title):
    """Print a section header for better readability"""
    width = 80
    print("\n" + "="*width)
    print(title.center(width))
    print("="*width + "\n")

def load_scan_file(file_path):
    """Load and parse an Nmap scan file"""
    try:
        with open(file_path, 'r') as f:
            scan_data = f.read()
        return parse_nmap_scan(scan_data)
    except Exception as e:
        logger.error(f"Error loading scan file: {e}")
        return None

def test_predictive_analysis(scan_file_path):
    """Test the predictive vulnerability analysis on a specific scan file"""
    print_section_header(f"Predictive Vulnerability Analysis for {os.path.basename(scan_file_path)}")
    
    # Load and parse the scan data
    scan_results = load_scan_file(scan_file_path)
    if not scan_results:
        return
    
    print(f"Target: {scan_results.get('host', 'Unknown')}")
    print(f"Detected ports: {len(scan_results.get('open_ports', []))}")
    
    # Extract technologies
    technologies = extract_technologies(scan_results)
    print("\n[+] Detected Technology Stack:")
    for tech in sorted(technologies):
        print(f"  - {tech}")
    
    # Get predictive analysis
    print("\n[+] Running Predictive Vulnerability Analysis...")
    predictive_results = get_predictive_analysis(scan_results)
    
    # Display prediction summary
    print(f"\nTotal Predictions: {predictive_results['total_predictions']}")
    print(f"Short-term Predictions: {predictive_results['predictions_by_timeframe']['short_term']}")
    print(f"Medium-term Predictions: {predictive_results['predictions_by_timeframe']['medium_term']}")
    print(f"Long-term Predictions: {predictive_results['predictions_by_timeframe']['long_term']}")
    
    # Show regulatory impact
    print("\n[+] Regulatory Impact of Predicted Vulnerabilities:")
    for reg, count in predictive_results.get('vulnerability_counts_by_regulation', {}).items():
        print(f"  - {reg}: {count} potential vulnerabilities")
    
    # Display predicted vulnerabilities by timeframe
    print("\n[+] SHORT-TERM Predicted Vulnerabilities:")
    for i, vuln in enumerate(predictive_results['grouped_vulnerabilities'].get('short_term', []), 1):
        print(f"\n  {i}. {vuln['name']} (ID: {vuln['id']})")
        print(f"     Confidence: {vuln['confidence']:.2f}")
        print(f"     Timeline: {vuln['time_window']}")
        print(f"     Description: {vuln['description']}")
        print(f"     Financial Impact: {vuln['financial_impact']}")
        print(f"     Mitigation: {vuln['mitigation']}")
    
    if not predictive_results['grouped_vulnerabilities'].get('short_term'):
        print("  No short-term vulnerabilities predicted")
    
    print("\n[+] MEDIUM-TERM Predicted Vulnerabilities:")
    for i, vuln in enumerate(predictive_results['grouped_vulnerabilities'].get('medium_term', []), 1):
        print(f"\n  {i}. {vuln['name']} (ID: {vuln['id']})")
        print(f"     Confidence: {vuln['confidence']:.2f}")
        print(f"     Timeline: {vuln['time_window']}")
        print(f"     Description: {vuln['description']}")
        print(f"     Financial Impact: {vuln['financial_impact']}")
    
    if not predictive_results['grouped_vulnerabilities'].get('medium_term'):
        print("  No medium-term vulnerabilities predicted")
    
    print("\n[+] Proactive Security Recommendations:")
    
    # Generate recommendations based on predicted vulnerabilities
    all_mitigations = set()
    for vuln in predictive_results.get('predicted_vulnerabilities', []):
        if vuln.get('mitigation'):
            all_mitigations.add(vuln.get('mitigation'))
    
    # Output unique mitigations
    for i, mitigation in enumerate(all_mitigations, 1):
        print(f"  {i}. {mitigation}")
    
    print("\n[+] Financial Security Roadmap:")
    print("  1. Immediate: Address any high-confidence, short-term predictions")
    print("  2. 3-Month: Implement mitigations for medium-term vulnerabilities")
    print("  3. 6-Month: Begin architectural improvements for long-term security")
    print("  4. Ongoing: Monitor emerging financial sector vulnerabilities")

def main():
    """Main function to test predictive vulnerability analysis"""
    if not HAS_MODULES:
        print("Error: Required modules not available.")
        return
    
    print("FinGuardAI - Predictive Vulnerability Analysis Test")
    print("==================================================")
    
    # Test with portal.lcu.edu.ng
    scan_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'nmap_portal.lcu.edu.ng.txt')
    if os.path.exists(scan_path):
        test_predictive_analysis(scan_path)
    else:
        print(f"Scan file not found: {scan_path}")
        # List available scan files
        scan_files = [f for f in os.listdir(os.path.dirname(os.path.abspath(__file__))) 
                     if f.startswith('nmap_') and f.endswith('.txt')]
        
        if scan_files:
            print("\nAvailable scan files:")
            for i, file in enumerate(scan_files, 1):
                print(f"  {i}. {file}")
            
            # Try first available scan file
            first_scan = os.path.join(os.path.dirname(os.path.abspath(__file__)), scan_files[0])
            print(f"\nUsing first available scan file: {scan_files[0]}")
            test_predictive_analysis(first_scan)
        else:
            print("No scan files available.")

if __name__ == "__main__":
    main()
