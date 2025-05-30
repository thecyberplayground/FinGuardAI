"""
FinGuardAI - Real-Time Vulnerability Prediction with Precise Timeframes

This script uses real NVD data to analyze and predict vulnerabilities with precise timeframes:
- 1-day (immediate action required)
- 1-week (urgent action required)
- 10-day (important action required)

Each prediction includes technology-specific upgrade recommendations and real CVE references.
"""

import os
import sys
import json
import datetime
import logging

# Add the backend directory to the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("finguardai.predictor")

# Import the required modules
try:
    from ml.remediation.scan_processor import parse_nmap_scan
    from ml.remediation.predictive_vulnerabilities import extract_technologies
    from ml.remediation.real_timeframe_predictor import generate_real_predictions
except ImportError as e:
    logger.error(f"Error importing modules: {e}")
    sys.exit(1)

def analyze_scan_file(file_path, api_key=None):
    """
    Analyze a scan file and generate real vulnerability predictions
    
    Args:
        file_path: Path to Nmap scan file
        api_key: Optional NVD API key
    """
    print(f"\nAnalyzing scan file: {os.path.basename(file_path)}")
    print("-" * 60)
    
    try:
        # Read the scan data
        with open(file_path, 'r') as f:
            scan_data = f.read()
        
        # Parse the scan
        scan_results = parse_nmap_scan(scan_data)
        
        print(f"Target: {scan_results.get('host', 'Unknown')}")
        print(f"Open Ports: {len(scan_results.get('open_ports', []))}")
        
        # Extract technologies
        technologies = extract_technologies(scan_results)
        print("\nDetected Technology Stack:")
        for tech in sorted(technologies):
            print(f"  - {tech}")
        
        # Run real-time prediction analysis
        print("\nRunning Real-Time Vulnerability Analysis...")
        print("Fetching real vulnerability data from NVD...")
        
        # Generate real predictions with specific timeframes
        predictions = generate_real_predictions(scan_results, api_key=api_key)
        
        # Print prediction summary
        print("\n=== REAL-TIME VULNERABILITY PREDICTIONS ===")
        print("Predicted Vulnerabilities by Timeframe:")
        print(f"  - 1-Day Required Actions: {predictions['summary']['1_day_count']}")
        print(f"  - 1-Week Required Actions: {predictions['summary']['1_week_count']}")
        print(f"  - 10-Days Required Actions: {predictions['summary']['10_days_count']}")
        print(f"  - Total Technology-Specific Upgrades: {predictions['summary']['tech_specific_count']}")
        
        # Print 1-day vulnerabilities (highest priority)
        if predictions['1_day']:
            print("\n[CRITICAL - IMMEDIATE ACTION REQUIRED]")
            print("The following vulnerabilities require action within 24 hours:")
            for i, vuln in enumerate(predictions['1_day'], 1):
                print(f"\n  {i}. {vuln['technology']} {vuln['current_version']} → {vuln['recommended_version']}")
                print(f"     Confidence: {vuln['prediction_confidence']:.2f}")
                print(f"     Vulnerability Types: {', '.join(vuln['vulnerability_types'][:3])}")
                print(f"     Recommendation: {vuln['detailed_recommendation']}")
                if vuln['affected_cves']:
                    print(f"     Related CVEs: {', '.join(vuln['affected_cves'])}")
        
        # Print 1-week vulnerabilities
        if predictions['1_week']:
            print("\n[URGENT - ACTION REQUIRED WITHIN ONE WEEK]")
            print("The following vulnerabilities require action within 7 days:")
            for i, vuln in enumerate(predictions['1_week'], 1):
                print(f"\n  {i}. {vuln['technology']} {vuln['current_version']} → {vuln['recommended_version']}")
                print(f"     Confidence: {vuln['prediction_confidence']:.2f}")
                print(f"     Vulnerability Types: {', '.join(vuln['vulnerability_types'][:3])}")
                print(f"     Recommendation: {vuln['detailed_recommendation']}")
                if vuln['affected_cves']:
                    print(f"     Related CVEs: {', '.join(vuln['affected_cves'])}")
        
        # Print 10-day vulnerabilities
        if predictions['10_days']:
            print("\n[IMPORTANT - ACTION REQUIRED WITHIN 10 DAYS]")
            print("The following vulnerabilities require action within 10 days:")
            for i, vuln in enumerate(predictions['10_days'], 1):
                print(f"\n  {i}. {vuln['technology']} {vuln['current_version']} → {vuln['recommended_version']}")
                print(f"     Confidence: {vuln['prediction_confidence']:.2f}")
                print(f"     Vulnerability Types: {', '.join(vuln['vulnerability_types'][:3])}")
                print(f"     Recommendation: {vuln['detailed_recommendation']}")
                if vuln['affected_cves']:
                    print(f"     Related CVEs: {', '.join(vuln['affected_cves'])}")
        
        # Print summary
        print(f"\nAnalysis completed: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        return True
    
    except Exception as e:
        logger.error(f"Error analyzing scan file: {e}")
        return False

def main():
    """
    Main function to run the real-time vulnerability analysis
    """
    print("FinGuardAI - Real-Time Vulnerability Prediction")
    print("=" * 50)
    
    # Check if NVD API key was provided
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        print("Using NVD API key for higher rate limits")
    else:
        print("No NVD API key found. Using public API (rate limited)")
    
    # Define scan files to analyze in order of priority
    target_scans = [
        'nmap_stampduty.gov.ng.txt',  # Financial government site
        'nmap_portal.lcu.edu.ng.txt',  # Educational portal
        'nmap_tryhackme.com.txt',      # Security training site
    ]
    
    # Collect available scan files
    scan_files = []
    for target in target_scans:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), target)
        if os.path.exists(path):
            scan_files.append(path)
    
    # If none of our priority targets exist, look for any scan files
    if not scan_files:
        for file in os.listdir(os.path.dirname(os.path.abspath(__file__))):
            if file.startswith('nmap_') and file.endswith('.txt'):
                scan_files.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), file))
    
    if not scan_files:
        print("No scan files found.")
        return
    
    # Analyze each scan file
    for scan_file in scan_files:
        success = analyze_scan_file(scan_file, api_key=api_key)
        
        if success:
            print("\nAnalysis complete.")
            break

if __name__ == "__main__":
    main()
