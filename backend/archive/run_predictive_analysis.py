"""
FinGuardAI - Predictive Vulnerability Analysis for Financial Targets

This script analyzes an Nmap scan of portal.lcu.edu.ng and predicts potential
future vulnerabilities that might emerge based on the detected technology stack.
"""

import os
import sys
import json
import datetime

# Add the backend directory to the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import the required modules
try:
    from ml.remediation.scan_processor import parse_nmap_scan
    from ml.remediation.predictive_vulnerabilities import get_predictive_analysis, extract_technologies
    from ml.remediation.precise_timeframe_predictor import generate_precise_predictions
except ImportError as e:
    print(f"Error importing modules: {e}")
    sys.exit(1)

def analyze_scan_file(file_path):
    """Analyze a scan file and predict future vulnerabilities"""
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
        
        # Run precise timeframe prediction analysis first
        print("\nRunning Precise Timeframe Vulnerability Analysis...")
        precise_predictions = generate_precise_predictions(scan_results)
        
        # Print precise prediction summary
        print(f"\n=== PRECISE TIMEFRAME PREDICTIONS ===")
        print(f"Predicted Vulnerabilities by Timeframe:")
        print(f"  - 1-Day Required Actions: {precise_predictions['summary']['1_day_count']}")
        print(f"  - 1-Week Required Actions: {precise_predictions['summary']['1_week_count']}")
        print(f"  - 10-Days Required Actions: {precise_predictions['summary']['10_days_count']}")
        print(f"  - Total Technology-Specific Upgrades: {precise_predictions['summary']['tech_specific_count']}")
        
        # Print 1-day vulnerabilities (highest priority)
        if precise_predictions['1_day']:
            print("\n[CRITICAL - IMMEDIATE ACTION REQUIRED]")
            print("The following vulnerabilities require action within 24 hours:")
            for i, vuln in enumerate(precise_predictions['1_day'], 1):
                print(f"\n  {i}. {vuln['technology']} {vuln['current_version']} → {vuln['recommended_version']}")
                print(f"     Confidence: {vuln['prediction_confidence']:.2f}")
                print(f"     Vulnerability Types: {', '.join(vuln['vulnerability_types'][:3])}")
                print(f"     Recommendation: {vuln['detailed_recommendation']}")
                if vuln['affected_cves']:
                    print(f"     Related CVEs: {', '.join(vuln['affected_cves'])}")
        
        # Print 1-week vulnerabilities
        if precise_predictions['1_week']:
            print("\n[URGENT - ACTION REQUIRED WITHIN ONE WEEK]")
            print("The following vulnerabilities require action within 7 days:")
            for i, vuln in enumerate(precise_predictions['1_week'], 1):
                print(f"\n  {i}. {vuln['technology']} {vuln['current_version']} → {vuln['recommended_version']}")
                print(f"     Confidence: {vuln['prediction_confidence']:.2f}")
                print(f"     Vulnerability Types: {', '.join(vuln['vulnerability_types'][:3])}")
                print(f"     Recommendation: {vuln['detailed_recommendation']}")
                if vuln['affected_cves']:
                    print(f"     Related CVEs: {', '.join(vuln['affected_cves'])}")
        
        # Print 10-day vulnerabilities
        if precise_predictions['10_days']:
            print("\n[IMPORTANT - ACTION REQUIRED WITHIN 10 DAYS]")
            print("The following vulnerabilities require action within 10 days:")
            for i, vuln in enumerate(precise_predictions['10_days'], 1):
                print(f"\n  {i}. {vuln['technology']} {vuln['current_version']} → {vuln['recommended_version']}")
                print(f"     Confidence: {vuln['prediction_confidence']:.2f}")
                print(f"     Vulnerability Types: {', '.join(vuln['vulnerability_types'][:3])}")
                print(f"     Recommendation: {vuln['detailed_recommendation']}")
                if vuln['affected_cves']:
                    print(f"     Related CVEs: {', '.join(vuln['affected_cves'])}")
        
        # Now run traditional predictive analysis for longer-term predictions
        print("\n\n=== LONGER-TERM PREDICTIONS ===")
        print("Running Extended Predictive Vulnerability Analysis...")
        predictions = get_predictive_analysis(scan_results)
        
        # Print long-term prediction summary
        print(f"\nPredicted Future Vulnerabilities: {predictions['total_predictions']}")
        print(f"  - Short-term (0-3 months): {predictions['predictions_by_timeframe']['short_term']}")
        print(f"  - Medium-term (3-6 months): {predictions['predictions_by_timeframe']['medium_term']}")
        print(f"  - Long-term (6+ months): {predictions['predictions_by_timeframe']['long_term']}")
        
        # Print detailed predictions
        print("\nDetailed Vulnerability Predictions:")
        
        # Sort all predictions by confidence
        all_predictions = predictions['predicted_vulnerabilities']
        all_predictions.sort(key=lambda x: x.get('confidence', 0), reverse=True)
        
        for i, vuln in enumerate(all_predictions, 1):
            print(f"\n[{i}] {vuln['name']}")
            print(f"    ID: {vuln['id']}")
            print(f"    Confidence: {vuln['confidence']:.2f}")
            print(f"    Timeframe: {vuln['time_window']}")
            print(f"    Description: {vuln['description']}")
            print(f"    Financial Impact: {vuln['financial_impact']}")
            print(f"    Mitigation: {vuln['mitigation']}")
            print(f"    Regulatory Impact: {', '.join(vuln.get('regulatory_impact', []))}")
        
        # Print regulatory impact summary
        print("\nRegulatory Impact Summary:")
        for reg, count in predictions.get('vulnerability_counts_by_regulation', {}).items():
            print(f"  - {reg}: {count} potential vulnerabilities")
        
        # Print proactive recommendations
        print("\nProactive Security Recommendations:")
        seen_mitigations = set()
        for i, vuln in enumerate(all_predictions, 1):
            mitigation = vuln.get('mitigation', '')
            if mitigation and mitigation not in seen_mitigations:
                seen_mitigations.add(mitigation)
                print(f"  {i}. {mitigation}")
        
        # Print summary with timestamp
        print(f"\nAnalysis completed: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        return True
    except Exception as e:
        print(f"Error analyzing scan file: {e}")
        return False

def main():
    print("FinGuardAI - Predictive Vulnerability Analysis")
    print("=" * 50)
    
    # Define scan files to analyze in order of priority
    target_scans = [
        'nmap_stampduty.gov.ng.txt',  # Financial government site
        'nmap_portal.lcu.edu.ng.txt',  # Educational portal
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
        success = analyze_scan_file(scan_file)
        
        # If we successfully analyzed at least one scan file with predictions, we're done
        if success:
            print("\nAnalysis complete.")
            break

if __name__ == "__main__":
    main()
