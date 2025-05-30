"""
Integrated Vulnerability Analysis System for FinGuardAI

This module combines active scanning, passive monitoring, and NVD-powered vulnerability predictions
into a comprehensive analysis system that provides detailed vulnerability reports and
remediation recommendations.
"""

import os
import json
import logging
import datetime
import argparse
from typing import Dict, List, Any, Optional, Tuple, Union

from .config import DEFAULT_SCAN_PARAMS, DEFAULT_ANALYSIS_PARAMS, TECHNOLOGY_MAPPINGS, logger
from .active_scanner import ActiveScanner
from .passive_monitor import PassiveMonitor
from .nvd_integration import NVDIntegration
from .vulnerability_scanner import VulnerabilityScanner
from .vulnerability_predictor import get_vulnerability_predictions
from .enhanced_report import EnhancedReportGenerator

class IntegratedAnalyzer:
    """
    Integrated vulnerability analysis system that combines active scanning,
    passive monitoring, and NVD-powered predictions.
    """
    
    def __init__(self, output_dir: Optional[str] = None):
        """
        Initialize the integrated analyzer
        
        Args:
            output_dir: Directory to store analysis results
        """
        self.output_dir = output_dir or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
            "reports"
        )
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Initialize components
        self.active_scanner = ActiveScanner()
        self.passive_monitor = PassiveMonitor()
        self.nvd_integration = NVDIntegration()
        self.vulnerability_scanner = VulnerabilityScanner()
        self.report_generator = EnhancedReportGenerator(self.output_dir)
        
        self.logger = logging.getLogger("finguardai.integrated_analyzer")
    
    def analyze_target(self, target: str, scan_params: Optional[Dict[str, Any]] = None,
                      analysis_params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Perform comprehensive analysis on a target
        
        Args:
            target: Target to analyze (IP, hostname, or URL)
            scan_params: Optional scan parameters to override defaults
            analysis_params: Optional analysis parameters to override defaults
            
        Returns:
            Dictionary with analysis results
        """
        # Set default parameters
        scan_params = scan_params or DEFAULT_SCAN_PARAMS
        analysis_params = analysis_params or DEFAULT_ANALYSIS_PARAMS
        
        self.logger.info(f"Starting integrated analysis of {target}")
        
        # Step 1: Active scanning
        self.logger.info("Step 1: Performing active scanning")
        scan_results = self.active_scanner.scan_target(target, scan_params)
        active_techs = self.active_scanner.extract_technologies(scan_results)
        
        # Step 2: Passive monitoring
        self.logger.info("Step 2: Performing passive monitoring")
        passive_results = self.passive_monitor.monitor_target(target)
        passive_techs = self.passive_monitor.extract_technologies(passive_results)
        
        # Step 3: Comprehensive vulnerability scanning
        self.logger.info("Step 3: Performing comprehensive vulnerability scanning")
        ports = scan_params.get("ports", DEFAULT_SCAN_PARAMS["ports"])
        intensity = "normal"  # Default intensity
        
        # Map scan_speed to vulnerability scan intensity
        if "scan_speed" in scan_params:
            if scan_params["scan_speed"] == "fast": 
                intensity = "stealthy"  # Use less intensive scanning
            elif scan_params["scan_speed"] == "thorough":
                intensity = "aggressive"  # Use more intensive scanning
        
        vuln_scan_results = self.vulnerability_scanner.scan_target(target, ports, intensity)
        
        # Step 4: Combine technologies from all sources
        combined_techs = self._merge_technologies(active_techs, passive_techs)
        
        # Add technologies from vulnerability scan if available
        vuln_scan_techs = vuln_scan_results.get("technologies", [])
        if vuln_scan_techs:
            combined_techs = self._merge_technologies(combined_techs, vuln_scan_techs)
            
        self.logger.info(f"Combined {len(active_techs)} active, {len(passive_techs)} passive, and {len(vuln_scan_techs)} vuln scan technologies into {len(combined_techs)} unique technologies")
        
        # Step 5: Get vulnerabilities by timeframe
        self.logger.info("Step 5: Analyzing vulnerabilities by timeframe")
        timeframes = analysis_params.get("timeframes", ["1_day", "1_week", "10_days"])
        vulnerability_predictions = self.nvd_integration.get_vulnerabilities_by_timeframe(combined_techs, timeframes)
        
        # Step 5: Get remediation recommendations
        self.logger.info("Step 5: Generating remediation recommendations")
        remediation_recommendations = {}
        
        for tech in combined_techs:
            tech_name = tech["name"]
            tech_version = tech["version"]
            remediation_recommendations[f"{tech_name} {tech_version}"] = self.nvd_integration.get_remediation_recommendations(tech_name, tech_version)
        
        # Step 6: Check for exploitable vulnerabilities if requested
        exploit_analysis = None
        if analysis_params.get("check_exploits", True):
            self.logger.info("Step 6: Checking for exploitable vulnerabilities")
            exploited_vulns = {}
            
            for tech in combined_techs:
                tech_name = tech["name"]
                exploits = self.nvd_integration.advanced_search.search_exploited_vulnerabilities(tech_name)
                if exploits:
                    exploited_vulns[tech_name] = exploits
            
            if exploited_vulns:
                exploit_analysis = {
                    "exploitable_technologies": list(exploited_vulns.keys()),
                    "total_exploits": sum(len(vulns) for vulns in exploited_vulns.values()),
                    "details": exploited_vulns
                }
        
        # Compile final results
        analysis_results = {
            "target": target,
            "scan_date": datetime.datetime.now().isoformat(),
            "active_scan": scan_results,
            "passive_monitoring": passive_results,
            "vulnerability_scan": vuln_scan_results,
            "technologies": combined_techs,
            "trends_analysis": trends_analysis,
            "vulnerability_predictions": prediction_data
        }
        
        if "exploit_analysis" in locals() and exploit_analysis:
            analysis_results["exploit_analysis"] = exploit_analysis
            
        # No need to add trends_analysis again as it's already in the analysis_results
        
        # Save results
        output_file = os.path.join(
            self.output_dir, 
            f"{target.replace('.', '_').replace(':', '_')}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        
        with open(output_file, 'w') as f:
            json.dump(analysis_results, f, indent=2)
            
        self.logger.info(f"Analysis results saved to {output_file}")
        
        return analysis_results
    
    def _merge_technologies(self, active_techs: List[Dict[str, Any]], 
                          passive_techs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Merge technologies from active and passive sources
        
        Args:
            active_techs: Technologies from active scanning
            passive_techs: Technologies from passive monitoring
            
        Returns:
            Merged list of unique technologies
        """
        # Create a map of technologies by name
        tech_map = {}
        
        # Add active technologies
        for tech in active_techs:
            name = tech["name"].lower()
            version = tech["version"]
            
            if name not in tech_map:
                tech_map[name] = {
                    "name": name,
                    "version": version,
                    "sources": ["active"],
                    "confidence": 100  # Active scanning is highly reliable
                }
        
        # Add or update with passive technologies
        for tech in passive_techs:
            name = tech["name"].lower()
            version = tech["version"]
            confidence = tech.get("confidence", 80)  # Default confidence for passive detection
            
            if name not in tech_map:
                # New technology
                tech_map[name] = {
                    "name": name,
                    "version": version,
                    "sources": ["passive"],
                    "confidence": confidence
                }
            else:
                # Existing technology - update if passive is more confident or add as source
                existing_tech = tech_map[name]
                existing_tech["sources"].append("passive")
                
                # If active and passive versions differ but passive has higher confidence, use passive version
                if version != existing_tech["version"] and confidence > existing_tech["confidence"]:
                    existing_tech["version"] = version
                    existing_tech["confidence"] = confidence
        
        # Convert map back to list
        return list(tech_map.values())
    
    def generate_report(self, analysis_results: Dict[str, Any], format: str = "text") -> str:
        """
        Generate a readable report from analysis results
        
        Args:
            analysis_results: Results from analyze_target
            format: Output format (text, json, html)
            
        Returns:
            Formatted report
        """
        # Use the enhanced report generator if available and format is supported
        if format.lower() in ["html", "text", "json"]:
            try:
                target = analysis_results.get("target", "Unknown")
                return self.report_generator.generate_report(
                    analysis_results, 
                    target=target,
                    report_format=format.lower()
                )
            except Exception as e:
                self.logger.error(f"Error generating enhanced report: {str(e)}")
                self.logger.info("Falling back to basic report format")
                # Fall back to basic report format if enhanced report fails
        if format == "json":
            return json.dumps(analysis_results, indent=4)
        
        # Generate text report
        target = analysis_results["target"]
        analysis_time = analysis_results["analysis_time"]
        technologies = analysis_results["technologies"]
        vulnerability_predictions = analysis_results.get("vulnerability_predictions", {})
        remediation_recommendations = analysis_results.get("remediation_recommendations", {})
        
        report = [
            f"FinGuardAI Integrated Vulnerability Analysis Report",
            f"Target: {target}",
            f"Analysis Time: {analysis_time}",
            f"\n--- DETECTED TECHNOLOGIES ---"
        ]
        
        for tech in technologies:
            sources = ", ".join(tech.get("sources", []))
            confidence = tech.get("confidence", "Unknown")
            report.append(f"{tech['name']} {tech['version']} (Sources: {sources}, Confidence: {confidence}%)")
        
        report.append("\n--- VULNERABILITY PREDICTIONS ---")
        
        # Add timeframe predictions
        for timeframe, data in vulnerability_predictions.get("timeframes", {}).items():
            report.append(f"\nTimeframe: {timeframe.replace('_', ' ')} ({data.get('days', 'Unknown')} days)")
            report.append(f"Total vulnerabilities: {data.get('total_count', 0)}")
            report.append(f"Critical vulnerabilities: {data.get('critical_count', 0)}")
            report.append(f"High vulnerabilities: {data.get('high_count', 0)}")
            
            # Add per-technology breakdown
            for tech, tech_data in data.get("vulnerabilities_by_technology", {}).items():
                report.append(f"  - {tech}: {tech_data.get('count', 0)} vulnerabilities "
                           f"({tech_data.get('critical', 0)} critical, {tech_data.get('high', 0)} high)")
        
        # Add remediation recommendations
        report.append("\n--- REMEDIATION RECOMMENDATIONS ---")
        
        for tech, recommendations in remediation_recommendations.items():
            urgency = recommendations.get("upgrade_urgency", "unknown")
            vuln_count = recommendations.get("vulnerability_count", 0)
            severity_counts = recommendations.get("severity_counts", {})
            
            report.append(f"\n{tech}")
            report.append(f"Vulnerabilities: {vuln_count} total "
                       f"({severity_counts.get('CRITICAL', 0)} critical, "
                       f"{severity_counts.get('HIGH', 0)} high, "
                       f"{severity_counts.get('MEDIUM', 0)} medium)")
            report.append(f"Upgrade urgency: {urgency.upper()}")
            
            if recommendations.get("exploitable", False):
                report.append("WARNING: Exploitable vulnerabilities exist!")
            report.append("Recommendations:")
            for rec in recommendations.get("recommendations", []):
                report.append(f"  - {rec}")
        
        # Add exploit analysis if available
        if "exploit_analysis" in analysis_results:
            exploit_analysis = analysis_results["exploit_analysis"]
            report.append("\n--- EXPLOIT ANALYSIS ---")
            report.append(f"Exploitable technologies: {', '.join(exploit_analysis.get('exploitable_technologies', []))}")
            report.append(f"Total exploits: {exploit_analysis.get('total_exploits', 0)}")
        
        # Add detected vulnerabilities from direct scanning
        if "vulnerability_scan" in analysis_results:
            vuln_scan = analysis_results["vulnerability_scan"]
            detected_vulns = vuln_scan.get("detected_vulnerabilities", [])
            vuln_summary = vuln_scan.get("vulnerability_summary", {})
            
            report.append("\n--- DETECTED VULNERABILITIES ---")
            report.append(f"Critical: {len(vuln_summary.get('critical', []))}")
            report.append(f"High: {len(vuln_summary.get('high', []))}")
            report.append(f"Medium: {len(vuln_summary.get('medium', []))}")
            report.append(f"Low: {len(vuln_summary.get('low', []))}")
            
            # Add critical vulnerabilities
            critical_vulns = vuln_summary.get('critical', [])
            if critical_vulns:
                report.append("\n--- CRITICAL VULNERABILITIES ---")
                for i, vuln in enumerate(critical_vulns, 1):
                    vuln_id = vuln.get("id", "")
                    name = vuln.get("name", "Unknown Vulnerability")
                    port = vuln.get("port", "")
                    report.append(f"{i}. {name} {f'({vuln_id})' if vuln_id else ''}")
                    if port:
                        report.append(f"   Port {port}")
            
            # Add high vulnerabilities
            high_vulns = vuln_summary.get('high', [])
            if high_vulns:
                report.append("\n--- HIGH VULNERABILITIES ---")
                for i, vuln in enumerate(high_vulns, 1):
                    vuln_id = vuln.get("id", "")
                    name = vuln.get("name", "Unknown Vulnerability")
                    port = vuln.get("port", "")
                    report.append(f"{i}. {name} {f'({vuln_id})' if vuln_id else ''}")
                    if port:
                        report.append(f"   Port {port}")
                        
            # Add open ports information
            open_ports = vuln_scan.get("open_ports", {})
            if open_ports:
                report.append("\n--- OPEN PORTS ---")
                for port, service in open_ports.items():
                    service_name = service.get("name", "")
                    product = service.get("product", "")
                    version = service.get("version", "")
                    service_str = f"{service_name}"
                    if product:
                        service_str += f" ({product}"
                        if version:
                            service_str += f" {version}"
                        service_str += ")"
                    report.append(f"Port {port}: {service_str}")
                
            # Add SSL details if available
            ssl_details = vuln_scan.get("ssl_details")
            if ssl_details:
                report.append("\n--- SSL CERTIFICATE DETAILS ---")
                report.append(f"Issuer: {ssl_details.get('issuer', '')}")
                report.append(f"Valid To: {ssl_details.get('valid_to', '')}")
                report.append(f"Self-Signed: {'Yes' if ssl_details.get('self_signed', False) else 'No'}")
                
        # Add trends analysis if available
        if "trends_analysis" in analysis_results:
            trends_analysis = analysis_results["trends_analysis"]
            report.append("\n--- VULNERABILITY TRENDS ---")
            
            for tech, trends in trends_analysis.items():
                increasing = trends.get("increasing_trend", False)
                trend_direction = "INCREASING ⚠️" if increasing else "Stable/Decreasing"
                
                report.append(f"\n{tech}: Trend is {trend_direction}")
        
        return "\n".join(report)


def main():
    """
    Main entry point for running the integrated analyzer from command line
    """
    parser = argparse.ArgumentParser(description="FinGuardAI Integrated Vulnerability Analyzer")
    parser.add_argument("target", help="Target to analyze (domain, IP, or URL)")
    parser.add_argument("--output", "-o", help="Output report file", default=None)
    parser.add_argument("--format", "-f", help="Output format (text, json)", default="text")
    parser.add_argument("--timeframes", help="Comma-separated list of timeframes", default="1_day,1_week,10_days")
    parser.add_argument("--ports", help="Comma-separated list of ports to scan", default="1-1000,3306,8080-8090")
    parser.add_argument("--scan-intensity", choices=["stealthy", "normal", "aggressive"], default="normal", help="Vulnerability scan intensity")
    args = parser.parse_args()
    
    # Configure parameters
    analysis_params = DEFAULT_ANALYSIS_PARAMS.copy()
    analysis_params["timeframes"] = args.timeframes.split(",")
    
    # Create analyzer and run analysis
    analyzer = IntegratedAnalyzer()
    results = analyzer.analyze_target(args.target, analysis_params=analysis_params)
    
    # Generate report
    report = analyzer.generate_report(results, format=args.format)
    
    # Output report
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        print(f"Report saved to {args.output}")
    else:
        print(report)


if __name__ == "__main__":
    main()
