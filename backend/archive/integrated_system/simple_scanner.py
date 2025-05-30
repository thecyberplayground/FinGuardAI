"""
FinGuardAI Simple Vulnerability Scanner

A simplified version of the comprehensive scanner that focuses on the core vulnerability
scanning functionality without the complex integrations that might cause errors.
"""

import os
import sys
import json
import logging
import subprocess
import datetime
import argparse
from typing import Dict, List, Any, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("finguardai.simple_scanner")

class SimpleScanner:
    """A simplified vulnerability scanner that focuses on core functionality"""
    
    def __init__(self, output_dir: Optional[str] = None):
        """Initialize the scanner"""
        self.output_dir = output_dir or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "reports"
        )
        os.makedirs(self.output_dir, exist_ok=True)
        
    def scan_target(self, target: str, ports: str = "80,443,8080", intensity: str = "normal") -> Dict[str, Any]:
        """
        Perform a vulnerability scan on the target
        
        Args:
            target: Target to scan (IP, hostname, or URL)
            ports: Ports to scan (comma-separated list or ranges)
            intensity: Scan intensity (stealthy, normal, aggressive)
            
        Returns:
            Scan results as a dictionary
        """
        logger.info(f"Starting vulnerability scan on {target}")
        
        # Create a unique scan ID
        scan_id = f"{target.replace('.', '_')}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Configure nmap flags based on intensity
        if intensity == "stealthy":
            nmap_flags = "-sS -T2"  # SYN scan with slower timing
        elif intensity == "aggressive":
            nmap_flags = "-sS -T4 -A"  # SYN scan with faster timing and OS/version detection
        else:  # normal
            nmap_flags = "-sS -T3"  # SYN scan with normal timing
        
        # Add vulnerability scanning scripts
        nmap_flags += " --script vuln,auth,default,discovery"
        
        # Add service/version detection
        nmap_flags += " -sV"
        
        # Perform the scan
        logger.info(f"Running nmap scan with flags: {nmap_flags}")
        output_file = os.path.join(self.output_dir, f"{scan_id}_scan.xml")
        
        try:
            # Run nmap scan
            cmd = f"nmap {nmap_flags} -p {ports} -oX {output_file} {target}"
            logger.info(f"Executing: {cmd}")
            
            # Execute the actual nmap scan
            subprocess.run(cmd, shell=True, check=True)
            
            # Parse the XML output into a dictionary
            scan_results = self._parse_nmap_xml(output_file)
            
            logger.info(f"Scan completed successfully, results saved to {output_file}")
            return scan_results
            
        except Exception as e:
            logger.error(f"Error running scan: {str(e)}")
            return {
                "error": str(e),
                "target": target,
                "scan_time": datetime.datetime.now().isoformat()
            }
    
    def generate_report(self, scan_results: Dict[str, Any], format: str = "text") -> str:
        """
        Generate a report from scan results
        
        Args:
            scan_results: Scan results from scan_target
            format: Output format (text, json)
            
        Returns:
            Formatted report
        """
        if format == "json":
            return json.dumps(scan_results, indent=2)
        
        # Generate text report
        report = []
        report.append("=" * 80)
        report.append("FINGUARDAI VULNERABILITY SCAN REPORT")
        report.append("=" * 80)
        
        # Add target and scan time
        report.append(f"Target: {scan_results.get('target', 'Unknown')}")
        report.append(f"Scan Time: {scan_results.get('scan_time', datetime.datetime.now().isoformat())}")
        report.append("-" * 80)
        
        # Add vulnerability summary
        vulnerabilities = scan_results.get("vulnerabilities", [])
        report.append(f"\nFound {len(vulnerabilities)} vulnerabilities:")
        
        # Count vulnerabilities by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "unknown").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        report.append(f"- Critical: {severity_counts['critical']}")
        report.append(f"- High: {severity_counts['high']}")
        report.append(f"- Medium: {severity_counts['medium']}")
        report.append(f"- Low: {severity_counts['low']}")
        
        # Add open ports
        open_ports = scan_results.get("open_ports", {})
        report.append(f"\nOpen Ports: {len(open_ports)}")
        for port, details in open_ports.items():
            service = details.get("name", "unknown")
            product = details.get("product", "")
            version = details.get("version", "")
            
            port_info = f"- Port {port}/{service}"
            if product:
                port_info += f" ({product}"
                if version:
                    port_info += f" {version}"
                port_info += ")"
            
            report.append(port_info)
        
        # Add detailed vulnerability list
        if vulnerabilities:
            report.append("\nVULNERABILITY DETAILS:")
            report.append("-" * 80)
            
            for i, vuln in enumerate(vulnerabilities, 1):
                name = vuln.get("name", "Unknown Vulnerability")
                severity = vuln.get("severity", "unknown").upper()
                description = vuln.get("description", "No description available")
                
                report.append(f"\n{i}. {name} [{severity}]")
                report.append(f"   Description: {description}")
                
                if "recommendation" in vuln:
                    report.append(f"   Recommendation: {vuln['recommendation']}")
        
        # Add recommendations section
        report.append("\nRECOMMENDED ACTIONS:")
        report.append("-" * 80)
        
        # Generate generic recommendations based on findings
        if severity_counts["critical"] > 0 or severity_counts["high"] > 0:
            report.append("1. Address critical and high severity vulnerabilities immediately")
            report.append("2. Implement security patches for affected systems")
            report.append("3. Consider network segmentation to isolate vulnerable systems")
        else:
            report.append("1. Continue regular security scanning and monitoring")
            report.append("2. Keep systems updated with security patches")
        
        report.append("\n" + "=" * 80)
        
        return "\n".join(report)
    
    def _parse_nmap_xml(self, xml_file: str) -> Dict[str, Any]:
        """Parse nmap XML output into a structured dictionary"""
        import xml.etree.ElementTree as ET
        
        try:
            # Parse the XML file
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            # Extract scan information
            scan_info = {}
            if root.find('./taskbegin') is not None:
                scan_info['start_time'] = root.find('./taskbegin').get('time')
            if root.find('./taskend') is not None:
                scan_info['end_time'] = root.find('./taskend').get('time')
            
            # Extract target information
            target = root.find('./runstats/finished').get('timestr') if root.find('./runstats/finished') is not None else 'Unknown'
            target_info = root.find('./host/address').get('addr') if root.find('./host/address') is not None else 'Unknown'
            
            # Extract open ports and services
            open_ports = {}
            host_elem = root.find('./host')
            if host_elem is not None:
                ports_elem = host_elem.find('./ports')
                if ports_elem is not None:
                    for port_elem in ports_elem.findall('./port'):
                        port_id = port_elem.get('portid')
                        state_elem = port_elem.find('./state')
                        service_elem = port_elem.find('./service')
                        
                        if state_elem is not None and state_elem.get('state') == 'open':
                            service_info = {
                                'state': 'open',
                                'name': service_elem.get('name') if service_elem is not None else 'unknown'
                            }
                            
                            # Add service details if available
                            if service_elem is not None:
                                if service_elem.get('product'):
                                    service_info['product'] = service_elem.get('product')
                                if service_elem.get('version'):
                                    service_info['version'] = service_elem.get('version')
                            
                            open_ports[port_id] = service_info
            
            # Extract vulnerabilities from script output
            vulnerabilities = []
            host_scripts = host_elem.findall('./hostscript/script') if host_elem is not None else []
            port_scripts = []
            if host_elem is not None and host_elem.find('./ports') is not None:
                for port in host_elem.find('./ports').findall('./port'):
                    port_scripts.extend(port.findall('./script'))
            
            for script in host_scripts + port_scripts:
                if 'vulners' in script.get('id') or 'vuln' in script.get('id'):
                    output = script.get('output')
                    # Very basic vulnerability parsing - in a real system this would be more sophisticated
                    if 'VULNERABLE' in output or 'vulnerable' in output.lower():
                        lines = output.split('\n')
                        name = script.get('id')
                        severity = "medium"  # Default severity
                        description = output[:200] + "..." if len(output) > 200 else output
                        recommendation = "Patch system and update software to the latest version."
                        
                        # Try to extract severity from the output
                        for line in lines:
                            if 'severity' in line.lower():
                                if 'critical' in line.lower():
                                    severity = "critical"
                                elif 'high' in line.lower():
                                    severity = "high"
                                elif 'medium' in line.lower():
                                    severity = "medium"
                                elif 'low' in line.lower():
                                    severity = "low"
                        
                        vulnerabilities.append({
                            "name": name,
                            "severity": severity,
                            "description": description,
                            "recommendation": recommendation
                        })
            
            # Extract technologies
            technologies = []
            if host_elem is not None and host_elem.find('./ports') is not None:
                for port in host_elem.find('./ports').findall('./port'):
                    service = port.find('./service')
                    if service is not None and service.get('product'):
                        tech = {
                            "name": service.get('product')
                        }
                        if service.get('version'):
                            tech["version"] = service.get('version')
                        
                        # Avoid duplicates
                        if not any(t["name"] == tech["name"] for t in technologies):
                            technologies.append(tech)
            
            return {
                "target": target_info,
                "scan_time": datetime.datetime.now().isoformat(),
                "scan_info": scan_info,
                "open_ports": open_ports,
                "vulnerabilities": vulnerabilities,
                "technologies": technologies
            }
            
        except Exception as e:
            logger.error(f"Error parsing nmap XML: {str(e)}")
            return {
                "target": "Unknown",
                "scan_time": datetime.datetime.now().isoformat(),
                "error": f"Failed to parse nmap results: {str(e)}"
            }

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="FinGuardAI Simple Vulnerability Scanner")
    parser.add_argument("target", help="Target to scan (IP, hostname, or URL)")
    parser.add_argument("--ports", "-p", default="80,443,8080", help="Ports to scan (comma-separated list or ranges)")
    parser.add_argument("--intensity", "-i", choices=["stealthy", "normal", "aggressive"], default="normal", 
                        help="Scan intensity")
    parser.add_argument("--format", "-f", choices=["text", "json"], default="text", help="Output format")
    parser.add_argument("--output", "-o", help="Output file for the report")
    args = parser.parse_args()
    
    scanner = SimpleScanner()
    scan_results = scanner.scan_target(args.target, args.ports, args.intensity)
    report = scanner.generate_report(scan_results, args.format)
    
    if args.output:
        with open(args.output, "w") as f:
            f.write(report)
        print(f"Report saved to {args.output}")
    else:
        print(report)

if __name__ == "__main__":
    main()
