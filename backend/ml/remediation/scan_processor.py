"""
FinGuardAI - Scan Results to Financial Remediation Processor

This module processes network scan results (Nmap, vulnerability scanners)
and generates specific financial sector remediation recommendations based on findings.
"""

import re
import os
import json
import logging
from typing import Dict, List, Any, Set, Optional

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('finguardai.scan_processor')

# Import remediation modules
try:
    from .financial_recommendations import get_financial_recommendations
    from .recommendations import get_recommendations_for_threat
    HAS_REMEDIATION = True
except ImportError:
    logger.warning("Remediation modules not available. Cannot generate recommendations.")
    HAS_REMEDIATION = False

# Common financial service ports and their descriptions
FINANCIAL_PORTS = {
    21: {"service": "ftp", "description": "FTP - File Transfer", "financial_impact": "Possible sensitive data transfer channel"},
    22: {"service": "ssh", "description": "SSH - Secure Shell", "financial_impact": "Administrative access to financial systems"},
    25: {"service": "smtp", "description": "SMTP - Email", "financial_impact": "Email data transfer, possible phishing target"},
    53: {"service": "dns", "description": "DNS - Domain Name System", "financial_impact": "Critical for financial service resolution"},
    80: {"service": "http", "description": "HTTP - Web", "financial_impact": "Unencrypted web services, banking portal risk"},
    443: {"service": "https", "description": "HTTPS - Encrypted Web", "financial_impact": "Banking portals, payment gateways, APIs"},
    465: {"service": "smtps", "description": "SMTPS - Encrypted Email", "financial_impact": "Secure email for financial communications"},
    587: {"service": "submission", "description": "Email Submission", "financial_impact": "Financial alerts, notifications channel"},
    993: {"service": "imaps", "description": "IMAPS - Encrypted Email Retrieval", "financial_impact": "Financial emails, statements"},
    995: {"service": "pop3s", "description": "POP3S - Encrypted Email Retrieval", "financial_impact": "Financial emails, statements"},
    1433: {"service": "mssql", "description": "MS SQL Server", "financial_impact": "Financial transaction database"},
    1521: {"service": "oracle", "description": "Oracle Database", "financial_impact": "Core banking database, ledger systems"},
    3306: {"service": "mysql", "description": "MySQL Database", "financial_impact": "Financial data storage, customer records"},
    5432: {"service": "postgresql", "description": "PostgreSQL Database", "financial_impact": "Financial data storage, customer records"},
    8000: {"service": "http-alt", "description": "Alternate HTTP", "financial_impact": "Web services, possible API endpoints"},
    8080: {"service": "http-proxy", "description": "HTTP Proxy", "financial_impact": "Web proxy, API gateway for financial services"},
    8443: {"service": "https-alt", "description": "Alternate HTTPS", "financial_impact": "Secure financial web services, APIs"},
    27017: {"service": "mongodb", "description": "MongoDB", "financial_impact": "Financial document storage, transaction records"}
}

# Financial sector vulnerability patterns
FINANCIAL_VULN_PATTERNS = [
    {
        "pattern": r"SSL\s+[^(]*?\(\s*?(\d+)\s*?\)",
        "description": "SSL/TLS Vulnerability",
        "threat_type": "encryption_weakness",
        "financial_threat": "payment_system_breach",
        "severity": "high"
    },
    {
        "pattern": r"CVE-\d{4}-\d{4,}",
        "description": "Known CVE Vulnerability",
        "threat_type": "known_vulnerability",
        "financial_threat": "financial_api_attack",
        "severity": "critical"
    },
    {
        "pattern": r"password|credentials|authentication",
        "description": "Authentication Vulnerability",
        "threat_type": "auth_weakness",
        "financial_threat": "authentication_attack",
        "severity": "critical"
    },
    {
        "pattern": r"injection|xss|cross.?site|sql",
        "description": "Injection/XSS Vulnerability",
        "threat_type": "injection_vulnerability",
        "financial_threat": "financial_api_attack",
        "severity": "critical"
    },
    {
        "pattern": r"default.?credentials|default.?password",
        "description": "Default Credentials Risk",
        "threat_type": "default_credentials",
        "financial_threat": "authentication_attack",
        "severity": "critical"
    },
    {
        "pattern": r"smb|samba|netbios|cifs",
        "description": "File Sharing Vulnerability",
        "threat_type": "file_sharing_exposure",
        "financial_threat": "financial_data_exfiltration",
        "severity": "high"
    },
    {
        "pattern": r"database|oracle|mysql|postgres|mssql|db2",
        "description": "Database Exposure",
        "threat_type": "database_exposure",
        "financial_threat": "financial_data_exfiltration",
        "severity": "critical"
    },
    {
        "pattern": r"api|rest|soap|graphql|json",
        "description": "API Vulnerability",
        "threat_type": "api_vulnerability",
        "financial_threat": "financial_api_attack",
        "severity": "high"
    },
    {
        "pattern": r"payment|credit.?card|pci|card.?number|cvv|ccv",
        "description": "Payment Data Vulnerability",
        "threat_type": "payment_data_exposure",
        "financial_threat": "payment_system_breach",
        "severity": "critical"
    }
]

def parse_nmap_scan(scan_data: str) -> Dict[str, Any]:
    """
    Parse Nmap scan output data into structured format
    
    Args:
        scan_data: Raw Nmap scan output text
        
    Returns:
        Dictionary of parsed scan data
    """
    # Initialize results
    results = {
        "host": None,
        "os": None,
        "open_ports": [],
        "vulnerabilities": [],
        "financial_services": [],
        "financial_risk_level": "low"
    }
    
    # Extract host information
    host_match = re.search(r"Nmap scan report for ([^\s]+)", scan_data)
    if host_match:
        results["host"] = host_match.group(1)
    
    # Extract OS information
    os_match = re.search(r"OS details: (.+?)(?:\n|$)", scan_data)
    if os_match:
        results["os"] = os_match.group(1).strip()
    
    # Extract port information
    port_matches = re.finditer(r"(\d+)/(\w+)\s+(\w+)\s+(\w+)\s+(.+?)(?:\n|$)", scan_data)
    for match in port_matches:
        port = int(match.group(1))
        protocol = match.group(2)
        state = match.group(3)
        service = match.group(4)
        version = match.group(5).strip()
        
        # Only consider open ports
        if state.lower() != 'open':
            continue
        
        port_info = {
            "port": port,
            "protocol": protocol,
            "service": service,
            "version": version,
            "financial_relevant": False,
            "vulnerabilities": []
        }
        
        # Check if this is a financial-relevant port
        if port in FINANCIAL_PORTS:
            port_info["financial_relevant"] = True
            port_info["financial_impact"] = FINANCIAL_PORTS[port]["financial_impact"]
            
            # Add to financial services
            results["financial_services"].append({
                "port": port,
                "service": service,
                "description": FINANCIAL_PORTS[port]["description"],
                "impact": FINANCIAL_PORTS[port]["financial_impact"]
            })
        
        # Check for vulnerabilities in version information
        for vuln_pattern in FINANCIAL_VULN_PATTERNS:
            if re.search(vuln_pattern["pattern"], version, re.IGNORECASE):
                vuln = {
                    "description": vuln_pattern["description"],
                    "threat_type": vuln_pattern["threat_type"],
                    "financial_threat": vuln_pattern["financial_threat"],
                    "severity": vuln_pattern["severity"],
                    "affected_port": port,
                    "affected_service": service
                }
                port_info["vulnerabilities"].append(vuln)
                results["vulnerabilities"].append(vuln)
        
        results["open_ports"].append(port_info)
    
    # Look for script output with vulnerabilities
    script_blocks = re.finditer(r"\|\s+([^:]+):(.*?)(?=\n\||\n[^|]|\Z)", scan_data, re.DOTALL)
    for block in script_blocks:
        script_name = block.group(1).strip()
        script_output = block.group(2).strip()
        
        # Check for vulnerabilities in script output
        for vuln_pattern in FINANCIAL_VULN_PATTERNS:
            if re.search(vuln_pattern["pattern"], script_output, re.IGNORECASE):
                vuln = {
                    "description": f"{vuln_pattern['description']} (from {script_name})",
                    "threat_type": vuln_pattern["threat_type"],
                    "financial_threat": vuln_pattern["financial_threat"],
                    "severity": vuln_pattern["severity"],
                    "evidence": script_output[:100] + ("..." if len(script_output) > 100 else "")
                }
                results["vulnerabilities"].append(vuln)
    
    # Determine overall financial risk level
    if any(v["severity"] == "critical" for v in results["vulnerabilities"]):
        results["financial_risk_level"] = "critical"
    elif any(v["severity"] == "high" for v in results["vulnerabilities"]):
        results["financial_risk_level"] = "high"
    elif results["vulnerabilities"]:
        results["financial_risk_level"] = "medium"
    elif results["financial_services"]:
        results["financial_risk_level"] = "medium"  # Financial services present but no obvious vulnerabilities
    
    return results

def convert_scan_to_threat_data(scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Convert scan results to threat data format for remediation system
    
    Args:
        scan_results: Parsed scan results dictionary
        
    Returns:
        List of threat data dictionaries
    """
    threats = []
    
    # Process each vulnerability as a potential threat
    for vuln in scan_results.get("vulnerabilities", []):
        # Create a threat entry for each vulnerability
        threat = {
            "protocol": "tcp",  # Assuming TCP for most vulnerabilities
            "service": vuln.get("affected_service", "unknown"),
            "src_ip": "scanning_source",  # Placeholder
            "dest_ip": scan_results.get("host", "unknown"),
            "is_threat": True,
            "threat_probability": 0.85 if vuln["severity"] == "critical" else 0.75,
            "threat_level": vuln["severity"],
            "vulnerability_type": vuln["threat_type"],
            "financial_threat_type": vuln["financial_threat"],
            "description": vuln["description"]
        }
        
        # Additional fields based on vulnerability type
        if vuln["threat_type"] == "encryption_weakness":
            threat["error_rate"] = 0.6
        elif vuln["threat_type"] == "injection_vulnerability":
            threat["error_rate"] = 0.3
        elif vuln["threat_type"] == "auth_weakness":
            threat["error_rate"] = 0.7
            threat["failed_logins"] = 15  # Assumed value
        
        threats.append(threat)
    
    # Add general threats based on open ports with financial relevance
    for service in scan_results.get("financial_services", []):
        # Add a general threat entry for each financial service
        if not any(t.get("vulnerability_type") for t in threats if t.get("service") == service["service"]):
            # Only add if we don't already have a specific vulnerability for this service
            threat = {
                "protocol": "tcp",
                "service": service["service"],
                "src_ip": "scanning_source",
                "dest_ip": scan_results.get("host", "unknown"),
                "port": service["port"],
                "is_threat": True,
                "threat_probability": 0.6,  # Medium probability
                "threat_level": "medium",
                "vulnerability_type": "exposed_service",
                "financial_threat_type": "financial_api_attack" if service["service"] in ["http", "https"] else "financial_data_exfiltration",
                "description": f"Exposed financial service: {service['description']}"
            }
            threats.append(threat)
    
    return threats

def get_recommendations_from_scan(scan_data: str) -> Dict[str, Any]:
    """
    Process raw scan data and generate financial-specific recommendations
    
    Args:
        scan_data: Raw scan output (Nmap, etc.)
        
    Returns:
        Dictionary with scan analysis and recommendations
    """
    if not HAS_REMEDIATION:
        return {"error": "Remediation modules not available"}
    
    # Parse the scan data
    parsed_scan = parse_nmap_scan(scan_data)
    
    # Convert to threat data format
    threats = convert_scan_to_threat_data(parsed_scan)
    
    # Generate recommendations for each threat
    all_recommendations = []
    unique_recommendations = set()
    all_threat_types = set()
    financial_threat_types = set()
    all_technical_controls = []
    unique_technical_controls = set()
    all_regulations = []
    unique_regulations = set()
    highest_severity = 0
    severity_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    
    for threat in threats:
        # Get general recommendations
        general_recs = get_recommendations_for_threat(threat)
        
        # Get financial recommendations
        financial_recs = get_financial_recommendations(threat)
        
        # Extract and track unique recommendations
        if "recommendations" in general_recs:
            for rec in general_recs["recommendations"]:
                if rec not in unique_recommendations:
                    unique_recommendations.add(rec)
                    all_recommendations.append(rec)
        
        # Extract and track financial recommendations
        if "critical_remediations" in financial_recs:
            for rec in financial_recs["critical_remediations"]:
                if rec not in unique_recommendations:
                    unique_recommendations.add(rec)
                    all_recommendations.append(rec)
        
        # Extract and track technical controls
        if "technical_controls" in financial_recs:
            for control in financial_recs["technical_controls"]:
                if control not in unique_technical_controls:
                    unique_technical_controls.add(control)
                    all_technical_controls.append(control)
        
        # Extract and track regulations
        if "regulatory_requirements" in financial_recs:
            for reg in financial_recs["regulatory_requirements"]:
                if isinstance(reg, dict) and "name" in reg and "section" in reg:
                    reg_str = f"{reg['name']} {reg['section']}"
                    if reg_str not in unique_regulations:
                        unique_regulations.add(reg_str)
                        all_regulations.append(reg_str)
        
        # Track threat types
        all_threat_types.update(general_recs.get("threat_types", []))
        financial_threat_types.update(financial_recs.get("financial_threat_types", []))
        
        # Track highest severity
        current_severity = max(
            severity_map.get(general_recs.get("severity", "low"), 1),
            severity_map.get(financial_recs.get("severity", "low"), 1)
        )
        highest_severity = max(highest_severity, current_severity)
    
    # Map severity back to string
    severity_map_reverse = {1: "low", 2: "medium", 3: "high", 4: "critical"}
    overall_severity = severity_map_reverse.get(highest_severity, "low")
    
    # Construct result
    result = {
        "scan_analysis": parsed_scan,
        "identified_threats": threats,
        "recommendations": {
            "severity": overall_severity,
            "general_threat_types": list(all_threat_types),
            "financial_threat_types": list(financial_threat_types),
            "general_recommendations": all_recommendations[:5],  # Top 5 general recommendations
            "financial_technical_controls": all_technical_controls[:10],  # Top 10 technical controls
            "regulations": all_regulations,
            "total_vulnerabilities": len(parsed_scan["vulnerabilities"]),
            "financial_risk_level": parsed_scan["financial_risk_level"]
        }
    }
    
    return result

def process_scan_file(file_path: str) -> Dict[str, Any]:
    """
    Process a scan output file and generate recommendations
    
    Args:
        file_path: Path to scan output file
        
    Returns:
        Dictionary with scan analysis and recommendations
    """
    try:
        with open(file_path, 'r') as f:
            scan_data = f.read()
        
        return get_recommendations_from_scan(scan_data)
    except Exception as e:
        logger.error(f"Error processing scan file: {e}")
        return {"error": f"Failed to process scan file: {str(e)}"}
