"""
FinGuardAI - Predictive Vulnerability Analysis for Financial Sector

This module predicts potential future vulnerabilities based on existing
infrastructure analysis, technology stacks, and emerging threat patterns
in the financial sector.
"""

import os
import re
import json
import logging
import datetime
from typing import Dict, List, Any, Optional, Set
from collections import defaultdict

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('finguardai.predictive')

# Service to technology mapping
SERVICE_TECH_MAPPING = {
    'http': ['web_server', 'apache', 'nginx', 'web_application'],
    'https': ['web_server', 'apache', 'nginx', 'web_application', 'tls'],
    'ftp': ['file_transfer', 'unencrypted_protocol'],
    'ssh': ['admin_access', 'secure_shell'],
    'smtp': ['mail_server', 'email_services'],
    'mysql': ['database', 'sql_database', 'mysql'],
    'mssql': ['database', 'sql_database', 'microsoft_sql'],
    'postgresql': ['database', 'sql_database', 'postgresql'],
    'mongodb': ['database', 'nosql_database', 'mongodb'],
    'redis': ['database', 'nosql_database', 'redis', 'cache'],
    'dns': ['dns_server', 'name_resolution'],
    'ldap': ['directory_services', 'authentication'],
    'radius': ['authentication', 'network_access'],
    'kerberos': ['authentication', 'enterprise'],
    'nfs': ['file_sharing', 'network_filesystem'],
    'smb': ['file_sharing', 'windows'],
    'rdp': ['remote_access', 'windows'],
    'vnc': ['remote_access', 'cross_platform'],
    'telnet': ['remote_access', 'unencrypted_protocol', 'legacy'],
    'snmp': ['monitoring', 'network_management'],
}

# Emerging financial sector vulnerabilities database (2025 projection)
EMERGING_VULNERABILITIES = [
    {
        "id": "FIN-2025-001",
        "name": "API Gateway Authentication Bypass",
        "description": "Next-gen financial API gateways may contain authentication bypass vulnerabilities due to JWT validation flaws",
        "affected_technologies": ["api_gateway", "web_application", "authentication"],
        "prediction_confidence": 0.85,
        "earliest_expected": "2025-06",
        "mitigation": "Implement multi-layer API authentication with token binding and certificate pinning",
        "financial_impact": "High - Could allow unauthorized access to financial transaction APIs",
        "indicators": ["api", "microservice", "jwt", "oauth"],
        "regulatory_impact": ["PCI DSS", "PSD2", "GDPR", "GLBA"]
    },
    {
        "id": "FIN-2025-002",
        "name": "Real-time Payment Injection Vulnerability",
        "description": "Instant payment systems may be vulnerable to a new class of injection attacks targeting transaction processors",
        "affected_technologies": ["payment_processor", "web_application", "api_gateway"],
        "prediction_confidence": 0.78,
        "earliest_expected": "2025-07",
        "mitigation": "Implement strict input validation specifically for transaction amount and routing fields",
        "financial_impact": "Critical - Could allow transaction amount/destination manipulation",
        "indicators": ["payment", "transaction", "web_server", "api"],
        "regulatory_impact": ["PCI DSS", "SWIFT CSP", "ISO 20022"]
    },
    {
        "id": "FIN-2025-003",
        "name": "TLS Downgrade in Financial Proxies",
        "description": "TLS proxies in financial services may be vulnerable to downgrade attacks via a new protocol weakness",
        "affected_technologies": ["tls", "web_server", "load_balancer", "proxy"],
        "prediction_confidence": 0.72,
        "earliest_expected": "2025-04",
        "mitigation": "Disable TLS downgrade capabilities and enforce minimum TLS 1.3",
        "financial_impact": "High - Could allow session hijacking of financial transactions",
        "indicators": ["https", "tls", "ssl", "proxy", "load_balancer"],
        "regulatory_impact": ["PCI DSS", "NYDFS", "GDPR"]
    },
    {
        "id": "FIN-2025-004",
        "name": "Banking Database Pagination Overflow",
        "description": "SQL and NoSQL databases with financial data may be vulnerable to a new pagination-based overflow attack",
        "affected_technologies": ["database", "sql_database", "nosql_database"],
        "prediction_confidence": 0.81,
        "earliest_expected": "2025-09",
        "mitigation": "Apply specific pagination controls and limit-offset validation",
        "financial_impact": "Critical - Could allow access to records outside authorized range",
        "indicators": ["database", "mysql", "postgresql", "mongodb"],
        "regulatory_impact": ["GLBA", "GDPR", "PCI DSS"]
    },
    {
        "id": "FIN-2025-005",
        "name": "Legacy Authentication Integration Weakness",
        "description": "Financial systems integrating legacy authentication with modern OAuth/OIDC may expose new attack vectors",
        "affected_technologies": ["authentication", "ldap", "kerberos", "oauth"],
        "prediction_confidence": 0.77,
        "earliest_expected": "2025-03",
        "mitigation": "Implement identity gateway with strict protocol transition controls",
        "financial_impact": "High - Could allow privilege escalation in financial systems",
        "indicators": ["ldap", "kerberos", "authentication", "legacy", "oauth"],
        "regulatory_impact": ["PSD2", "FFIEC", "SOX"]
    },
    {
        "id": "FIN-2025-006",
        "name": "Encrypted File Storage Side Channel",
        "description": "Encrypted financial document storage may be vulnerable to side-channel attacks revealing customer data",
        "affected_technologies": ["file_sharing", "encryption", "document_management"],
        "prediction_confidence": 0.70,
        "earliest_expected": "2025-08",
        "mitigation": "Implement constant-time encryption operations and access pattern obfuscation",
        "financial_impact": "High - Could leak sensitive financial documents metadata",
        "indicators": ["file_transfer", "file_sharing", "encryption", "nfs", "smb"],
        "regulatory_impact": ["GLBA", "GDPR", "PCI DSS"]
    },
    {
        "id": "FIN-2025-007",
        "name": "Banking Portal Session Prediction",
        "description": "Web banking portals may be vulnerable to session prediction attacks via new entropy weaknesses",
        "affected_technologies": ["web_application", "web_server", "session_management"],
        "prediction_confidence": 0.82,
        "earliest_expected": "2025-05",
        "mitigation": "Implement dual-layer session management with client entropy contribution",
        "financial_impact": "Critical - Could allow session hijacking of active banking sessions",
        "indicators": ["web_server", "http", "https", "web_application"],
        "regulatory_impact": ["PSD2", "FFIEC", "NYDFS"]
    },
    {
        "id": "FIN-2025-008",
        "name": "SWIFT Message Parser Vulnerability",
        "description": "SWIFT message parsing libraries may contain vulnerabilities allowing transaction manipulation",
        "affected_technologies": ["financial_messaging", "swift", "iso20022"],
        "prediction_confidence": 0.75,
        "earliest_expected": "2025-10",
        "mitigation": "Implement strict message validation and cryptographic integrity checks",
        "financial_impact": "Critical - Could allow manipulation of financial transfers",
        "indicators": ["financial_messaging", "swift", "payment", "transaction"],
        "regulatory_impact": ["SWIFT CSP", "PCI DSS", "NYDFS"]
    },
    {
        "id": "FIN-2025-009",
        "name": "Financial Data Lake Access Control Bypass",
        "description": "Data lakes containing financial information may be vulnerable to a new access control bypass",
        "affected_technologies": ["data_lake", "cloud_storage", "big_data"],
        "prediction_confidence": 0.72,
        "earliest_expected": "2025-07",
        "mitigation": "Implement attribute-based access control with continuous verification",
        "financial_impact": "High - Could allow unauthorized analytics on financial data",
        "indicators": ["database", "cloud", "storage", "data_lake"],
        "regulatory_impact": ["GDPR", "CCPA", "GLBA", "FFIEC"]
    },
    {
        "id": "FIN-2025-010",
        "name": "Unencrypted Protocol Data Leakage",
        "description": "Legacy unencrypted protocols may leak financial metadata even when not carrying primary financial data",
        "affected_technologies": ["unencrypted_protocol", "legacy", "telnet", "ftp"],
        "prediction_confidence": 0.88,
        "earliest_expected": "2025-02",
        "mitigation": "Replace all unencrypted protocols with encrypted alternatives",
        "financial_impact": "Medium - Could leak metadata about financial operations",
        "indicators": ["ftp", "telnet", "unencrypted_protocol"],
        "regulatory_impact": ["PCI DSS", "GDPR", "GLBA"]
    }
]

def predict_vulnerabilities(scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Predict potential future vulnerabilities based on scan results
    
    Args:
        scan_results: Parsed scan results from Nmap or similar
        
    Returns:
        List of predicted vulnerabilities with remediation recommendations
    """
    # Extract technologies in use based on scan data
    technologies = extract_technologies(scan_results)
    
    # Match technologies to potential vulnerabilities
    potential_vulnerabilities = []
    
    for vuln in EMERGING_VULNERABILITIES:
        # Calculate match score based on technology overlap
        tech_match_count = sum(1 for tech in vuln["affected_technologies"] if tech in technologies)
        indicator_match_count = sum(1 for indicator in vuln["indicators"] if indicator in technologies)
        
        total_match_score = (tech_match_count / len(vuln["affected_technologies"])) * 0.7 + \
                           (indicator_match_count / len(vuln["indicators"])) * 0.3
        
        # If there's a significant match, include this vulnerability
        if total_match_score > 0.3:
            # Calculate adjusted confidence based on match score
            adjusted_confidence = vuln["prediction_confidence"] * total_match_score
            
            # Create prediction entry
            prediction = {
                "id": vuln["id"],
                "name": vuln["name"],
                "description": vuln["description"],
                "confidence": adjusted_confidence,
                "financial_impact": vuln["financial_impact"],
                "earliest_expected": vuln["earliest_expected"],
                "time_window": time_until_vulnerability(vuln["earliest_expected"]),
                "mitigation": vuln["mitigation"],
                "affected_technologies": [tech for tech in vuln["affected_technologies"] if tech in technologies],
                "regulatory_impact": vuln["regulatory_impact"],
                "match_score": total_match_score
            }
            
            potential_vulnerabilities.append(prediction)
    
    # Sort by adjusted confidence
    potential_vulnerabilities.sort(key=lambda x: x["confidence"], reverse=True)
    
    return potential_vulnerabilities

def extract_technologies(scan_results: Dict[str, Any]) -> Set[str]:
    """
    Extract technology stack from scan results
    
    Args:
        scan_results: Parsed scan results
        
    Returns:
        Set of identified technologies
    """
    technologies = set()
    
    # Extract from services
    for port in scan_results.get("open_ports", []):
        service = port.get("service", "").lower()
        if service in SERVICE_TECH_MAPPING:
            technologies.update(SERVICE_TECH_MAPPING[service])
    
    # Extract from version information
    for port in scan_results.get("open_ports", []):
        version = port.get("version", "").lower()
        
        # Check for web servers
        if "apache" in version:
            technologies.add("apache")
        if "nginx" in version:
            technologies.add("nginx")
        if "iis" in version:
            technologies.add("iis")
            
        # Check for database technologies
        if "mysql" in version:
            technologies.add("mysql")
        if "postgresql" in version:
            technologies.add("postgresql")
        if "mongodb" in version:
            technologies.add("mongodb")
            
        # Check for application frameworks or APIs
        if "api" in version:
            technologies.add("api")
        if "rest" in version:
            technologies.add("api")
        if "json" in version:
            technologies.add("api")
        if "graphql" in version:
            technologies.add("api")
            
        # Check for payment/financial indicators
        if "payment" in version:
            technologies.add("payment")
        if "bank" in version:
            technologies.add("banking")
        if "oauth" in version:
            technologies.add("oauth")
        if "jwt" in version:
            technologies.add("jwt")
    
    # Add inferred technologies
    if "mysql" in technologies or "postgresql" in technologies or "mssql" in technologies:
        technologies.add("sql_database")
    
    if "mongodb" in technologies or "redis" in technologies:
        technologies.add("nosql_database")
    
    if "web_server" in technologies:
        technologies.add("web_application")
    
    if "https" in technologies:
        technologies.add("tls")
    
    # Add financial sector technologies if we have any indicators
    financial_indicators = {"payment", "banking", "transaction", "finance", "financial"}
    if any(indicator in technologies for indicator in financial_indicators):
        technologies.add("financial_services")
    
    # Look for evidence of financial data services
    if "web_application" in technologies and "database" in technologies:
        technologies.add("data_storage")
        
        # If we have financial services, this could be financial data storage
        if "financial_services" in technologies:
            technologies.add("financial_data_storage")
    
    # Add microservices if we see APIs and multiple services
    if "api" in technologies and len(technologies) > 5:
        technologies.add("microservice")
    
    return technologies

def time_until_vulnerability(earliest_date: str) -> str:
    """
    Calculate time window until potential vulnerability
    
    Args:
        earliest_date: Earliest expected vulnerability date (YYYY-MM)
        
    Returns:
        String describing time window
    """
    try:
        # Parse the earliest date
        year, month = map(int, earliest_date.split("-"))
        earliest = datetime.datetime(year, month, 1)
        
        # Get current date
        now = datetime.datetime.now()
        
        # Calculate difference in months
        diff_months = (earliest.year - now.year) * 12 + earliest.month - now.month
        
        if diff_months < 0:
            return "Potential vulnerability already possible"
        elif diff_months == 0:
            return "Potential vulnerability expected this month"
        elif diff_months == 1:
            return "Potential vulnerability expected next month"
        elif diff_months <= 3:
            return f"Potential vulnerability expected in {diff_months} months (short-term)"
        elif diff_months <= 6:
            return f"Potential vulnerability expected in {diff_months} months (medium-term)"
        else:
            return f"Potential vulnerability expected in {diff_months} months (long-term)"
    except:
        return "Unknown timeframe"

def get_predictive_analysis(scan_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Get predictive vulnerability analysis for scan results
    
    Args:
        scan_results: Parsed scan results
        
    Returns:
        Dictionary with predictive analysis results
    """
    # Extract technologies
    technologies = extract_technologies(scan_results)
    
    # Predict vulnerabilities
    predicted_vulnerabilities = predict_vulnerabilities(scan_results)
    
    # Group vulnerabilities by timeframe
    grouped_by_timeframe = defaultdict(list)
    for vuln in predicted_vulnerabilities:
        if "short-term" in vuln["time_window"]:
            grouped_by_timeframe["short_term"].append(vuln)
        elif "medium-term" in vuln["time_window"]:
            grouped_by_timeframe["medium_term"].append(vuln)
        else:
            grouped_by_timeframe["long_term"].append(vuln)
    
    # Return final analysis
    return {
        "technologies_detected": list(technologies),
        "predicted_vulnerabilities": predicted_vulnerabilities,
        "total_predictions": len(predicted_vulnerabilities),
        "predictions_by_timeframe": {
            "short_term": len(grouped_by_timeframe["short_term"]),
            "medium_term": len(grouped_by_timeframe["medium_term"]),
            "long_term": len(grouped_by_timeframe["long_term"])
        },
        "grouped_vulnerabilities": dict(grouped_by_timeframe),
        "highest_confidence_prediction": predicted_vulnerabilities[0] if predicted_vulnerabilities else None,
        "vulnerability_counts_by_regulation": count_regulations(predicted_vulnerabilities)
    }

def count_regulations(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
    """
    Count vulnerability predictions by regulatory impact
    
    Args:
        vulnerabilities: List of predicted vulnerabilities
        
    Returns:
        Dictionary with counts by regulation
    """
    regulation_counts = defaultdict(int)
    
    for vuln in vulnerabilities:
        for reg in vuln.get("regulatory_impact", []):
            regulation_counts[reg] += 1
    
    return dict(regulation_counts)
