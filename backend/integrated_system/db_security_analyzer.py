"""
Database Security Analysis Module

This module provides functions to analyze database security issues identified during scanning.
"""

import re
import logging
from typing import Dict, List, Any

logger = logging.getLogger("finguardai.db_security_analyzer")

def analyze_database_security(scan_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze database security issues in scan results
    
    Args:
        scan_results: Vulnerability scan results
        
    Returns:
        Dictionary with database security analysis
    """
    # Initialize analysis structure
    analysis = {
        "database_types": [],
        "security_issues": [],
        "configuration_issues": [],
        "summary": {
            "critical_issues": 0,
            "high_issues": 0,
            "medium_issues": 0,
            "low_issues": 0
        },
        "security_score": 0,
        "recommendations": []
    }
    
    # Detect database types
    open_ports = scan_results.get("open_ports", {})
    vulnerabilities = scan_results.get("vulnerabilities", [])
    
    # Map ports to database types
    db_port_mapping = {
        "3306": "MySQL",
        "5432": "PostgreSQL",
        "1433": "Microsoft SQL Server",
        "1521": "Oracle Database",
        "27017": "MongoDB",
        "6379": "Redis",
        "9042": "Cassandra"
    }
    
    # Identify active databases
    active_dbs = []
    for port, details in open_ports.items():
        if port in db_port_mapping:
            db_type = db_port_mapping[port]
            service_name = details.get("name", "")
            product = details.get("product", "")
            version = details.get("version", "")
            
            # Compile database info
            db_info = {
                "type": db_type,
                "port": port,
                "service": service_name,
                "product": product,
                "version": version
            }
            active_dbs.append(db_info)
            analysis["database_types"].append(db_info)
    
    if not active_dbs:
        analysis["summary"]["message"] = "No database services detected"
        return analysis
    
    # Analyze database-specific vulnerabilities
    security_issues = []
    db_vuln_patterns = {
        "empty_password": (r"empty.?password", "high"),
        "weak_auth": (r"authentication|auth.?bypass", "critical"),
        "sql_injection": (r"sql.?injection", "critical"),
        "information_disclosure": (r"information.?disclosure|data.?leak", "high"),
        "default_credentials": (r"default.?credentials|default.?password|default.?user", "high"),
        "remote_access": (r"remote.?access.?enabled", "medium"),
        "privilege_escalation": (r"privilege.?escalation", "high")
    }
    
    # Process each vulnerability for database relevance
    for vuln in vulnerabilities:
        vuln_desc = vuln.get("description", "").lower()
        vuln_name = vuln.get("name", "").lower()
        vuln_port = vuln.get("port", "")
        
        # Skip if not related to database ports
        if vuln_port not in db_port_mapping and str(vuln_port) not in db_port_mapping:
            continue
        
        # Check against known database vulnerability patterns
        for issue_type, (pattern, severity) in db_vuln_patterns.items():
            if re.search(pattern, vuln_desc) or re.search(pattern, vuln_name):
                db_vuln = {
                    "type": issue_type,
                    "severity": severity,
                    "description": vuln.get("description", ""),
                    "name": vuln.get("name", ""),
                    "port": vuln_port,
                    "database": db_port_mapping.get(vuln_port, "Unknown Database")
                }
                security_issues.append(db_vuln)
                
                # Update severity counts
                analysis["summary"][f"{severity}_issues"] += 1
    
    # Add security issues to analysis
    analysis["security_issues"] = security_issues
    
    # Generate recommendations
    recommendations = []
    
    # Base recommendations by database type
    for db in active_dbs:
        db_type = db["type"]
        
        if db_type == "MySQL":
            recommendations.extend([
                "Enable strict SQL mode to prevent SQL injection",
                "Disable remote root access",
                "Use strong password policies",
                "Implement network-level access controls"
            ])
        elif db_type == "PostgreSQL":
            recommendations.extend([
                "Configure pg_hba.conf to restrict client access",
                "Enable SSL connections",
                "Set password_encryption to scram-sha-256"
            ])
        elif db_type == "Microsoft SQL Server":
            recommendations.extend([
                "Use Windows Authentication when possible",
                "Enable Transparent Data Encryption (TDE)",
                "Implement column-level encryption for sensitive data"
            ])
        elif db_type == "MongoDB":
            recommendations.extend([
                "Enable authentication and role-based access control",
                "Configure MongoDB to bind to specific IP addresses",
                "Use TLS/SSL for all connections"
            ])
        elif db_type == "Redis":
            recommendations.extend([
                "Configure Redis to not bind to public interfaces",
                "Set a strong Redis password",
                "Disable dangerous commands in production"
            ])
    
    # Issue-specific recommendations
    for issue in security_issues:
        issue_type = issue.get("type")
        
        if issue_type == "empty_password":
            recommendations.append("Set strong passwords for all database accounts")
        elif issue_type == "weak_auth":
            recommendations.append("Implement multi-factor authentication for database access")
        elif issue_type == "sql_injection":
            recommendations.append("Use prepared statements and parameterized queries")
        elif issue_type == "information_disclosure":
            recommendations.append("Review and restrict database error messages")
        elif issue_type == "default_credentials":
            recommendations.append("Change all default credentials and implement a credential rotation policy")
        elif issue_type == "remote_access":
            recommendations.append("Restrict database access to specific IP ranges and use a VPN for remote access")
        elif issue_type == "privilege_escalation":
            recommendations.append("Implement principle of least privilege for all database accounts")
    
    # Add financial-specific recommendations
    recommendations.extend([
        "Implement database activity monitoring (DAM) for regulatory compliance",
        "Configure data at rest encryption for all financial data",
        "Establish regular database security assessments and audits",
        "Implement database query rate limiting to prevent DoS attacks"
    ])
    
    # Remove duplicates while preserving order
    seen = set()
    unique_recommendations = []
    for item in recommendations:
        if item not in seen:
            seen.add(item)
            unique_recommendations.append(item)
    
    analysis["recommendations"] = unique_recommendations
    
    # Calculate security score (0-100, lower is worse)
    severity_weights = {"critical": 40, "high": 20, "medium": 10, "low": 5}
    penalty = 0
    for severity, count in analysis["summary"].items():
        if severity.endswith("_issues"):
            base_severity = severity.replace("_issues", "")
            if base_severity in severity_weights:
                penalty += count * severity_weights[base_severity]
    
    # Calculate score (100 - penalties, minimum 0)
    analysis["security_score"] = max(0, 100 - penalty)
    
    return analysis
