"""
Web Server and Application Security Analysis Module

This module provides functions to analyze web server and application security issues
identified during scanning.
"""

import re
import logging
from typing import Dict, List, Any

logger = logging.getLogger("finguardai.web_security_analyzer")

def analyze_web_security(scan_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze web server and application security issues in scan results
    
    Args:
        scan_results: Vulnerability scan results
        
    Returns:
        Dictionary with web security analysis
    """
    # Initialize analysis structure
    analysis = {
        "web_servers": [],
        "security_issues": [],
        "ssl_issues": [],
        "http_headers": {},
        "summary": {
            "critical_issues": 0,
            "high_issues": 0,
            "medium_issues": 0,
            "low_issues": 0
        },
        "security_score": 0,
        "recommendations": []
    }
    
    # Detect web servers
    open_ports = scan_results.get("open_ports", {})
    vulnerabilities = scan_results.get("vulnerabilities", [])
    ssl_details = scan_results.get("ssl_details", {})
    
    # Web server ports
    web_ports = ["80", "443", "8080", "8443", "8000", "8008", "8888"]
    
    # Identify active web servers
    active_web_servers = []
    for port, details in open_ports.items():
        if port in web_ports:
            service_name = details.get("name", "")
            product = details.get("product", "")
            version = details.get("version", "")
            
            # Only include if it's actually a web server
            if (service_name.lower() in ["http", "https"] or 
                any(ws in product.lower() for ws in ["apache", "nginx", "iis", "lighttpd", "tomcat"])):
                
                # Compile web server info
                web_server = {
                    "port": port,
                    "service": service_name,
                    "product": product,
                    "version": version
                }
                active_web_servers.append(web_server)
                analysis["web_servers"].append(web_server)
    
    if not active_web_servers:
        analysis["summary"]["message"] = "No web server services detected"
        return analysis
    
    # Analyze web-specific vulnerabilities
    security_issues = []
    web_vuln_patterns = {
        "xss": (r"xss|cross.?site.?script", "high"),
        "csrf": (r"csrf|cross.?site.?request.?forg", "high"),
        "sqli": (r"sql.?injection", "critical"),
        "rce": (r"remote.?code.?execution|command.?injection|rce", "critical"),
        "path_traversal": (r"path.?traversal|directory.?traversal", "high"),
        "information_disclosure": (r"information.?disclosure|data.?leak", "medium"),
        "clickjacking": (r"clickjack", "medium"),
        "http_methods": (r"http.?methods", "low"),
        "ssl_weak": (r"ssl|tls|weak.?cipher|weak.?protocol", "high"),
        "shellshock": (r"shellshock|bash.?vulnerability", "critical")
    }
    
    # Process each vulnerability for web relevance
    for vuln in vulnerabilities:
        vuln_desc = vuln.get("description", "").lower()
        vuln_name = vuln.get("name", "").lower()
        vuln_port = vuln.get("port", "")
        
        # Skip if not related to web ports
        if vuln_port not in web_ports and str(vuln_port) not in web_ports:
            continue
        
        # Check against known web vulnerability patterns
        matched = False
        for issue_type, (pattern, severity) in web_vuln_patterns.items():
            if re.search(pattern, vuln_desc) or re.search(pattern, vuln_name):
                web_vuln = {
                    "type": issue_type,
                    "severity": severity,
                    "description": vuln.get("description", ""),
                    "name": vuln.get("name", ""),
                    "port": vuln_port
                }
                security_issues.append(web_vuln)
                
                # Update severity counts
                analysis["summary"][f"{severity}_issues"] += 1
                matched = True
                break
        
        # If no pattern matched but it's on a web port, add as general web issue
        if not matched:
            web_vuln = {
                "type": "general_web",
                "severity": vuln.get("severity", "medium"),
                "description": vuln.get("description", ""),
                "name": vuln.get("name", ""),
                "port": vuln_port
            }
            security_issues.append(web_vuln)
            
            # Update severity counts for general issue
            severity = vuln.get("severity", "medium")
            analysis["summary"][f"{severity}_issues"] += 1
    
    # Process SSL issues
    if ssl_details:
        # Check for self-signed certificate
        if ssl_details.get("self_signed", False):
            ssl_issue = {
                "type": "self_signed_cert",
                "severity": "high",
                "description": "Self-signed SSL certificate detected",
                "port": "443"
            }
            analysis["ssl_issues"].append(ssl_issue)
            analysis["summary"]["high_issues"] += 1
        
        # Check for expired or almost expired certificate
        import datetime
        valid_to = ssl_details.get("valid_to", "")
        try:
            if valid_to:
                # Parse the date - adapt this to match your date format
                expiry_date = datetime.datetime.strptime(valid_to.split("T")[0], "%Y-%m-%d")
                today = datetime.datetime.now()
                days_to_expiry = (expiry_date - today).days
                
                if days_to_expiry <= 0:
                    ssl_issue = {
                        "type": "expired_cert",
                        "severity": "critical",
                        "description": f"SSL certificate has expired on {valid_to}",
                        "port": "443"
                    }
                    analysis["ssl_issues"].append(ssl_issue)
                    analysis["summary"]["critical_issues"] += 1
                elif days_to_expiry <= 30:
                    ssl_issue = {
                        "type": "expiring_cert",
                        "severity": "high",
                        "description": f"SSL certificate expires soon ({days_to_expiry} days)",
                        "port": "443"
                    }
                    analysis["ssl_issues"].append(ssl_issue)
                    analysis["summary"]["high_issues"] += 1
        except:
            # Date parsing error - ignore
            pass
    
    # Add security issues to analysis
    analysis["security_issues"] = security_issues
    
    # Generate recommendations
    recommendations = []
    
    # Base recommendations based on detected issues
    issue_types = {issue["type"] for issue in security_issues}
    ssl_issue_types = {issue["type"] for issue in analysis["ssl_issues"]}
    
    # Issue-specific recommendations
    if "xss" in issue_types:
        recommendations.extend([
            "Implement Content Security Policy (CSP) headers",
            "Use appropriate output encoding for user-supplied content",
            "Validate and sanitize all user inputs"
        ])
    
    if "csrf" in issue_types:
        recommendations.extend([
            "Implement anti-CSRF tokens for all state-changing operations",
            "Use SameSite cookie attributes to restrict cross-site requests"
        ])
    
    if "sqli" in issue_types:
        recommendations.extend([
            "Use parameterized queries or prepared statements for all database operations",
            "Implement least privilege database accounts for web applications",
            "Consider a web application firewall to block SQL injection attempts"
        ])
    
    if "rce" in issue_types:
        recommendations.extend([
            "Sanitize and validate all inputs used in system commands",
            "Avoid using system command functions in web applications",
            "Implement proper input validation and sanitization"
        ])
    
    if "path_traversal" in issue_types:
        recommendations.extend([
            "Validate file paths and use proper canonicalization",
            "Implement proper access controls for file operations",
            "Avoid passing user-supplied input to file operations"
        ])
    
    # SSL recommendations
    if ssl_issue_types:
        recommendations.extend([
            "Deploy properly signed SSL certificates from trusted certificate authorities",
            "Configure proper SSL/TLS protocols (TLS 1.2+ only)",
            "Implement strong cipher suites and disable weak ciphers",
            "Use HSTS headers to enforce HTTPS"
        ])
    
    if "self_signed_cert" in ssl_issue_types:
        recommendations.append("Replace self-signed certificates with certificates from trusted CAs")
    
    if "expired_cert" in ssl_issue_types or "expiring_cert" in ssl_issue_types:
        recommendations.append("Renew SSL certificates and implement automated certificate monitoring")
    
    # General security recommendations
    recommendations.extend([
        "Implement proper HTTP security headers (X-Content-Type-Options, X-Frame-Options, etc.)",
        "Keep web servers and applications updated with security patches",
        "Use a web application firewall (WAF) to protect against common attacks",
        "Implement proper logging and monitoring for web applications",
        "Conduct regular security testing and code reviews"
    ])
    
    # Add financial-specific recommendations
    recommendations.extend([
        "Implement multi-factor authentication for all financial operations",
        "Use proper session management with secure, HttpOnly, and SameSite cookies",
        "Implement transaction signing for critical financial operations",
        "Consider implementing behavioral analysis to detect account takeover attempts",
        "Ensure compliance with PCI DSS requirements for handling payment card data"
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
