"""
Financial Impact Analysis Module

This module provides specialized impact analysis for vulnerabilities in financial systems,
evaluating risks according to financial sector security standards and regulatory requirements.
"""

import logging
from typing import Dict, List, Any, Tuple

logger = logging.getLogger("finguardai.financial_impact_analyzer")

# Financial regulations relevant to cybersecurity
FINANCIAL_REGULATIONS = [
    "PCI DSS",    # Payment Card Industry Data Security Standard
    "SOX",        # Sarbanes-Oxley Act
    "GDPR",       # General Data Protection Regulation
    "GLBA",       # Gramm-Leach-Bliley Act
    "Basel III",  # Banking regulations
    "FFIEC",      # Federal Financial Institutions Examination Council
    "NYDFS",      # New York Department of Financial Services Cybersecurity Regulation
]

def calculate_financial_impact(scan_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calculate the financial impact of vulnerabilities in a financial system
    
    Args:
        scan_results: Vulnerability scan results
        
    Returns:
        Dictionary with financial impact analysis
    """
    # Initialize financial impact analysis
    impact = {
        "overall_score": 0,
        "risk_levels": {
            "data_breach": {"score": 0, "level": "low"},
            "operational_disruption": {"score": 0, "level": "low"},
            "regulatory_compliance": {"score": 0, "level": "low"},
            "reputational_damage": {"score": 0, "level": "low"},
            "monetary_loss": {"score": 0, "level": "low"}
        },
        "affected_regulations": [],
        "summary": "",
        "recommendations": []
    }
    
    # Get vulnerabilities from scan results
    vulnerabilities = scan_results.get("vulnerabilities", [])
    
    # Skip analysis if no vulnerabilities found
    if not vulnerabilities:
        impact["summary"] = "No vulnerabilities detected - minimal financial impact expected"
        return impact
    
    # Analyze data breach risk
    data_breach_score = _assess_data_breach_risk(vulnerabilities)
    impact["risk_levels"]["data_breach"]["score"] = data_breach_score
    impact["risk_levels"]["data_breach"]["level"] = _score_to_level(data_breach_score)
    
    # Analyze operational disruption risk
    disruption_score = _assess_operational_disruption(vulnerabilities)
    impact["risk_levels"]["operational_disruption"]["score"] = disruption_score
    impact["risk_levels"]["operational_disruption"]["level"] = _score_to_level(disruption_score)
    
    # Analyze regulatory compliance risk
    compliance_score, affected_regs = _assess_regulatory_compliance(vulnerabilities)
    impact["risk_levels"]["regulatory_compliance"]["score"] = compliance_score
    impact["risk_levels"]["regulatory_compliance"]["level"] = _score_to_level(compliance_score)
    impact["affected_regulations"] = affected_regs
    
    # Analyze reputational damage risk
    reputation_score = _assess_reputational_damage(vulnerabilities, data_breach_score, disruption_score)
    impact["risk_levels"]["reputational_damage"]["score"] = reputation_score
    impact["risk_levels"]["reputational_damage"]["level"] = _score_to_level(reputation_score)
    
    # Analyze monetary loss risk
    monetary_score = _assess_monetary_loss(
        data_breach_score, 
        disruption_score, 
        compliance_score, 
        reputation_score
    )
    impact["risk_levels"]["monetary_loss"]["score"] = monetary_score
    impact["risk_levels"]["monetary_loss"]["level"] = _score_to_level(monetary_score)
    
    # Calculate overall financial risk score (weighted average)
    weights = {
        "data_breach": 0.25,
        "operational_disruption": 0.2,
        "regulatory_compliance": 0.25,
        "reputational_damage": 0.15,
        "monetary_loss": 0.15
    }
    
    overall_score = sum(
        impact["risk_levels"][key]["score"] * weight
        for key, weight in weights.items()
    )
    
    impact["overall_score"] = overall_score
    
    # Generate summary based on overall score
    if overall_score >= 80:
        impact["summary"] = "CRITICAL FINANCIAL RISK: Immediate action required to address severe vulnerabilities with potential for significant financial loss."
    elif overall_score >= 60:
        impact["summary"] = "HIGH FINANCIAL RISK: Urgent attention needed for serious vulnerabilities threatening financial operations and compliance."
    elif overall_score >= 40:
        impact["summary"] = "MODERATE FINANCIAL RISK: Important vulnerabilities present with potential for moderate financial impact."
    elif overall_score >= 20:
        impact["summary"] = "LOW FINANCIAL RISK: Minor vulnerabilities with limited potential financial impact."
    else:
        impact["summary"] = "MINIMAL FINANCIAL RISK: Few or no significant vulnerabilities detected."
    
    # Generate financial-specific recommendations
    impact["recommendations"] = _generate_financial_recommendations(impact)
    
    return impact

def _score_to_level(score: float) -> str:
    """Convert a numerical score to a risk level string"""
    if score >= 80:
        return "critical"
    elif score >= 60:
        return "high"
    elif score >= 40:
        return "medium"
    elif score >= 20:
        return "low"
    else:
        return "minimal"

def _assess_data_breach_risk(vulnerabilities: List[Dict[str, Any]]) -> float:
    """
    Assess the risk of data breach based on vulnerabilities
    
    Returns a score 0-100 where higher means higher risk
    """
    risk_score = 0
    
    # Data breach related vulnerability types
    data_breach_vulns = [
        "sql_injection", "xss", "rce", "path_traversal", 
        "information_disclosure", "authentication_bypass"
    ]
    
    # Count vulnerabilities by severity
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    
    for vuln in vulnerabilities:
        severity = vuln.get("severity", "low")
        vuln_type = vuln.get("type", "").lower()
        
        # Increase count for the appropriate severity
        if severity in severity_counts:
            severity_counts[severity] += 1
        
        # Add extra points for data breach related vulnerabilities
        if any(breach_type in vuln_type for breach_type in data_breach_vulns):
            if severity == "critical":
                risk_score += 15
            elif severity == "high":
                risk_score += 10
            elif severity == "medium":
                risk_score += 5
            else:
                risk_score += 2
    
    # Add base risk from severity counts
    risk_score += severity_counts["critical"] * 12
    risk_score += severity_counts["high"] * 6
    risk_score += severity_counts["medium"] * 3
    risk_score += severity_counts["low"] * 1
    
    # Cap the score at 100
    return min(risk_score, 100)

def _assess_operational_disruption(vulnerabilities: List[Dict[str, Any]]) -> float:
    """
    Assess the risk of operational disruption based on vulnerabilities
    
    Returns a score 0-100 where higher means higher risk
    """
    risk_score = 0
    
    # Operational disruption related vulnerability types
    disruption_vulns = [
        "dos", "ddos", "rce", "service_vulnerability", 
        "resource_exhaustion", "configuration_error"
    ]
    
    for vuln in vulnerabilities:
        severity = vuln.get("severity", "low")
        vuln_type = vuln.get("type", "").lower()
        vuln_desc = vuln.get("description", "").lower()
        
        # Add points for operational disruption vulnerabilities
        if any(disrupt_type in vuln_type for disrupt_type in disruption_vulns):
            if severity == "critical":
                risk_score += 15
            elif severity == "high":
                risk_score += 10
            elif severity == "medium":
                risk_score += 5
            else:
                risk_score += 2
                
        # Check description for disruption-related keywords
        disruption_keywords = ["denial", "availability", "crash", "exhaust", "performance"]
        if any(keyword in vuln_desc for keyword in disruption_keywords):
            if severity == "critical":
                risk_score += 10
            elif severity == "high":
                risk_score += 7
            elif severity == "medium":
                risk_score += 4
            else:
                risk_score += 1
    
    # Cap the score at 100
    return min(risk_score, 100)

def _assess_regulatory_compliance(vulnerabilities: List[Dict[str, Any]]) -> Tuple[float, List[str]]:
    """
    Assess the risk to regulatory compliance based on vulnerabilities
    
    Returns:
        A tuple with (risk_score, affected_regulations)
    """
    risk_score = 0
    affected_regulations = []
    
    # Mapping of vulnerability types to impacted regulations
    vuln_to_regulation = {
        "pci": ["PCI DSS"],
        "gdpr": ["GDPR"],
        "pii": ["GDPR", "GLBA", "SOX"],
        "financial_data": ["PCI DSS", "SOX", "GLBA", "Basel III"],
        "authentication": ["PCI DSS", "NYDFS", "FFIEC"],
        "encryption": ["PCI DSS", "NYDFS", "GDPR", "GLBA"],
        "audit": ["SOX", "Basel III", "NYDFS", "FFIEC"],
        "sql_injection": ["PCI DSS", "NYDFS"],
        "xss": ["PCI DSS", "NYDFS"]
    }
    
    for vuln in vulnerabilities:
        severity = vuln.get("severity", "low")
        vuln_type = vuln.get("type", "").lower()
        vuln_desc = vuln.get("description", "").lower()
        
        # Check for compliance-related keywords
        for keyword, regulations in vuln_to_regulation.items():
            if keyword in vuln_type or keyword in vuln_desc:
                # Add regulations to the affected list
                for reg in regulations:
                    if reg not in affected_regulations:
                        affected_regulations.append(reg)
                
                # Add points based on severity
                if severity == "critical":
                    risk_score += 15
                elif severity == "high":
                    risk_score += 10
                elif severity == "medium":
                    risk_score += 5
                else:
                    risk_score += 2
    
    # Add points based on the number of affected regulations
    risk_score += len(affected_regulations) * 10
    
    # Cap the score at 100
    return min(risk_score, 100), affected_regulations

def _assess_reputational_damage(
    vulnerabilities: List[Dict[str, Any]], 
    data_breach_score: float, 
    disruption_score: float
) -> float:
    """
    Assess the risk of reputational damage based on vulnerabilities
    and other risk factors
    
    Returns a score 0-100 where higher means higher risk
    """
    # Start with a base influenced by data breach and operational disruption
    risk_score = (data_breach_score * 0.6) + (disruption_score * 0.4)
    
    # Add additional points for high-visibility vulnerabilities
    for vuln in vulnerabilities:
        severity = vuln.get("severity", "low")
        vuln_type = vuln.get("type", "").lower()
        
        # High-visibility vulnerability types that could lead to public incidents
        high_visibility = [
            "xss", "sql_injection", "authentication_bypass", "data_leak",
            "hardcoded_credentials", "default_password"
        ]
        
        if any(visible_type in vuln_type for visible_type in high_visibility):
            if severity == "critical":
                risk_score += 8
            elif severity == "high":
                risk_score += 5
            elif severity == "medium":
                risk_score += 2
            
    # Cap the score at 100
    return min(risk_score, 100)

def _assess_monetary_loss(
    data_breach_score: float,
    disruption_score: float,
    compliance_score: float,
    reputation_score: float
) -> float:
    """
    Assess the risk of monetary loss based on other risk factors
    
    Returns a score 0-100 where higher means higher risk
    """
    # Weighted combination of other risk factors
    # Data breaches and compliance issues typically have the highest direct financial impact
    risk_score = (
        data_breach_score * 0.35 +
        compliance_score * 0.3 +
        disruption_score * 0.2 +
        reputation_score * 0.15
    )
    
    return min(risk_score, 100)

def _generate_financial_recommendations(impact: Dict[str, Any]) -> List[str]:
    """
    Generate financial-specific recommendations based on impact assessment
    
    Returns a list of recommendations
    """
    recommendations = []
    
    # Basic financial recommendations
    recommendations.append("Implement a comprehensive incident response plan focused on financial impact mitigation")
    
    # Add data breach recommendations
    data_breach_level = impact["risk_levels"]["data_breach"]["level"]
    if data_breach_level in ["critical", "high"]:
        recommendations.extend([
            "Conduct an immediate data security assessment of all financial systems",
            "Implement advanced data loss prevention (DLP) solutions",
            "Consider cyber insurance coverage specific to financial data breaches",
            "Prepare customer notification and credit monitoring services"
        ])
    elif data_breach_level == "medium":
        recommendations.extend([
            "Review data encryption policies and implementation",
            "Implement additional authentication for accessing sensitive financial data"
        ])
    
    # Add operational disruption recommendations
    disruption_level = impact["risk_levels"]["operational_disruption"]["level"]
    if disruption_level in ["critical", "high"]:
        recommendations.extend([
            "Develop robust business continuity plans for financial operations",
            "Implement redundant systems for critical financial functions",
            "Establish alternate transaction processing capabilities"
        ])
    elif disruption_level == "medium":
        recommendations.append("Review and test disaster recovery procedures for financial systems")
    
    # Add regulatory compliance recommendations
    compliance_level = impact["risk_levels"]["regulatory_compliance"]["level"]
    affected_regs = impact["affected_regulations"]
    
    if compliance_level in ["critical", "high"]:
        recommendations.append("Engage with compliance and legal teams immediately to address regulatory violations")
        
        # Add regulation-specific recommendations
        if "PCI DSS" in affected_regs:
            recommendations.append("Conduct an emergency PCI DSS compliance assessment")
        if "SOX" in affected_regs:
            recommendations.append("Review controls related to financial reporting systems")
        if "GDPR" in affected_regs or "GLBA" in affected_regs:
            recommendations.append("Review and strengthen data privacy controls")
    
    # Add severity-based general recommendations
    overall_score = impact["overall_score"]
    if overall_score >= 60:
        recommendations.extend([
            "Establish a dedicated security budget for high-priority financial system remediation",
            "Consider engaging specialized financial cybersecurity consultants",
            "Implement enhanced transaction monitoring for fraud detection"
        ])
    
    # Always include these recommendations
    recommendations.extend([
        "Maintain appropriate cyber insurance coverage for financial institutions",
        "Conduct regular security awareness training for financial staff",
        "Implement a vulnerability management program aligned with financial compliance requirements"
    ])
    
    return recommendations
