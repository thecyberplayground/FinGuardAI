"""
CVSS Vector Analyzer for NVD Vulnerabilities

This module provides enhanced analysis of CVSS vectors from NVD data,
extracting detailed information about vulnerability characteristics.
"""

import re
import logging
from typing import Dict, Any, Optional, List, Tuple

# Configure logging
logger = logging.getLogger("finguardai.cvss_analyzer")

# CVSS v3.1 Vector Components
CVSS_V3_COMPONENTS = {
    # Attack Vector
    "AV": {
        "N": {"name": "Network", "description": "Exploitable remotely across network", "value": 0.85},
        "A": {"name": "Adjacent", "description": "Exploitable from adjacent network", "value": 0.62},
        "L": {"name": "Local", "description": "Requires local access", "value": 0.55},
        "P": {"name": "Physical", "description": "Requires physical access", "value": 0.2}
    },
    # Attack Complexity
    "AC": {
        "L": {"name": "Low", "description": "No specialized conditions needed", "value": 0.77},
        "H": {"name": "High", "description": "Specific conditions must exist", "value": 0.44}
    },
    # Privileges Required
    "PR": {
        "N": {"name": "None", "description": "No privileges required", "value": 0.85},
        "L": {"name": "Low", "description": "Low-level privileges required", "value": 0.62},
        "H": {"name": "High", "description": "High-level privileges required", "value": 0.27}
    },
    # User Interaction
    "UI": {
        "N": {"name": "None", "description": "No user interaction required", "value": 0.85},
        "R": {"name": "Required", "description": "User interaction required", "value": 0.62}
    },
    # Scope
    "S": {
        "U": {"name": "Unchanged", "description": "Vulnerability affects only containing system", "value": 0.0},
        "C": {"name": "Changed", "description": "Vulnerability affects beyond the containing system", "value": 1.0}
    },
    # Confidentiality
    "C": {
        "H": {"name": "High", "description": "Complete information disclosure", "value": 0.56},
        "L": {"name": "Low", "description": "Some information disclosure", "value": 0.22},
        "N": {"name": "None", "description": "No impact to confidentiality", "value": 0.0}
    },
    # Integrity
    "I": {
        "H": {"name": "High", "description": "Complete system integrity compromise", "value": 0.56},
        "L": {"name": "Low", "description": "Limited integrity impact", "value": 0.22},
        "N": {"name": "None", "description": "No impact to integrity", "value": 0.0}
    },
    # Availability
    "A": {
        "H": {"name": "High", "description": "Complete system availability compromise", "value": 0.56},
        "L": {"name": "Low", "description": "Limited availability impact", "value": 0.22},
        "N": {"name": "None", "description": "No impact to availability", "value": 0.0}
    }
}

def parse_cvss_vector(vector_string: str) -> Dict[str, Any]:
    """
    Parse CVSS vector string into component values
    
    Args:
        vector_string: CVSS vector string (e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
        
    Returns:
        Dictionary with parsed components and metadata
    """
    if not vector_string:
        return {"error": "Empty vector string"}
    
    try:
        # Determine CVSS version
        version = "unknown"
        if "CVSS:3.1" in vector_string:
            version = "3.1"
        elif "CVSS:3.0" in vector_string:
            version = "3.0"
        elif "CVSS:2.0" in vector_string:
            version = "2.0"
        
        # Parse the components
        components = {}
        vector_parts = vector_string.split("/")
        
        for part in vector_parts:
            if ":" in part:
                key, value = part.split(":", 1)
                if key and value:
                    components[key] = value
        
        # Build result
        result = {
            "version": version,
            "components": components,
            "parsed": {}
        }
        
        # Parse component meanings (for v3.x)
        if version in ["3.0", "3.1"]:
            for key, value in components.items():
                if key in CVSS_V3_COMPONENTS and value in CVSS_V3_COMPONENTS[key]:
                    result["parsed"][key] = {
                        "value": value,
                        "name": CVSS_V3_COMPONENTS[key][value]["name"],
                        "description": CVSS_V3_COMPONENTS[key][value]["description"],
                        "numeric_value": CVSS_V3_COMPONENTS[key][value]["value"]
                    }
        
        return result
    
    except Exception as e:
        logger.error(f"Error parsing CVSS vector: {e}")
        return {"error": f"Failed to parse vector: {str(e)}"}

def get_attack_surface_recommendations(cvss_data: Dict[str, Any]) -> List[str]:
    """
    Generate attack surface reduction recommendations based on CVSS vector
    
    Args:
        cvss_data: Parsed CVSS data from parse_cvss_vector
        
    Returns:
        List of recommendations
    """
    recommendations = []
    components = cvss_data.get("parsed", {})
    
    # Attack Vector recommendations
    if components.get("AV", {}).get("value") == "N":
        recommendations.append("Implement network segmentation to restrict remote access")
        recommendations.append("Deploy web application firewall for internet-facing services")
        recommendations.append("Use IP allowlisting for administrative interfaces")
    
    # Attack Complexity
    if components.get("AC", {}).get("value") == "L":
        recommendations.append("Implement defense-in-depth measures as vulnerability is easily exploitable")
        recommendations.append("Apply the principle of least privilege across systems")
    
    # Privileges Required
    if components.get("PR", {}).get("value") == "N":
        recommendations.append("Enable multi-factor authentication for all access points")
        recommendations.append("Implement strict access controls and boundary protections")
    
    # User Interaction
    if components.get("UI", {}).get("value") == "N":
        recommendations.append("Deploy automated vulnerability scanning and patching systems")
        recommendations.append("Implement zero-trust security model")
    
    # Scope considerations
    if components.get("S", {}).get("value") == "C":
        recommendations.append("Implement strong isolation between system components")
        recommendations.append("Deploy system integrity monitoring")
    
    # Impact considerations - Confidentiality
    if components.get("C", {}).get("value") == "H":
        recommendations.append("Encrypt sensitive data at rest and in transit")
        recommendations.append("Implement data loss prevention systems")
    
    # Impact considerations - Integrity
    if components.get("I", {}).get("value") == "H":
        recommendations.append("Implement file integrity monitoring")
        recommendations.append("Deploy digital signing for critical transactions")
    
    # Impact considerations - Availability
    if components.get("A", {}).get("value") == "H":
        recommendations.append("Implement redundancy and high availability configurations")
        recommendations.append("Deploy DDoS protection services")
    
    return recommendations

def assess_financial_impact(cvss_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Assess financial impact of vulnerability based on CVSS vector
    
    Args:
        cvss_data: Parsed CVSS data from parse_cvss_vector
        
    Returns:
        Dictionary with financial impact assessment
    """
    components = cvss_data.get("parsed", {})
    
    # Initialize impact areas
    impact = {
        "data_breach_risk": "low",
        "operational_disruption": "low",
        "financial_loss_potential": "low",
        "regulatory_risk": "low",
        "remediation_complexity": "low",
        "overall_financial_risk": "low"
    }
    
    # Determine data breach risk
    if components.get("C", {}).get("value") == "H":
        impact["data_breach_risk"] = "high"
    elif components.get("C", {}).get("value") == "L":
        impact["data_breach_risk"] = "medium"
    
    # Determine operational disruption
    if components.get("A", {}).get("value") == "H":
        impact["operational_disruption"] = "high"
    elif components.get("A", {}).get("value") == "L":
        impact["operational_disruption"] = "medium"
    
    # Determine financial loss potential
    c_value = "N"
    i_value = "N"
    a_value = "N"
    
    if "C" in components:
        c_value = components["C"].get("value", "N")
    if "I" in components:
        i_value = components["I"].get("value", "N")
    if "A" in components:
        a_value = components["A"].get("value", "N")
    
    # High financial loss if high impact on at least two areas
    high_impact_count = sum(1 for x in [c_value, i_value, a_value] if x == "H")
    medium_impact_count = sum(1 for x in [c_value, i_value, a_value] if x == "L")
    
    if high_impact_count >= 2:
        impact["financial_loss_potential"] = "high"
    elif high_impact_count == 1 or medium_impact_count >= 2:
        impact["financial_loss_potential"] = "medium"
    
    # Determine regulatory risk
    if components.get("C", {}).get("value") == "H" or components.get("I", {}).get("value") == "H":
        impact["regulatory_risk"] = "high"
    elif components.get("C", {}).get("value") == "L" or components.get("I", {}).get("value") == "L":
        impact["regulatory_risk"] = "medium"
    
    # Determine remediation complexity
    # Higher attack complexity usually means harder remediation
    if components.get("AC", {}).get("value") == "H":
        impact["remediation_complexity"] = "high"
    elif components.get("S", {}).get("value") == "C":
        impact["remediation_complexity"] = "medium"
    
    # Calculate overall financial risk
    risk_values = {"low": 1, "medium": 2, "high": 3}
    total_risk = sum(risk_values[v] for v in impact.values() if v in risk_values)
    avg_risk = total_risk / (len(impact) - 1)  # Exclude the overall_financial_risk
    
    if avg_risk > 2.5:
        impact["overall_financial_risk"] = "high"
    elif avg_risk > 1.5:
        impact["overall_financial_risk"] = "medium"
    else:
        impact["overall_financial_risk"] = "low"
    
    return impact

def extract_cvss_from_vulnerability(vulnerability: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract CVSS data from an NVD vulnerability
    
    Args:
        vulnerability: Vulnerability data from NVD API
        
    Returns:
        Dictionary with CVSS data
    """
    result = {
        "cvss_v31": None,
        "cvss_v30": None,
        "cvss_v2": None,
        "vector_string": None,
        "base_score": None,
        "base_severity": None,
        "analysis": None
    }
    
    try:
        metrics = vulnerability.get("metrics", {})
        
        # Try CVSS v3.1 first
        if metrics.get("cvssMetricV31"):
            cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
            result["cvss_v31"] = cvss_data
            result["vector_string"] = cvss_data.get("vectorString")
            result["base_score"] = cvss_data.get("baseScore")
            result["base_severity"] = cvss_data.get("baseSeverity")
        
        # Try CVSS v3.0 next
        elif metrics.get("cvssMetricV30"):
            cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
            result["cvss_v30"] = cvss_data
            result["vector_string"] = cvss_data.get("vectorString")
            result["base_score"] = cvss_data.get("baseScore")
            result["base_severity"] = cvss_data.get("baseSeverity")
        
        # Try CVSS v2.0 last
        elif metrics.get("cvssMetricV2"):
            cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
            result["cvss_v2"] = cvss_data
            result["vector_string"] = cvss_data.get("vectorString")
            result["base_score"] = cvss_data.get("baseScore")
            result["base_severity"] = "N/A"  # CVSS v2 doesn't have named severity
        
        # If we have a vector string, parse it
        if result["vector_string"]:
            parsed_data = parse_cvss_vector(result["vector_string"])
            result["analysis"] = parsed_data
            
            # Add recommendations if parsed successfully
            if "error" not in parsed_data:
                result["recommendations"] = get_attack_surface_recommendations(parsed_data)
                result["financial_impact"] = assess_financial_impact(parsed_data)
    
    except Exception as e:
        logger.error(f"Error extracting CVSS data: {e}")
        result["error"] = str(e)
    
    return result
