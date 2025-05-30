"""
FinGuardAI - Security Remediation Recommendations

This module provides actionable security recommendations based on detected threats
and vulnerabilities. It maps threat types to specific remediation actions tailored
for financial sector organizations.
"""

import logging
from typing import Dict, List, Any, Optional, Set
import os
import json

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('finguardai.remediation')

# Try to import financial recommendations
try:
    from .financial_recommendations import get_financial_recommendations
    HAS_FINANCIAL_RECOMMENDATIONS = True
    logger.info("Financial sector specific recommendations loaded successfully")
except ImportError:
    HAS_FINANCIAL_RECOMMENDATIONS = False
    logger.warning("Financial sector recommendations not available. Using general recommendations only.")

# Load remediation knowledge base
REMEDIATION_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'remediation_db.json')

class RemediationEngine:
    """Provides security remediation recommendations for detected threats"""
    
    def __init__(self, kb_path: str = REMEDIATION_DB_PATH):
        """
        Initialize the remediation engine
        
        Args:
            kb_path: Path to the remediation knowledge base JSON file
        """
        self.knowledge_base = {}
        self.load_knowledge_base(kb_path)
    
    def load_knowledge_base(self, kb_path: str) -> bool:
        """
        Load the remediation knowledge base from a JSON file
        
        Args:
            kb_path: Path to the knowledge base file
        
        Returns:
            True if loaded successfully, False otherwise
        """
        try:
            if os.path.exists(kb_path):
                with open(kb_path, 'r') as f:
                    self.knowledge_base = json.load(f)
                logger.info(f"Loaded remediation knowledge base from {kb_path}")
                return True
            else:
                # Use default built-in knowledge base if file doesn't exist
                self.knowledge_base = self._create_default_knowledge_base()
                
                # Save it for future use
                os.makedirs(os.path.dirname(kb_path), exist_ok=True)
                with open(kb_path, 'w') as f:
                    json.dump(self.knowledge_base, f, indent=2)
                
                logger.info(f"Created default remediation knowledge base at {kb_path}")
                return True
                
        except Exception as e:
            logger.error(f"Error loading remediation knowledge base: {e}")
            # Fall back to default knowledge base
            self.knowledge_base = self._create_default_knowledge_base()
            return False
    
    def _create_default_knowledge_base(self) -> Dict:
        """
        Create a default remediation knowledge base
        
        Returns:
            Dictionary of threat types mapped to remediation actions
        """
        return {
            "network_scan": {
                "name": "Network Scanning Activity",
                "description": "Systematic probing of network services and ports",
                "indicators": [
                    "Multiple connection attempts to different ports",
                    "Sequential IP address access",
                    "Low packet sizes with TCP SYN flags",
                    "High error rates"
                ],
                "severity": "medium",
                "financial_impact": "Can lead to unauthorized access to financial systems",
                "remediation_steps": [
                    "Implement connection rate limiting",
                    "Configure firewall to block suspicious scanning IPs",
                    "Enable scan detection alerts",
                    "Consider implementing network segmentation"
                ],
                "regulations": ["PCI-DSS 11.4", "ISO 27001 A.13.1"]
            },
            "dos_attack": {
                "name": "Denial of Service Attack",
                "description": "Attempt to overwhelm services by flooding them with traffic",
                "indicators": [
                    "Abnormally high traffic volume",
                    "Many similar packets in short time",
                    "Traffic from unusual sources",
                    "Unusual packet fragmentation"
                ],
                "severity": "high",
                "financial_impact": "Service disruption leading to financial transaction failures",
                "remediation_steps": [
                    "Implement DDoS protection services",
                    "Configure traffic rate limiting",
                    "Set up traffic filtering based on analysis of attack",
                    "Configure your network to handle traffic spikes",
                    "Ensure high availability and failover systems"
                ],
                "regulations": ["PCI-DSS 6.5.10", "ISO 27001 A.13.1", "FFIEC Information Security"]
            },
            "brute_force": {
                "name": "Authentication Brute Force",
                "description": "Repeated login attempts to guess credentials",
                "indicators": [
                    "Multiple failed login attempts",
                    "Authentication requests at high frequency",
                    "Systematic pattern in authentication attempts"
                ],
                "severity": "high",
                "financial_impact": "Potential unauthorized access to financial accounts and systems",
                "remediation_steps": [
                    "Implement account lockout policies",
                    "Add CAPTCHA or other anti-automation measures",
                    "Enforce strong password requirements",
                    "Implement multi-factor authentication",
                    "Monitor and alert on abnormal login patterns"
                ],
                "regulations": ["PCI-DSS 8.1.6", "ISO 27001 A.9.4", "NIST 800-53 IA-5"]
            },
            "data_exfiltration": {
                "name": "Data Exfiltration Attempt",
                "description": "Suspicious outbound data transfers that may indicate data theft",
                "indicators": [
                    "Unusual large outbound data transfers",
                    "Communications to uncommon destinations",
                    "Encrypted traffic to non-standard ports",
                    "Unusual access patterns to sensitive data"
                ],
                "severity": "critical",
                "financial_impact": "Data breaches leading to financial loss, regulatory fines, and reputation damage",
                "remediation_steps": [
                    "Implement Data Loss Prevention (DLP) solutions",
                    "Configure egress filtering at network boundaries",
                    "Monitor and baseline normal data movement patterns",
                    "Encrypt sensitive data in transit and at rest",
                    "Implement least privilege access controls"
                ],
                "regulations": ["GDPR Art. 32", "PCI-DSS 4.1", "ISO 27001 A.13.2", "GLBA Safeguards Rule"]
            },
            "suspicious_connections": {
                "name": "Suspicious Network Connections",
                "description": "Unusual network activity that doesn't match normal patterns",
                "indicators": [
                    "Connections to known malicious IPs/domains",
                    "Unusual protocols or port usage",
                    "Connections at unusual times",
                    "Abnormal data transfer patterns"
                ],
                "severity": "medium",
                "financial_impact": "Potential data leakage or command-and-control activity for financial fraud",
                "remediation_steps": [
                    "Block connections to known malicious destinations",
                    "Implement network behavior analysis",
                    "Review and tighten firewall rules",
                    "Deploy intrusion prevention systems",
                    "Consider zero trust network architecture"
                ],
                "regulations": ["PCI-DSS 1.3", "ISO 27001 A.13.1.1", "FFIEC Information Security"]
            },
            "protocol_abuse": {
                "name": "Protocol Misuse/Abuse",
                "description": "Exploitation of network protocols for malicious purposes",
                "indicators": [
                    "Protocol behavior outside normal specifications",
                    "Unusual flags or packet structures",
                    "Tunneling through allowed protocols"
                ],
                "severity": "medium",
                "financial_impact": "Can enable covert communication channels for data theft",
                "remediation_steps": [
                    "Implement deep packet inspection",
                    "Configure protocol validation at network boundaries",
                    "Use application-layer gateways rather than simple packet filters",
                    "Monitor protocol usage patterns for anomalies"
                ],
                "regulations": ["PCI-DSS 4.1", "ISO 27001 A.13.2.1"]
            },
            "web_attack": {
                "name": "Web Application Attack",
                "description": "Attempts to exploit vulnerabilities in web applications",
                "indicators": [
                    "SQL injection patterns in requests",
                    "Cross-site scripting (XSS) attempts",
                    "Command injection patterns",
                    "Path traversal attempts",
                    "Unusual request parameters"
                ],
                "severity": "high",
                "financial_impact": "Compromise of web banking interfaces, financial fraud",
                "remediation_steps": [
                    "Implement a Web Application Firewall (WAF)",
                    "Keep web applications patched and updated",
                    "Perform regular security testing of applications",
                    "Validate all input and implement proper output encoding",
                    "Implement strong Content Security Policy (CSP)"
                ],
                "regulations": ["PCI-DSS 6.6", "ISO 27001 A.14.2", "OWASP Top 10"]
            },
            "malware": {
                "name": "Malware Activity",
                "description": "Signs of malware infection or communication",
                "indicators": [
                    "Known malware communication patterns",
                    "Suspicious executable downloads",
                    "Unusual system behavior",
                    "Communication with known command-and-control servers"
                ],
                "severity": "critical",
                "financial_impact": "Financial fraud, theft of banking credentials, ransomware",
                "remediation_steps": [
                    "Deploy endpoint protection platforms (EPP)",
                    "Implement endpoint detection and response (EDR)",
                    "Keep systems patched and updated",
                    "Use application allowlisting in critical financial environments",
                    "Establish malware incident response procedures"
                ],
                "regulations": ["PCI-DSS 5.1", "ISO 27001 A.12.2", "FFIEC Information Security"]
            },
            "insider_threat": {
                "name": "Insider Threat Activity",
                "description": "Suspicious actions that may indicate malicious insider activity",
                "indicators": [
                    "Unusual access to sensitive financial data",
                    "Accessing systems outside normal business hours",
                    "Unusual data access patterns",
                    "Excessive privilege usage"
                ],
                "severity": "high",
                "financial_impact": "Fraud, unauthorized transactions, data theft",
                "remediation_steps": [
                    "Implement least privilege access controls",
                    "Deploy user behavior analytics (UBA)",
                    "Create separation of duties for critical financial functions",
                    "Implement privileged access management",
                    "Conduct regular access reviews"
                ],
                "regulations": ["SOX Section 404", "ISO 27001 A.9", "FFIEC Information Security"]
            }
        }
    
    def get_threat_types(self) -> List[str]:
        """
        Get all supported threat types
        
        Returns:
            List of threat type identifiers
        """
        return list(self.knowledge_base.keys())
    
    def get_remediation_by_threat_type(self, threat_type: str) -> Dict:
        """
        Get remediation recommendations for a specific threat type
        
        Args:
            threat_type: The type of threat
            
        Returns:
            Dictionary with remediation information or empty dict if not found
        """
        return self.knowledge_base.get(threat_type, {})
    
    def _match_indicators_to_threats(self, indicators: Dict[str, Any]) -> List[str]:
        """
        Match observed indicators to potential threat types
        
        Args:
            indicators: Dictionary of observed indicators
            
        Returns:
            List of matching threat types
        """
        matching_threats = []
        
        # Extract relevant data from indicators
        protocol = indicators.get('protocol', '').lower()
        error_rate = indicators.get('error_rate', 0)
        wrong_fragment = indicators.get('wrong_fragment', 0)
        packet_size = indicators.get('packet_size', 0)
        tcp_flags = indicators.get('tcp_flags', '')
        count = indicators.get('count', 0)
        
        # Match network scanning
        if (protocol == 'tcp' and 'S' in tcp_flags and count > 50 and 
            packet_size < 100 and error_rate > 0.3):
            matching_threats.append('network_scan')
        
        # Match DoS attacks
        if count > 500 or (error_rate > 0.5 and count > 100):
            matching_threats.append('dos_attack')
        
        # Match protocol abuse
        if wrong_fragment > 0 or (protocol == 'tcp' and len(tcp_flags) > 3):
            matching_threats.append('protocol_abuse')
        
        # Match suspicious connections (generic)
        if error_rate > 0.7 or wrong_fragment > 0:
            matching_threats.append('suspicious_connections')
        
        # If no specific matches but is considered a threat
        if not matching_threats and indicators.get('is_threat', False):
            matching_threats.append('suspicious_connections')
        
        return matching_threats
    
    def generate_recommendations(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate remediation recommendations based on threat data
        
        Args:
            threat_data: Dictionary containing threat detection results
            
        Returns:
            Dictionary with remediation recommendations
        """
        # Initialize response
        recommendations = {
            'recommendations': [],
            'threat_types': [],
            'severity': 'low',
            'regulations': []
        }
        
        # Get basic threat info
        is_threat = threat_data.get('is_threat', False)
        probability = threat_data.get('threat_probability', 0.0)
        
        # If not a threat, return minimal response
        if not is_threat and probability < 0.3:
            recommendations['recommendations'] = ['No significant threats detected - maintain normal security measures']
            return recommendations
        
        # Identify threat types based on indicators
        threat_types = self._match_indicators_to_threats(threat_data)
        
        # If no specific threat type identified, use threat level to suggest general recommendations
        if not threat_types:
            threat_level = threat_data.get('threat_level', 'low')
            if threat_level == 'high' or threat_level == 'critical':
                threat_types = ['suspicious_connections']
            elif threat_level == 'medium':
                threat_types = ['protocol_abuse']
            else:
                # For low threats, still provide basic recommendations
                recommendations['recommendations'] = [
                    'Monitor for pattern changes',
                    'Review network security baseline',
                    'Ensure all systems are updated and patched'
                ]
                return recommendations
        
        # Collect recommendations from each matching threat type
        all_recommendations = []
        all_regulations = []
        severity_levels = []
        financial_impacts = []
        details = []
        
        for threat_type in threat_types:
            remediation_info = self.get_remediation_by_threat_type(threat_type)
            if remediation_info:
                all_recommendations.extend(remediation_info.get('remediation_steps', []))
                all_regulations.extend(remediation_info.get('regulations', []))
                severity_levels.append(remediation_info.get('severity', 'low'))
                financial_impacts.append(remediation_info.get('financial_impact', ''))
                
                # Add threat details
                details.append({
                    'type': threat_type,
                    'name': remediation_info.get('name', threat_type),
                    'description': remediation_info.get('description', ''),
                    'indicators': remediation_info.get('indicators', []),
                    'severity': remediation_info.get('severity', 'low')
                })
        
        # Determine highest severity
        severity_map = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        highest_severity = max([severity_map.get(level, 0) for level in severity_levels], default=1)
        severity_reverse_map = {1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}
        
        # Build general recommendations response
        recommendations['threat_types'] = threat_types
        recommendations['severity'] = severity_reverse_map.get(highest_severity, 'low')
        recommendations['recommendations'] = list(dict.fromkeys(all_recommendations))  # Remove duplicates
        recommendations['regulations'] = list(dict.fromkeys(all_regulations))  # Remove duplicates
        recommendations['financial_impact'] = ' '.join(financial_impacts)
        recommendations['details'] = details
        
        # Add financial sector specific recommendations if available
        global HAS_FINANCIAL_RECOMMENDATIONS  # Access the global variable
        if HAS_FINANCIAL_RECOMMENDATIONS and is_threat:
            try:
                # Import the function here to avoid circular imports
                from .financial_recommendations import get_financial_recommendations
                financial_recs = get_financial_recommendations(threat_data)
                
                # Only enhance with financial recommendations if we have matches
                if financial_recs and financial_recs.get('financial_threat_types'):
                    finance_types = financial_recs.get('financial_threat_types', [])
                    if finance_types:
                        # Add finance-specific threat types
                        recommendations['finance_threat_types'] = finance_types
                        
                        # Add these to regular threat types too
                        for ft in finance_types:
                            if ft not in recommendations['threat_types']:
                                recommendations['threat_types'].append(ft)
                    
                    # Financial specific remediations (more precise than general ones)
                    critical_remediations = financial_recs.get('critical_remediations', [])
                    if critical_remediations:
                        # These are specific to financial sector, prioritize them
                        financial_specific_recommendations = critical_remediations.copy()
                        
                        # Get technical controls which are even more specific
                        tech_controls = financial_recs.get('technical_controls', [])
                        if tech_controls:
                            financial_specific_recommendations.extend(tech_controls)
                        
                        # Replace generic recommendations with financial-specific ones
                        # but keep some general recommendations that don't overlap
                        final_recommendations = []
                        
                        # Start with all financial-specific recommendations
                        final_recommendations.extend(financial_specific_recommendations)
                        
                        # Add general recommendations that don't seem to overlap
                        for rec in recommendations['recommendations']:
                            # Simple heuristic: if no word overlap of 3+ words with any financial rec
                            if not any(self._significant_overlap(rec, fin_rec) for fin_rec in financial_specific_recommendations):
                                final_recommendations.append(rec)
                                
                                # Don't add too many general recommendations
                                if len(final_recommendations) >= 15:  # Limit total recommendations
                                    break
                        
                        # Update with our enhanced recommendations
                        recommendations['recommendations'] = final_recommendations
                    
                    # Add regulatory information if available
                    fin_regulations = financial_recs.get('regulatory_requirements', [])
                    if fin_regulations:
                        # Extract regulation information in consistent format
                        for reg in fin_regulations:
                            if isinstance(reg, dict) and 'name' in reg and 'section' in reg:
                                reg_str = f"{reg['name']} {reg['section']}"
                                if reg_str not in recommendations['regulations']:
                                    recommendations['regulations'].append(reg_str)
                    
                    # Take highest severity between general and financial
                    fin_severity = financial_recs.get('severity', 'low')
                    fin_severity_value = severity_map.get(fin_severity, 1)
                    if fin_severity_value > highest_severity:
                        recommendations['severity'] = fin_severity
                    
                    # Add financial impact if available
                    if financial_recs.get('financial_impact'):
                        if recommendations.get('financial_impact'):
                            recommendations['financial_impact'] += ' ' + financial_recs.get('financial_impact')
                        else:
                            recommendations['financial_impact'] = financial_recs.get('financial_impact')
                    
                    # Mark as having financial-specific recommendations
                    recommendations['finance_specific'] = True
            except Exception as e:
                logger.error(f"Error incorporating financial recommendations: {e}")
        
        return recommendations
        
    def _significant_overlap(self, str1: str, str2: str) -> bool:
        """
        Check if two strings have significant word overlap
        
        Args:
            str1: First string
            str2: Second string
            
        Returns:
            True if significant overlap, False otherwise
        """
        # Simple implementation - check for 3+ word match sequences
        words1 = str1.lower().split()
        words2 = str2.lower().split()
        
        # If either string has fewer than 3 words, check for exact matches
        if len(words1) < 3 or len(words2) < 3:
            return str1.lower() == str2.lower()
        
        # Check for sequences of 3 words that match
        for i in range(len(words1) - 2):
            three_word_seq = ' '.join(words1[i:i+3])
            if three_word_seq in str2.lower():
                return True
                
        return False

# Singleton instance
_remediation_engine = None

def get_remediation_engine(kb_path: str = REMEDIATION_DB_PATH) -> RemediationEngine:
    """
    Get or create the remediation engine singleton instance
    
    Args:
        kb_path: Path to the knowledge base file
        
    Returns:
        RemediationEngine instance
    """
    global _remediation_engine
    if _remediation_engine is None:
        _remediation_engine = RemediationEngine(kb_path)
    return _remediation_engine

def get_recommendations_for_threat(threat_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convenience function to get recommendations for a threat
    
    Args:
        threat_data: Dictionary containing threat detection results
        
    Returns:
        Dictionary with remediation recommendations
    """
    engine = get_remediation_engine()
    return engine.generate_recommendations(threat_data)
