"""
FinGuardAI - Financial Sector Specific Remediation Recommendations

This module provides precise, actionable remediation recommendations for financial sector
vulnerabilities and threats. It focuses on industry-specific controls, regulatory compliance,
and exact technical configurations.
"""

import logging
import os
import json
from typing import Dict, List, Any, Optional, Set, Tuple

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('finguardai.remediation.financial')

class FinancialRemediationEngine:
    """Provides financial-sector specific security remediation recommendations"""
    
    def __init__(self):
        """Initialize the financial remediation engine"""
        self.knowledge_base = self._create_financial_knowledge_base()
        
    def _create_financial_knowledge_base(self) -> Dict:
        """
        Create a specialized remediation knowledge base for financial sector
        
        Returns:
            Dictionary of threat types mapped to specific financial sector remediations
        """
        return {
            "transaction_fraud": {
                "name": "Transaction Fraud Detection",
                "description": "Anomalous financial transaction patterns indicative of fraud",
                "indicators": [
                    "Unusual transaction volumes or frequencies",
                    "Transactions from unusual geographic locations",
                    "Multiple failed authentication attempts",
                    "Unusual access patterns to account information"
                ],
                "severity": "critical",
                "financial_impact": "Direct monetary loss, fraudulent transactions, legal liability",
                "remediation_steps": [
                    "Implement velocity checks with max 5 transactions/minute per account",
                    "Configure behavior-based anomaly detection with 60-day baseline",
                    "Deploy ML-based fraud detection with <0.5% false positive rate",
                    "Implement $1000 transaction threshold requiring step-up authentication",
                    "Set up multi-factor authentication for transactions >$500",
                    "Implement 24-hour wait period for first-time payment recipients >$5000",
                    "Deploy real-time interbank transaction verification via SWIFT"
                ],
                "technical_controls": [
                    "Implement IP-based geolocation verification with opt-in authorization",
                    "Set up transaction amount velocity ratios (comparison to 90-day history)",
                    "Enable RASP (Runtime Application Self-Protection) for transaction processors",
                    "Implement device fingerprinting with risk-based step-up authentication"
                ],
                "specific_patterns": [
                    "TCP traffic to transaction API endpoints with unusual frequency",
                    "Repeated authentication attempts to financial services",
                    "Multiple accounts accessed from same IP within short timeframe",
                    "API requests with transaction data at unusual hours"
                ],
                "regulations": [
                    {"name": "PCI DSS", "section": "6.5.1, 8.3, 10.2", "control_id": "PCI-DSS:6.5.1"}, 
                    {"name": "GLBA", "section": "501(b)", "control_id": "GLBA:501b"},
                    {"name": "SOX", "section": "404", "control_id": "SOX:404"}
                ]
            },
            "payment_system_breach": {
                "name": "Payment System Security Vulnerability",
                "description": "Exploitation of vulnerabilities in payment processing systems",
                "indicators": [
                    "Unusual connections to payment gateways",
                    "API requests with manipulated payment data",
                    "Suspicious pattern access to payment processing endpoints",
                    "Data leakage from payment processing systems"
                ],
                "severity": "critical",
                "financial_impact": "Payment fraud, service disruption, financial penalties",
                "remediation_steps": [
                    "Implement tokenization for all payment card data using PCI-validated method",
                    "Enable TLS 1.3 (ECDHE+AES-GCM) with strict certificate validation",
                    "Configure point-to-point encryption (P2PE) for payment terminals",
                    "Implement dedicated payment card industry data security standard (PCI DSS) controls",
                    "Deploy API gateway with schema validation for payment endpoints",
                    "Configure payment processor-specific firewall rules (list provided)"
                ],
                "technical_controls": [
                    "Set up segmented payment network with stateful inspection firewalls",
                    "Implement network data leakage prevention for card number patterns",
                    "Enable HSM (Hardware Security Module) for all cryptographic operations",
                    "Deploy continuous file integrity monitoring with real-time alerts",
                    "Configure PCI DSS-specific IDS rules for payment traffic"
                ],
                "payment_processors": {
                    "Stripe": [
                        "Rotate Stripe API keys every 90 days",
                        "Implement webhook signature verification with rotated secrets",
                        "Enable Stripe Radar with custom rules for your transaction patterns",
                        "Set up fingerprinting-based fraud detection"
                    ],
                    "PayPal": [
                        "Implement PayPal IPN verification with strict validation",
                        "Enable PayPal's Fraud Protection Advanced",
                        "Configure anti-fraud rules based on country constraints",
                        "Implement address verification service (AVS) and CVV validation"
                    ]
                },
                "specific_patterns": [
                    "Network connections to payment processor endpoints outside business hours",
                    "Unusual data volumes to/from payment processor IPs",
                    "Abnormal API call patterns to payment endpoints",
                    "HTTP POST requests with malformed payment data"
                ],
                "regulations": [
                    {"name": "PCI DSS", "section": "1.3.4, 3.4, 4.1, 6.5.1-10", "control_id": "PCI-DSS:4.1"},
                    {"name": "GDPR", "section": "32", "control_id": "GDPR:32"},
                    {"name": "FFIEC", "section": "Information Security Handbook", "control_id": "FFIEC:IS"}
                ]
            },
            "financial_api_attack": {
                "name": "Financial API Security Vulnerability",
                "description": "Attempts to exploit vulnerabilities in financial service APIs",
                "indicators": [
                    "Unusual API request patterns to financial services",
                    "Abnormal request volumes or frequencies",
                    "API requests with suspicious parameters or payloads",
                    "Authentication anomalies on API endpoints"
                ],
                "severity": "high",
                "financial_impact": "Unauthorized access to financial data, service disruption",
                "remediation_steps": [
                    "Implement OAuth 2.0 with mTLS for API authentication",
                    "Configure API rate limiting at 100 req/min for authenticated, 10 req/min for unauthenticated",
                    "Enable strict schema validation on all API requests",
                    "Implement OWASP API Security Top 10 countermeasures",
                    "Deploy just-in-time (JIT) API access with expiring credentials (15 min)",
                    "Configure separate scopes for read vs. transaction APIs",
                    "Implement API Gateway with banking-specific threat protection rules"
                ],
                "technical_controls": [
                    "Set up API-specific WAF rules with financial data leak prevention",
                    "Implement financial transaction simulation for attack detection",
                    "Configure API access log monitoring with anomaly detection",
                    "Deploy API behavior analytics with custom banking-specific rules"
                ],
                "specific_patterns": [
                    "Repeated API calls with different credentials",
                    "API requests with suspected SQL/NoSQL injection attempts",
                    "Parameter manipulation in financial transaction API calls",
                    "Excessive API error responses indicating brute force"
                ],
                "sample_rules": [
                    "Block API keys after 5 consecutive 401/403 responses in 60 seconds",
                    "Require re-authentication for sensitive operations after 15 minutes",
                    "Limit duplicate transaction requests to 3 per minute",
                    "Implement graduated response (delay, challenge, block) for suspicious API patterns"
                ],
                "regulations": [
                    {"name": "SOX", "section": "302, 404", "control_id": "SOX:404"},
                    {"name": "PSD2", "section": "Strong Customer Authentication", "control_id": "PSD2:SCA"},
                    {"name": "NYDFS", "section": "500.04, 500.05", "control_id": "NYDFS:500.04"}
                ]
            },
            "financial_data_exfiltration": {
                "name": "Financial Data Exfiltration Attempt",
                "description": "Potential theft of financial account data, PII, or transaction records",
                "indicators": [
                    "Unusual outbound data transfers containing financial data patterns",
                    "Suspicious access to financial databases",
                    "Data transfers to unauthorized destinations",
                    "Encrypted or obfuscated outbound traffic"
                ],
                "severity": "critical",
                "financial_impact": "Data breach reporting costs, customer compensation, regulatory fines",
                "remediation_steps": [
                    "Implement financial data loss prevention with regex patterns for account/routing numbers",
                    "Enable database activity monitoring with real-time alerts for unusual queries",
                    "Configure egress filtering specifically for financial data patterns",
                    "Deploy CASB (Cloud Access Security Broker) for financial SaaS applications",
                    "Implement table-level encryption for financial databases with HSM key management",
                    "Set up anomaly detection for database access patterns with 30-day baseline"
                ],
                "technical_controls": [
                    "Configure SIEM correlation rules for financial data access + egress traffic",
                    "Implement just-in-time database access for financial data tables",
                    "Deploy content inspection at network egress points with financial data patterns",
                    "Enable watermarking of sensitive financial documents"
                ],
                "data_patterns": [
                    "Account numbers (13-16 digit patterns with appropriate prefixes)",
                    "Routing numbers (9-digit ABA RTN format validation)",
                    "Credit card data (matching PCI DSS detection patterns)",
                    "Customer financial records (statement data, transaction history)"
                ],
                "dlp_rules": [
                    "Block unencrypted transfer of >5 credit card numbers",
                    "Require DLP scanning of all outbound email with financial data",
                    "Implement automated redaction of account numbers in documents",
                    "Enable secure transmission channels for authorized financial data sharing"
                ],
                "regulations": [
                    {"name": "GLBA", "section": "Safeguards Rule", "control_id": "GLBA:Safeguards"},
                    {"name": "PCI DSS", "section": "3.4, 3.5, 4.1, 10.5", "control_id": "PCI-DSS:3.4"},
                    {"name": "GDPR", "section": "32, 33, 34", "control_id": "GDPR:32"}
                ]
            },
            "authentication_attack": {
                "name": "Financial Authentication System Attack",
                "description": "Attempts to compromise authentication for financial systems",
                "indicators": [
                    "Multiple failed login attempts to financial portals",
                    "Credential stuffing patterns against banking interfaces",
                    "Session manipulation attempts", 
                    "MFA bypass attempts"
                ],
                "severity": "critical",
                "financial_impact": "Account takeover, unauthorized transactions, fraud losses",
                "remediation_steps": [
                    "Implement risk-based authentication with device, location and behavior factors",
                    "Configure multi-factor authentication using FIDO2/WebAuthn standard",
                    "Enable biometric verification for high-value transactions",
                    "Deploy CAPTCHA after 3 failed login attempts within 5 minutes",
                    "Implement 30-minute lockout after 5 failed authentication attempts",
                    "Configure browser fingerprinting with risk scoring (0-100)",
                    "Deploy password-less authentication for mobile banking"
                ],
                "technical_controls": [
                    "Set up account takeover protection with behavior-based anomaly detection",
                    "Implement credential stuffing protection with IP reputation analysis",
                    "Configure secure session management with 15-minute inactivity timeout",
                    "Deploy anti-automation measures on login endpoints (rate limiting, bot detection)"
                ],
                "specific_patterns": [
                    "Multiple login attempts with different usernames from same source",
                    "Rapid succession of authentication requests (>3/minute)",
                    "Login attempts outside of typical usage patterns",
                    "Authentication from geographically improbable locations"
                ],
                "regulations": [
                    {"name": "FFIEC", "section": "Authentication Guidance", "control_id": "FFIEC:AUTH"},
                    {"name": "PSD2", "section": "Strong Customer Authentication", "control_id": "PSD2:SCA"},
                    {"name": "NYDFS", "section": "500.12", "control_id": "NYDFS:500.12"}
                ]
            },
            "insider_threat_finance": {
                "name": "Financial Insider Threat Activity",
                "description": "Potential malicious activity by authorized users in financial systems",
                "indicators": [
                    "Unusual access patterns to financial records",
                    "Access to financial data outside job responsibilities",
                    "Abnormal transaction approvals or modifications",
                    "Suspicious database queries on financial records"
                ],
                "severity": "high",
                "financial_impact": "Fraud, embezzlement, data theft, compliance violations",
                "remediation_steps": [
                    "Implement segregation of duties for financial transactions (request/approve/execute)",
                    "Configure privileged access management with just-in-time access to financial systems",
                    "Enable user behavior analytics with financial transaction monitoring",
                    "Deploy database activity monitoring with custom rules for financial queries",
                    "Implement four-eyes principle for transactions above $10,000",
                    "Configure alerting for off-hours access to financial systems"
                ],
                "technical_controls": [
                    "Set up fine-grained access controls based on specific data fields",
                    "Implement continuous verification of user access rights",
                    "Configure monitoring for suspicious user activity patterns",
                    "Deploy keystroke monitoring on critical financial systems",
                    "Enable data access logging with 1-year retention"
                ],
                "specific_patterns": [
                    "Access to financial records outside normal business hours",
                    "Unusual volume of records accessed by a single user",
                    "Access patterns inconsistent with job responsibilities",
                    "Unusual export or download of financial data"
                ],
                "regulations": [
                    {"name": "SOX", "section": "302, 404", "control_id": "SOX:404"},
                    {"name": "GLBA", "section": "501(b)", "control_id": "GLBA:501b"},
                    {"name": "FFIEC", "section": "Information Security Handbook", "control_id": "FFIEC:IS"}
                ]
            }
        }
    
    def map_threat_to_financial_category(self, threat_data: Dict[str, Any]) -> List[str]:
        """
        Map general threat data to specific financial threat categories
        
        Args:
            threat_data: Dictionary containing threat detection results
            
        Returns:
            List of matching financial threat categories
        """
        # Initialize matches
        matches = []
        
        # Get relevant threat indicators
        protocol = threat_data.get('protocol', '').lower()
        is_threat = threat_data.get('is_threat', False)
        probability = threat_data.get('threat_probability', 0)
        service = threat_data.get('service', '').lower()
        error_rate = threat_data.get('error_rate', 0)
        
        # Skip non-threats or low probability threats
        if not is_threat or probability < 0.4:
            return matches
        
        # Check for authentication attack patterns
        if service in ['http', 'https'] and error_rate > 0.5:
            matches.append('authentication_attack')
        
        # Check for payment system patterns
        if service in ['http', 'https'] and 'payment' in str(threat_data):
            matches.append('payment_system_breach')
        
        # Financial API attack patterns
        if protocol == 'tcp' and service in ['http', 'https', 'ssh']:
            # API-related threats
            if error_rate > 0.3:
                matches.append('financial_api_attack')
        
        # Transaction fraud patterns
        if service in ['http', 'https'] and probability > 0.7:
            matches.append('transaction_fraud')
        
        # Data exfiltration patterns
        if protocol in ['tcp', 'udp'] and probability > 0.8:
            matches.append('financial_data_exfiltration')
        
        # Insider threat patterns (harder to detect from just network traffic)
        if service in ['ssh', 'ftp', 'database', 'sql'] and probability > 0.7:
            matches.append('insider_threat_finance')
        
        # If no specific match but high probability
        if not matches and probability > 0.8:
            # Default to API attack as a conservative approach
            matches.append('financial_api_attack')
        
        return matches
    
    def get_financial_recommendations(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate financial-sector specific remediation recommendations
        
        Args:
            threat_data: Dictionary containing threat detection results
            
        Returns:
            Dictionary with financial-specific remediation recommendations
        """
        # Initialize response
        response = {
            'financial_threat_types': [],
            'critical_remediations': [],
            'technical_controls': [],
            'regulatory_requirements': [],
            'financial_impact': '',
            'severity': 'low'
        }
        
        # Skip for non-threats
        if not threat_data.get('is_threat', False):
            return response
        
        # Map general threat to financial categories
        threat_categories = self.map_threat_to_financial_category(threat_data)
        
        # Track severity for determining highest
        severity_map = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        highest_severity = 0
        
        # Collect all remediations from matching categories
        all_remediations = []
        all_controls = []
        all_regulations = []
        impacts = []
        
        for category in threat_categories:
            if category in self.knowledge_base:
                cat_data = self.knowledge_base[category]
                
                # Add remediation steps
                all_remediations.extend(cat_data.get('remediation_steps', []))
                
                # Add technical controls
                all_controls.extend(cat_data.get('technical_controls', []))
                
                # Add regulations
                all_regulations.extend(cat_data.get('regulations', []))
                
                # Add impact
                impacts.append(cat_data.get('financial_impact', ''))
                
                # Track highest severity
                sev = cat_data.get('severity', 'low') 
                sev_value = severity_map.get(sev, 1)
                if sev_value > highest_severity:
                    highest_severity = sev_value
                
                # Add category-specific controls if available
                if 'payment_processors' in cat_data and category == 'payment_system_breach':
                    for processor, controls in cat_data['payment_processors'].items():
                        processor_controls = [f"{processor}: {control}" for control in controls]
                        all_controls.extend(processor_controls[:2])  # Add top 2 controls
                
                if 'sample_rules' in cat_data and category == 'financial_api_attack':
                    all_controls.extend(cat_data['sample_rules'])
                
                if 'dlp_rules' in cat_data and category == 'financial_data_exfiltration':
                    all_controls.extend(cat_data['dlp_rules'])
        
        # Remove duplicates while preserving order
        unique_remediations = []
        unique_controls = []
        unique_regulations = []
        seen_remediations = set()
        seen_controls = set()
        seen_regulations = set()
        
        for rem in all_remediations:
            if rem not in seen_remediations:
                seen_remediations.add(rem)
                unique_remediations.append(rem)
        
        for control in all_controls:
            if control not in seen_controls:
                seen_controls.add(control)
                unique_controls.append(control)
        
        for reg in all_regulations:
            reg_id = reg.get('control_id', '')
            if reg_id and reg_id not in seen_regulations:
                seen_regulations.add(reg_id)
                unique_regulations.append(reg)
        
        # Get severity string
        severity_map_reverse = {1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}
        severity = severity_map_reverse.get(highest_severity, 'low')
        
        # Build response
        response['financial_threat_types'] = threat_categories
        response['critical_remediations'] = unique_remediations[:5]  # Top 5 critical remediations
        response['technical_controls'] = unique_controls[:5]  # Top 5 technical controls
        response['regulatory_requirements'] = unique_regulations[:3]  # Top 3 regulations
        response['financial_impact'] = ' '.join(impacts)
        response['severity'] = severity
        
        return response

# Singleton instance
_financial_engine = None

def get_financial_engine() -> FinancialRemediationEngine:
    """
    Get or create the financial remediation engine singleton
    
    Returns:
        FinancialRemediationEngine instance
    """
    global _financial_engine
    if _financial_engine is None:
        _financial_engine = FinancialRemediationEngine()
    return _financial_engine

def get_financial_recommendations(threat_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convenience function to get financial-sector specific recommendations
    
    Args:
        threat_data: Dictionary containing threat detection results
        
    Returns:
        Dictionary with financial-specific remediation recommendations
    """
    engine = get_financial_engine()
    return engine.get_financial_recommendations(threat_data)
