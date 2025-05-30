"""
FinGuardAI - Financial Remediation System Test Script

This script tests the complete integration of the financial-specific remediation
system with the threat detection system.
"""

import os
import sys
import json
import logging
from typing import Dict, List, Any
import time

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('finguardai.test')

# Add the backend directory to the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import remediation and threat detection modules
try:
    # Add ml directory to path to ensure all imports work
    sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ml'))
    
    # Now import the modules
    from ml.remediation.recommendations import get_recommendations_for_threat
    from ml.remediation.financial_recommendations import get_financial_recommendations
    from ml.detect_threats import get_detector
    import ml.feature_extraction  # Import the feature_extraction module
    
    HAS_MODULES = True
except ImportError as e:
    logger.error(f"Error importing required modules: {e}")
    HAS_MODULES = False

def generate_test_threats() -> List[Dict[str, Any]]:
    """
    Generate a series of test threat scenarios for evaluation.
    
    Returns:
        List of threat data dictionaries
    """
    return [
        {
            "name": "Financial API Scan",
            "data": {
                "protocol": "tcp",
                "service": "https",
                "src_ip": "192.168.1.10",
                "dest_ip": "10.0.0.5",
                "packet_size": 64,
                "src_bytes": 300,
                "dst_bytes": 1200,
                "count": 150,
                "error_rate": 0.4,
                "is_threat": True,
                "threat_probability": 0.78,
                "threat_level": "high"
            }
        },
        {
            "name": "Payment System Probe",
            "data": {
                "protocol": "tcp",
                "service": "https",
                "src_ip": "192.168.1.20",
                "dest_ip": "10.0.0.10",
                "packet_size": 92,
                "src_bytes": 500,
                "dst_bytes": 2500,
                "count": 45,
                "error_rate": 0.6,
                "is_threat": True,
                "threat_probability": 0.85,
                "threat_level": "high",
                "url_path": "/api/payments/process"
            }
        },
        {
            "name": "Authentication Attack",
            "data": {
                "protocol": "tcp",
                "service": "https",
                "src_ip": "192.168.1.30",
                "dest_ip": "10.0.0.15",
                "packet_size": 128,
                "src_bytes": 1024,
                "dst_bytes": 2048,
                "count": 200,
                "error_rate": 0.7,
                "failed_logins": 25,
                "is_threat": True,
                "threat_probability": 0.92,
                "threat_level": "critical"
            }
        },
        {
            "name": "Financial Data Exfiltration",
            "data": {
                "protocol": "tcp",
                "service": "https",
                "src_ip": "10.0.0.50",
                "dest_ip": "203.0.113.100",
                "packet_size": 1500,
                "src_bytes": 150000,
                "dst_bytes": 3000,
                "count": 10,
                "error_rate": 0.05,
                "is_threat": True,
                "threat_probability": 0.89,
                "threat_level": "critical"
            }
        },
        {
            "name": "Normal Financial Transaction",
            "data": {
                "protocol": "tcp",
                "service": "https",
                "src_ip": "192.168.1.100",
                "dest_ip": "10.0.0.20",
                "packet_size": 512,
                "src_bytes": 1024,
                "dst_bytes": 2048,
                "count": 3,
                "error_rate": 0.0,
                "is_threat": False,
                "threat_probability": 0.05,
                "threat_level": "low"
            }
        }
    ]

def test_financial_recommendations():
    """Test the financial-specific recommendation system"""
    if not HAS_MODULES:
        logger.error("Required modules not available. Cannot run test.")
        return
    
    logger.info("=== Testing Financial-Specific Remediation System ===\n")
    
    # Generate test threats
    test_threats = generate_test_threats()
    
    # Test each scenario
    for scenario in test_threats:
        logger.info(f"\n\n=== Testing Scenario: {scenario['name']} ===")
        threat_data = scenario['data']
        
        # 1. Test basic financial recommendations
        logger.info("\n--- Financial-Specific Recommendations ---")
        financial_recs = get_financial_recommendations(threat_data)
        
        logger.info(f"Financial Threat Types: {financial_recs.get('financial_threat_types', [])}")
        logger.info(f"Severity: {financial_recs.get('severity', 'N/A')}")
        
        if financial_recs.get('critical_remediations'):
            logger.info("\nCritical Remediations:")
            for i, rec in enumerate(financial_recs.get('critical_remediations', []), 1):
                logger.info(f"  {i}. {rec}")
        
        if financial_recs.get('technical_controls'):
            logger.info("\nTechnical Controls:")
            for i, control in enumerate(financial_recs.get('technical_controls', []), 1):
                logger.info(f"  {i}. {control}")
        
        if financial_recs.get('regulatory_requirements'):
            logger.info("\nRegulatory Requirements:")
            for i, reg in enumerate(financial_recs.get('regulatory_requirements', []), 1):
                if isinstance(reg, dict):
                    logger.info(f"  {i}. {reg.get('name', 'Unknown')} {reg.get('section', 'Unknown')}")
        
        # 2. Test integrated recommendations
        logger.info("\n--- Integrated Recommendations ---")
        integrated_recs = get_recommendations_for_threat(threat_data)
        
        logger.info(f"Is Finance-Specific: {integrated_recs.get('finance_specific', False)}")
        logger.info(f"General Threat Types: {integrated_recs.get('threat_types', [])}")
        logger.info(f"Financial Threat Types: {integrated_recs.get('finance_threat_types', [])}")
        logger.info(f"Overall Severity: {integrated_recs.get('severity', 'N/A')}")
        
        logger.info("\nFinal Recommendations:")
        for i, rec in enumerate(integrated_recs.get('recommendations', []), 1):
            logger.info(f"  {i}. {rec}")
        
        logger.info("\nRegulations:")
        for i, reg in enumerate(integrated_recs.get('regulations', []), 1):
            logger.info(f"  {i}. {reg}")
        
        # Small delay to make output readable
        time.sleep(0.5)
    
    logger.info("\n\n=== Financial Remediation System Test Complete ===")

def test_financial_remediation_direct():
    """Test financial remediation directly without detector dependency"""
    if not HAS_MODULES:
        logger.error("Required modules not available. Cannot run test.")
        return
    
    logger.info("\n\n=== Testing Financial Remediation Direct Integration ===")
    
    # Create a mock threat that would typically come from the detector
    test_threat = {
        "protocol": "tcp",
        "service": "https",
        "src_ip": "192.168.1.10",
        "dest_ip": "10.0.0.5",
        "packet_size": 128,
        "src_bytes": 1024,
        "dst_bytes": 2048,
        "count": 75,
        "error_rate": 0.6,
        "is_threat": True,
        "threat_probability": 0.85,
        "threat_level": "high",
        "url_path": "/api/banking/transactions"
    }
    
    # Generate both types of recommendations
    logger.info("\nGenerating recommendations for financial sector threat...")
    
    # Get general recommendations
    general_recs = get_recommendations_for_threat(test_threat)
    
    # Get financial-specific recommendations 
    financial_recs = get_financial_recommendations(test_threat)
    
    # Output the results
    logger.info("\n--- General Recommendations ---")
    logger.info(f"Threat Types: {general_recs.get('threat_types', [])}")
    logger.info(f"Severity: {general_recs.get('severity', 'low')}")
    
    logger.info("\nRecommendations:")
    for i, rec in enumerate(general_recs.get('recommendations', []), 1):
        logger.info(f"  {i}. {rec}")
    
    logger.info("\n--- Financial-Specific Recommendations ---")
    logger.info(f"Financial Threat Types: {financial_recs.get('financial_threat_types', [])}")
    logger.info(f"Financial Severity: {financial_recs.get('severity', 'low')}")
    
    logger.info("\nCritical Remediations:")
    for i, rec in enumerate(financial_recs.get('critical_remediations', []), 1):
        logger.info(f"  {i}. {rec}")
    
    logger.info("\nTechnical Controls:")
    for i, control in enumerate(financial_recs.get('technical_controls', []), 1):
        logger.info(f"  {i}. {control}")
    
    logger.info("\n=== Direct Integration Test Complete ===")

if __name__ == "__main__":
    if not HAS_MODULES:
        print("ERROR: Required modules not available. Cannot run tests.")
        sys.exit(1)
    
    logger.info("FinGuardAI - Financial Remediation System Test")
    logger.info("============================================")
    
    # Test financial recommendations system
    test_financial_recommendations()
    
    # Test direct integration with financial remediation
    test_financial_remediation_direct()
    
    logger.info("\n\nAll tests completed successfully!")
