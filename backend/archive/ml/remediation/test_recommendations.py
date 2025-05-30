"""
FinGuardAI - Test Remediation Recommendations

This script tests the remediation recommendation system by generating
recommendations for various threat scenarios.
"""

import os
import sys
import logging

# Add parent directories to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('finguardai.test')

# Import remediation module
from remediation import get_recommendations_for_threat
from remediation.recommendations import get_remediation_engine

def test_remediation_engine():
    """Test basic functionality of the remediation engine"""
    engine = get_remediation_engine()
    threat_types = engine.get_threat_types()
    
    logger.info(f"Remediation engine loaded with {len(threat_types)} threat types")
    logger.info(f"Available threat types: {', '.join(threat_types)}")
    
    # Test getting recommendations for each threat type
    for threat_type in threat_types:
        remediation = engine.get_remediation_by_threat_type(threat_type)
        logger.info(f"\nRemediation for {threat_type}:")
        logger.info(f"  Name: {remediation.get('name', 'N/A')}")
        logger.info(f"  Severity: {remediation.get('severity', 'N/A')}")
        logger.info(f"  Steps: {len(remediation.get('remediation_steps', []))} recommendations")

def test_threat_recommendations():
    """Test generating recommendations for different threat scenarios"""
    test_cases = [
        {
            "name": "Network Scan",
            "data": {
                "protocol": "tcp",
                "packet_size": 60,
                "src_bytes": 40,
                "dst_bytes": 20,
                "tcp_flags": "S",
                "error_rate": 0.5,
                "count": 200,
                "is_threat": True,
                "threat_probability": 0.9,
                "threat_level": "medium"
            }
        },
        {
            "name": "DoS Attack",
            "data": {
                "protocol": "tcp",
                "packet_size": 120,
                "src_bytes": 100,
                "dst_bytes": 20,
                "tcp_flags": "S",
                "error_rate": 0.7,
                "count": 1000,
                "is_threat": True,
                "threat_probability": 0.95,
                "threat_level": "high"
            }
        },
        {
            "name": "Protocol Abuse",
            "data": {
                "protocol": "tcp",
                "packet_size": 300,
                "src_bytes": 200,
                "dst_bytes": 100,
                "tcp_flags": "SFRPA",
                "error_rate": 0.3,
                "wrong_fragment": 1,
                "count": 30,
                "is_threat": True,
                "threat_probability": 0.8,
                "threat_level": "medium"
            }
        },
        {
            "name": "Safe Traffic",
            "data": {
                "protocol": "tcp",
                "packet_size": 1200,
                "src_bytes": 800,
                "dst_bytes": 400,
                "tcp_flags": "SA",
                "error_rate": 0.01,
                "count": 5,
                "is_threat": False,
                "threat_probability": 0.05,
                "threat_level": "low"
            }
        }
    ]
    
    # Test each case
    for case in test_cases:
        logger.info(f"\n=== Testing {case['name']} ===")
        recommendations = get_recommendations_for_threat(case['data'])
        
        logger.info(f"Threat Types: {recommendations.get('threat_types', [])}")
        logger.info(f"Severity: {recommendations.get('severity', 'N/A')}")
        logger.info(f"Regulations: {recommendations.get('regulations', [])}")
        
        logger.info("Recommendations:")
        for i, rec in enumerate(recommendations.get('recommendations', []), 1):
            logger.info(f"  {i}. {rec}")

def main():
    """Run all tests"""
    logger.info("=== FinGuardAI Remediation Recommendations Test ===")
    
    logger.info("\n\n--- Testing Remediation Engine ---")
    test_remediation_engine()
    
    logger.info("\n\n--- Testing Threat Recommendations ---")
    test_threat_recommendations()

if __name__ == "__main__":
    main()
