"""
FinGuardAI - Threat Detection Module

This module handles real-time threat detection using the trained ML model.
It processes network packets to determine if they represent potential threats.
"""

import os
import joblib
import logging
import numpy as np
import pandas as pd
from typing import Dict, List, Union, Optional, Tuple

from feature_extraction import extract_features_from_tshark_data, extract_packet_features

# Import remediation recommendations
try:
    from remediation import get_recommendations_for_threat
    HAS_REMEDIATION = True
except ImportError:
    HAS_REMEDIATION = False
    logging.warning("Remediation module not available. Recommendations will not be included in threat detection results.")

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('finguardai.threat_detection')

# Constants
MODEL_DIR = os.path.join(os.path.dirname(__file__), 'models')
DEFAULT_MODEL_PATH = os.path.join(MODEL_DIR, 'threat_detection_model.joblib')
THREAT_THRESHOLD = 0.6  # Probability threshold for classifying as threat

class ThreatDetector:
    """Handles real-time threat detection on network packets."""
    
    def __init__(self, model_path: str = DEFAULT_MODEL_PATH):
        """
        Initialize the threat detector with a trained model.
        
        Args:
            model_path: Path to the trained model
        """
        self.model = None
        self.metadata = None
        self.feature_names = []
        self._load_model(model_path)
    
    def _load_model(self, model_path: str) -> bool:
        """
        Load the ML model and its metadata.
        
        Args:
            model_path: Path to the trained model
            
        Returns:
            True if loaded successfully, False otherwise
        """
        # Check if model exists
        if not os.path.exists(model_path):
            logger.error(f"Model file not found: {model_path}")
            return False
        
        try:
            # Load model
            self.model = joblib.load(model_path)
            logger.info(f"Loaded threat detection model from {model_path}")
            
            # Load metadata
            metadata_path = os.path.splitext(model_path)[0] + '_metadata.joblib'
            if os.path.exists(metadata_path):
                self.metadata = joblib.load(metadata_path)
                self.feature_names = self.metadata.get('feature_names', [])
                logger.info(f"Loaded model metadata with {len(self.feature_names)} features")
            else:
                logger.warning(f"Model metadata not found at {metadata_path}")
            
            return True
        
        except Exception as e:
            logger.error(f"Error loading model: {str(e)}")
            return False
    
    def is_model_loaded(self) -> bool:
        """Check if the model is loaded and ready for inference."""
        return self.model is not None
    
    def detect_threats_from_tshark(self, tshark_output: str) -> List[Dict]:
        """
        Process TShark output and detect threats.
        
        Args:
            tshark_output: Raw output from TShark
            
        Returns:
            List of dictionaries with threat detection results
        """
        if not self.is_model_loaded():
            logger.error("Cannot detect threats: Model not loaded")
            return []
        
        # Extract features from TShark output
        feature_dicts = extract_features_from_tshark_data(tshark_output)
        if not feature_dicts:
            logger.warning("No packets extracted from TShark output")
            return []
        
        # Convert to DataFrame in the correct format for the model
        features_df = pd.DataFrame(feature_dicts)
        
        # Ensure we have all expected features, add missing ones with 0
        for feature in self.feature_names:
            if feature not in features_df.columns:
                features_df[feature] = 0.0
        
        # Keep only the features used by the model, in the correct order
        if self.feature_names:
            features_df = features_df.reindex(columns=self.feature_names, fill_value=0.0)
        
        # Make predictions
        try:
            # Get probability scores (second column is probability of being a threat)
            if hasattr(self.model, 'predict_proba'):
                threat_probas = self.model.predict_proba(features_df.values)[:, 1]
            else:
                # Fallback to binary prediction if predict_proba not available
                predictions = self.model.predict(features_df.values)
                threat_probas = np.array([1.0 if p else 0.0 for p in predictions])
            
            # Combine predictions with original features
            results = []
            for i, (features, prob) in enumerate(zip(feature_dicts, threat_probas)):
                is_threat = prob >= THREAT_THRESHOLD
                results.append({
                    'packet_id': i,
                    'features': features,
                    'threat_probability': float(prob),
                    'is_threat': bool(is_threat),
                    'threat_level': self._calculate_threat_level(prob)
                })
            
            return results
            
        except Exception as e:
            logger.error(f"Error during threat detection: {str(e)}")
            return []
    
    def detect_threat(self, packet_data: Dict) -> Dict:
        """
        Detect if a single packet is a threat.
        
        Args:
            packet_data: Dictionary with packet information
            
        Returns:
            Dictionary with threat detection results
        """
        if not self.is_model_loaded():
            logger.error("Cannot detect threat: Model not loaded")
            return {
                'error': 'Model not loaded',
                'is_threat': False,
                'threat_probability': 0.0,
                'threat_level': 'unknown'
            }
        
        # Extract features
        features = extract_packet_features(packet_data)
        features_df = pd.DataFrame([features])
        
        # Ensure we have all expected features
        for feature in self.feature_names:
            if feature not in features_df.columns:
                features_df[feature] = 0.0
        
        # Keep only the features used by the model, in the correct order
        if self.feature_names:
            features_df = features_df.reindex(columns=self.feature_names, fill_value=0.0)
        
        # Make prediction
        try:
            if hasattr(self.model, 'predict_proba'):
                # Get probability of being a threat (second column)
                threat_proba = self.model.predict_proba(features_df.values)[0, 1]
            else:
                # Fallback if predict_proba not available
                prediction = self.model.predict(features_df.values)[0]
                threat_proba = 1.0 if prediction else 0.0
            
            is_threat = threat_proba >= THREAT_THRESHOLD
            threat_level = self._calculate_threat_level(threat_proba)
            
            # Create base result
            result = {
                'is_threat': bool(is_threat),
                'threat_probability': float(threat_proba),
                'threat_level': threat_level,
                'features_used': list(features.keys())
            }
            
            # Add source IP and destination IP if available
            if 'src_ip' in packet_data:
                result['src_ip'] = packet_data['src_ip']
            if 'dest_ip' in packet_data:
                result['dest_ip'] = packet_data['dest_ip']
            if 'protocol' in packet_data:
                result['protocol'] = packet_data['protocol']
            if 'service' in packet_data:
                result['service'] = packet_data['service']
            if 'packet_size' in packet_data:
                result['packet_size'] = packet_data['packet_size']
                
            # Add remediation recommendations if available
            if HAS_REMEDIATION and is_threat:
                try:
                    recommendations = get_recommendations_for_threat(result)
                    result['remediation'] = recommendations
                except Exception as e:
                    logger.error(f"Error generating remediation recommendations: {e}")
            
            return result
            
        except Exception as e:
            logger.error(f"Error during threat detection: {str(e)}")
            return {
                'error': str(e),
                'is_threat': False,
                'threat_probability': 0.0,
                'threat_level': 'unknown'
            }
    
    def _calculate_threat_level(self, probability: float) -> str:
        """
        Convert probability to a threat level category.
        
        Args:
            probability: Threat probability from 0.0 to 1.0
            
        Returns:
            Threat level as string: 'low', 'medium', 'high', or 'critical'
        """
        if probability < 0.3:
            return 'low'
        elif probability < 0.6:
            return 'medium'
        elif probability < 0.85:
            return 'high'
        else:
            return 'critical'
    
    def analyze_traffic(self, packet_batch: List[Dict]) -> Dict:
        """
        Analyze a batch of packets and provide summary statistics.
        
        Args:
            packet_batch: List of packet data dictionaries
            
        Returns:
            Dictionary with traffic analysis results
        """
        if not packet_batch:
            return {
                'total_packets': 0,
                'threat_count': 0,
                'threat_percentage': 0,
                'threat_levels': {},
                'highest_threat': 0.0
            }
        
        # Process each packet
        results = []
        for packet in packet_batch:
            result = self.detect_threat(packet)
            results.append(result)
        
        # Compute statistics
        threat_count = sum(1 for r in results if r.get('is_threat', False))
        threat_percentage = (threat_count / len(results)) * 100
        
        # Count by threat level
        threat_levels = {
            'low': sum(1 for r in results if r.get('threat_level') == 'low'),
            'medium': sum(1 for r in results if r.get('threat_level') == 'medium'),
            'high': sum(1 for r in results if r.get('threat_level') == 'high'),
            'critical': sum(1 for r in results if r.get('threat_level') == 'critical')
        }
        
        # Find highest threat probability
        highest_threat = max((r.get('threat_probability', 0.0) for r in results), default=0.0)
        
        # Collect remediation recommendations from all threats
        all_recommendations = []
        threat_types = set()
        regulations = set()
        overall_severity = 'low'
        
        # Severity ranking
        severity_rank = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        max_severity = 0
        
        # Extract unique remediation steps and other metadata
        for result in results:
            if result.get('is_threat', False) and 'remediation' in result:
                remediation = result['remediation']
                # Add recommendations
                all_recommendations.extend(remediation.get('recommendations', []))
                # Add threat types
                threat_types.update(remediation.get('threat_types', []))
                # Add regulations
                regulations.update(remediation.get('regulations', []))
                # Track highest severity
                this_severity = severity_rank.get(remediation.get('severity', 'low'), 1)
                if this_severity > max_severity:
                    max_severity = this_severity
                    if max_severity in [3, 4]:  # high or critical
                        overall_severity = remediation.get('severity', 'low')
        
        # Remove duplicates while preserving order
        unique_recommendations = []
        seen = set()
        for rec in all_recommendations:
            if rec not in seen:
                seen.add(rec)
                unique_recommendations.append(rec)
        
        # Final analysis result
        analysis = {
            'total_packets': len(results),
            'threat_count': threat_count,
            'threat_percentage': threat_percentage,
            'threat_levels': threat_levels,
            'highest_threat': highest_threat,
            'detailed_results': results
        }
        
        # Add remediation information if available
        if HAS_REMEDIATION and threat_count > 0:
            analysis['remediation'] = {
                'recommendations': unique_recommendations[:10],  # Limit to top 10
                'threat_types': list(threat_types),
                'regulations': list(regulations),
                'overall_severity': overall_severity
            }
        
        return analysis

# Singleton instance
_detector_instance = None

def get_detector(model_path: str = DEFAULT_MODEL_PATH) -> ThreatDetector:
    """
    Get or create the threat detector singleton instance.
    
    Args:
        model_path: Path to the trained model
        
    Returns:
        ThreatDetector instance
    """
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = ThreatDetector(model_path)
    return _detector_instance

def detect_threats_in_tshark_output(tshark_output: str) -> List[Dict]:
    """
    Convenience function to detect threats in TShark output.
    
    Args:
        tshark_output: Raw output from TShark
        
    Returns:
        List of dictionaries with threat detection results
    """
    detector = get_detector()
    return detector.detect_threats_from_tshark(tshark_output)
