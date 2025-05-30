"""
FinGuardAI - Threat Model Training Script

This script generates synthetic network packet data and trains the threat detection model
for FinGuardAI's ML-based security analysis.
"""

import os
import pandas as pd
import numpy as np
import argparse
import sys
import logging
from datetime import datetime

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('finguardai.ml')

# Import our threat model
from threat_model import NetworkThreatDetector

def setup_training_data(data_dir: str, samples: int = 2000, force_new: bool = False) -> str:
    """
    Set up the training data directory and generate synthetic data if needed.
    
    Args:
        data_dir: Directory to store training data
        samples: Number of synthetic samples to generate
        force_new: Whether to force regeneration of data even if it exists
        
    Returns:
        Path to the training data file
    """
    # Create data directory if it doesn't exist
    os.makedirs(data_dir, exist_ok=True)
    
    # Define data file path
    data_file = os.path.join(data_dir, 'network_training_data.csv')
    
    # Check if we need to generate data
    if force_new or not os.path.exists(data_file):
        logger.info(f"Generating synthetic training data ({samples} samples)...")
        
        # Create detector instance
        detector = NetworkThreatDetector()
        
        # Generate synthetic data
        df = detector._generate_synthetic_data(samples)
        
        # Save to file
        df.to_csv(data_file, index=False)
        logger.info(f"Saved {len(df)} synthetic training samples to {data_file}")
    else:
        logger.info(f"Using existing training data from {data_file}")
    
    return data_file

def train_model(data_file: str) -> None:
    """
    Train the threat detection model and save it.
    
    Args:
        data_file: Path to the training data file
    """
    logger.info(f"Training threat detection model on {data_file}...")
    
    # Create detector
    detector = NetworkThreatDetector()
    
    # Train model
    start_time = datetime.now()
    model = detector.train(data_file)
    end_time = datetime.now()
    
    # Log results
    training_time = (end_time - start_time).total_seconds()
    logger.info(f"Model training completed in {training_time:.2f}s")
    
    # Test the model on some examples
    test_packets = [
        {
            # Normal packet
            'protocol': 'TCP',
            'packet_size': 120,
            'tcp_flags': 'A',
            'src_ip': '192.168.1.100:40001',
            'dest_ip': '192.168.1.1:80'
        },
        {
            # Suspicious packet
            'protocol': 'TCP',
            'packet_size': 2500,
            'tcp_flags': 'SF',
            'src_ip': '10.0.0.1:12345',
            'dest_ip': '192.168.1.5:445'
        }
    ]
    
    # Get predictions
    results = detector.predict(test_packets)
    
    # Log results
    logger.info("Model test results:")
    for i, result in enumerate(results):
        packet_type = "Suspicious" if i == 1 else "Normal"
        logger.info(f"  {packet_type} packet: Threat Probability={result['threat_probability']:.4f}, "
                   f"Classification={'THREAT' if result['is_threat'] else 'SAFE'}")
                   
    logger.info("Model is ready for use with FinGuardAI!")

def main():
    """Main entry point for the training script."""
    parser = argparse.ArgumentParser(description='Train the FinGuardAI threat detection model')
    parser.add_argument('--samples', type=int, default=2000, 
                        help='Number of synthetic samples to generate')
    parser.add_argument('--force-new', action='store_true',
                        help='Force regeneration of training data')
    parser.add_argument('--data-dir', type=str, default='../data',
                        help='Directory for training data storage')
    
    args = parser.parse_args()
    
    # Setup data directory path relative to this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.abspath(os.path.join(script_dir, args.data_dir))
    
    # Set up training data
    data_file = setup_training_data(data_dir, args.samples, args.force_new)
    
    # Train the model
    train_model(data_file)

if __name__ == "__main__":
    main()
