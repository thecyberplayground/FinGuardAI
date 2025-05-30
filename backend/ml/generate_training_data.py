"""
FinGuardAI - Training Data Generator

This module generates synthetic training data for the ML model.
It creates a balanced dataset of normal and anomalous network traffic patterns.
"""

import os
import pandas as pd
import numpy as np
import random
from datetime import datetime, timedelta
from typing import List, Dict

# Configure paths
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')
NETWORK_DATA_PATH = os.path.join(DATA_DIR, 'network_data.csv')

# Common ports - regular and high risk
COMMON_PORTS = [80, 443, 8080, 8443, 53, 123]
HIGH_RISK_PORTS = [21, 22, 23, 25, 445, 1433, 3306, 3389, 4444, 5900]

def generate_safe_packet() -> Dict:
    """Generate a feature vector for a safe network packet."""
    features = {}
    
    # Basic packet metrics
    features['packet_size'] = random.uniform(100, 1500)
    features['ttl'] = random.uniform(32, 128)
    
    # Protocol features (one-hot encoding)
    protocol = random.choice(['tcp', 'udp', 'icmp', 'http', 'dns'])
    features['is_tcp'] = 1.0 if protocol == 'tcp' else 0.0
    features['is_udp'] = 1.0 if protocol == 'udp' else 0.0
    features['is_icmp'] = 1.0 if protocol == 'icmp' else 0.0
    features['is_http'] = 1.0 if protocol == 'http' else 0.0
    features['is_dns'] = 1.0 if protocol == 'dns' else 0.0
    features['is_other_protocol'] = 0.0  # Standard protocols
    
    # Port risk features - safe packets typically use common ports
    src_port = random.choice(COMMON_PORTS) if random.random() < 0.7 else random.randint(1024, 65535)
    dst_port = random.choice(COMMON_PORTS) if random.random() < 0.7 else random.randint(1024, 65535)
    
    features['src_port_risk'] = 0.0  # Not risky ports
    features['dst_port_risk'] = 0.0  # Not risky ports
    features['high_port_number'] = 1.0 if max(src_port, dst_port) > 30000 else 0.0
    
    # IP features - safe traffic is typically regular internal/external communication
    features['src_ip_private'] = 1.0 if random.random() < 0.5 else 0.0
    features['dst_ip_private'] = 1.0 if random.random() < 0.5 else 0.0
    
    # Traffic direction
    features['outbound'] = 1.0 if features['src_ip_private'] and not features['dst_ip_private'] else 0.0
    features['inbound'] = 1.0 if not features['src_ip_private'] and features['dst_ip_private'] else 0.0
    features['internal'] = 1.0 if features['src_ip_private'] and features['dst_ip_private'] else 0.0
    
    # TCP flag features - regular patterns for normal traffic
    if protocol == 'tcp':
        # Normal pattern: mostly established connections (ACK)
        features['flag_syn'] = 1.0 if random.random() < 0.1 else 0.0  # Occasional SYN for new connections
        features['flag_ack'] = 1.0 if random.random() < 0.8 else 0.0  # Mostly ACKs in established connections
        features['flag_fin'] = 1.0 if random.random() < 0.05 else 0.0  # Occasional FIN for closing connections
        features['flag_rst'] = 1.0 if random.random() < 0.02 else 0.0  # Rare RST packets
        features['flag_psh'] = 1.0 if random.random() < 0.3 else 0.0   # Some PSH for data transfer
        features['flag_urg'] = 1.0 if random.random() < 0.01 else 0.0  # Very rare URG flags
    else:
        # Non-TCP packets have no flags
        features['flag_syn'] = 0.0
        features['flag_ack'] = 0.0
        features['flag_fin'] = 0.0
        features['flag_rst'] = 0.0
        features['flag_psh'] = 0.0
        features['flag_urg'] = 0.0
    
    # Label: safe
    features['is_threat'] = 0
    
    return features

def generate_threat_packet() -> Dict:
    """Generate a feature vector for a threatening network packet."""
    features = {}
    
    # Basic packet metrics - similar to normal packets, but can be unusual sizes
    features['packet_size'] = random.choice([
        random.uniform(20, 60),  # Unusually small
        random.uniform(100, 1500),  # Normal
        random.uniform(1500, 9000)  # Unusually large
    ])
    features['ttl'] = random.choice([
        random.uniform(1, 20),  # Unusually small TTL
        random.uniform(32, 128),  # Normal
        random.uniform(200, 255)  # Unusually large TTL
    ])
    
    # Protocol features - attacks can use various protocols
    protocol = random.choice(['tcp', 'udp', 'icmp', 'http', 'dns', 'other'])
    features['is_tcp'] = 1.0 if protocol == 'tcp' else 0.0
    features['is_udp'] = 1.0 if protocol == 'udp' else 0.0
    features['is_icmp'] = 1.0 if protocol == 'icmp' else 0.0
    features['is_http'] = 1.0 if protocol == 'http' else 0.0
    features['is_dns'] = 1.0 if protocol == 'dns' else 0.0
    features['is_other_protocol'] = 1.0 if protocol == 'other' else 0.0
    
    # Port risk features - threats often target high-risk ports
    threat_type = random.choice(['risky_port', 'scan', 'unusual_flag', 'mixed'])
    
    if threat_type in ['risky_port', 'mixed']:
        # Use risky ports
        src_port = random.choice(HIGH_RISK_PORTS) if random.random() < 0.3 else random.randint(1024, 65535)
        dst_port = random.choice(HIGH_RISK_PORTS) if random.random() < 0.7 else random.randint(1024, 65535)
        features['src_port_risk'] = 1.0 if src_port in HIGH_RISK_PORTS else 0.0
        features['dst_port_risk'] = 1.0 if dst_port in HIGH_RISK_PORTS else 0.0
    else:
        # Use normal or high port numbers (port scanning)
        src_port = random.randint(1024, 65535)
        dst_port = random.randint(1, 65535)
        features['src_port_risk'] = 0.0
        features['dst_port_risk'] = 0.0
    
    features['high_port_number'] = 1.0 if max(src_port, dst_port) > 30000 else 0.0
    
    # IP features - various traffic directions for threats
    features['src_ip_private'] = 1.0 if random.random() < 0.3 else 0.0
    features['dst_ip_private'] = 1.0 if random.random() < 0.7 else 0.0
    
    # Traffic direction
    features['outbound'] = 1.0 if features['src_ip_private'] and not features['dst_ip_private'] else 0.0
    features['inbound'] = 1.0 if not features['src_ip_private'] and features['dst_ip_private'] else 0.0
    features['internal'] = 1.0 if features['src_ip_private'] and features['dst_ip_private'] else 0.0
    
    # TCP flag features - unusual patterns for attacks
    if protocol == 'tcp':
        if threat_type in ['unusual_flag', 'mixed']:
            # Unusual flag combinations for attacks (nmap scans, SYN floods, etc.)
            features['flag_syn'] = 1.0 if random.random() < 0.7 else 0.0  # Many SYNs (potential SYN flood)
            features['flag_ack'] = 1.0 if random.random() < 0.3 else 0.0  # Few ACKs
            features['flag_fin'] = 1.0 if random.random() < 0.3 else 0.0  # FIN scans
            features['flag_rst'] = 1.0 if random.random() < 0.3 else 0.0  # RST scans
            features['flag_psh'] = 1.0 if random.random() < 0.3 else 0.0   
            features['flag_urg'] = 1.0 if random.random() < 0.3 else 0.0  # URG often used in attacks
            
            # Sometimes all flags set (XMAS scan)
            if random.random() < 0.1:
                features['flag_syn'] = 1.0
                features['flag_ack'] = 1.0
                features['flag_fin'] = 1.0
                features['flag_rst'] = 1.0
                features['flag_psh'] = 1.0
                features['flag_urg'] = 1.0
        else:
            # Normal flag pattern
            features['flag_syn'] = 1.0 if random.random() < 0.2 else 0.0
            features['flag_ack'] = 1.0 if random.random() < 0.6 else 0.0
            features['flag_fin'] = 1.0 if random.random() < 0.1 else 0.0
            features['flag_rst'] = 1.0 if random.random() < 0.1 else 0.0
            features['flag_psh'] = 1.0 if random.random() < 0.2 else 0.0
            features['flag_urg'] = 1.0 if random.random() < 0.05 else 0.0
    else:
        # Non-TCP packets have no flags
        features['flag_syn'] = 0.0
        features['flag_ack'] = 0.0
        features['flag_fin'] = 0.0
        features['flag_rst'] = 0.0
        features['flag_psh'] = 0.0
        features['flag_urg'] = 0.0
    
    # Label: threat
    features['is_threat'] = 1
    
    return features

def generate_synthetic_dataset(n_samples: int = 1000, threat_ratio: float = 0.3) -> pd.DataFrame:
    """
    Generate a synthetic dataset for training the threat detection model.
    
    Args:
        n_samples: Total number of samples to generate
        threat_ratio: Proportion of samples that should be threats
        
    Returns:
        DataFrame with synthetic network packet features
    """
    # Calculate number of samples for each class
    n_threats = int(n_samples * threat_ratio)
    n_safe = n_samples - n_threats
    
    # Generate samples
    threat_samples = [generate_threat_packet() for _ in range(n_threats)]
    safe_samples = [generate_safe_packet() for _ in range(n_safe)]
    
    # Combine and shuffle
    all_samples = threat_samples + safe_samples
    random.shuffle(all_samples)
    
    # Convert to DataFrame
    df = pd.DataFrame(all_samples)
    
    return df

def save_synthetic_dataset(df: pd.DataFrame, filepath: str = NETWORK_DATA_PATH) -> None:
    """
    Save the synthetic dataset to a CSV file.
    
    Args:
        df: DataFrame with synthetic data
        filepath: Path to save the CSV file
    """
    # Ensure data directory exists
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    
    # Save to CSV
    df.to_csv(filepath, index=False)
    print(f"Saved {len(df)} samples to {filepath}")
    print(f"Threat ratio: {df['is_threat'].mean():.2f}")

if __name__ == "__main__":
    # Generate and save a synthetic dataset
    print("Generating synthetic network traffic dataset...")
    df = generate_synthetic_dataset(n_samples=5000, threat_ratio=0.3)
    save_synthetic_dataset(df)
    print("Done!")
