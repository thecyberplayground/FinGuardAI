"""
FinGuardAI - Enhanced Training Data Generator

This script generates synthetic network traffic data for training the FinGuardAI
threat detection model, based on real-world attack patterns.
"""

import os
import pandas as pd
import numpy as np
import logging
import time
import json
from datetime import datetime, timedelta

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('finguardai.ml.data_generator')

# Common network protocols
PROTOCOLS = ['tcp', 'udp', 'icmp']

# Common TCP flags
TCP_FLAGS = ['S', 'A', 'P', 'F', 'R', 'U', 'SA', 'PA', 'FA']

# Known attack types and their characteristics
ATTACK_TYPES = {
    "normal": {
        "protocol_dist": {"tcp": 0.85, "udp": 0.14, "icmp": 0.01},
        "packet_size_range": (60, 1500),
        "size_distribution": "normal",
        "size_mean": 700,
        "size_std": 300,
    },
    "dos": {
        "protocol_dist": {"tcp": 0.65, "udp": 0.30, "icmp": 0.05},
        "packet_size_range": (60, 1000),
        "size_distribution": "gamma",
        "size_shape": 2,
        "size_scale": 200,
        "tcp_flags_dist": {"S": 0.8, "A": 0.05, "R": 0.1, "other": 0.05},
    },
    "probe": {
        "protocol_dist": {"tcp": 0.75, "udp": 0.05, "icmp": 0.20},
        "packet_size_range": (40, 100),
        "size_distribution": "constant",
        "size_mean": 60,
        "size_std": 10,
        "tcp_flags_dist": {"S": 0.9, "SA": 0.05, "other": 0.05},
    },
    "r2l": {  # Remote to Local
        "protocol_dist": {"tcp": 0.95, "udp": 0.05, "icmp": 0.0},
        "packet_size_range": (200, 1200),
        "size_distribution": "exponential",
        "size_scale": 300,
        "tcp_flags_dist": {"PA": 0.6, "A": 0.3, "other": 0.1},
    },
    "u2r": {  # User to Root
        "protocol_dist": {"tcp": 0.98, "udp": 0.01, "icmp": 0.01},
        "packet_size_range": (500, 2000),
        "size_distribution": "normal",
        "size_mean": 1000,
        "size_std": 300,
        "tcp_flags_dist": {"PA": 0.5, "A": 0.4, "other": 0.1},
    },
}

# Common services for each protocol
SERVICES = {
    "tcp": ["http", "https", "ftp", "ssh", "telnet", "smtp", "imap", "pop3", "mysql"],
    "udp": ["dns", "dhcp", "snmp", "ntp", "tftp", "sip"],
    "icmp": ["echo-request", "echo-reply", "destination-unreachable", "time-exceeded"]
}

def generate_ip(internal=True):
    """Generate a random IP address"""
    if internal:
        return f"192.168.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}"
    else:
        # External IPs, avoid reserved ranges
        return f"{np.random.randint(1, 223)}.{np.random.randint(0, 255)}.{np.random.randint(0, 255)}.{np.random.randint(1, 255)}"

def generate_packet_size(attack_type):
    """Generate a packet size based on attack type characteristics"""
    attack_info = ATTACK_TYPES[attack_type]
    min_size, max_size = attack_info["packet_size_range"]
    
    if attack_info["size_distribution"] == "normal":
        size = int(np.random.normal(attack_info["size_mean"], attack_info["size_std"]))
    elif attack_info["size_distribution"] == "gamma":
        size = int(np.random.gamma(attack_info["size_shape"], attack_info["size_scale"]))
    elif attack_info["size_distribution"] == "exponential":
        size = int(np.random.exponential(attack_info["size_scale"]))
    elif attack_info["size_distribution"] == "constant":
        size = int(attack_info["size_mean"] + np.random.normal(0, attack_info["size_std"]))
    else:
        size = np.random.randint(min_size, max_size)
    
    # Ensure within range
    return max(min_size, min(size, max_size))

def select_protocol(attack_type):
    """Select a protocol based on attack type distribution"""
    dist = ATTACK_TYPES[attack_type]["protocol_dist"]
    return np.random.choice(list(dist.keys()), p=list(dist.values()))

def select_service(protocol):
    """Select a service based on protocol"""
    if protocol in SERVICES:
        return np.random.choice(SERVICES[protocol])
    return "other"

def select_tcp_flag(attack_type):
    """Select TCP flags based on attack type"""
    if attack_type in ATTACK_TYPES and "tcp_flags_dist" in ATTACK_TYPES[attack_type]:
        dist = ATTACK_TYPES[attack_type]["tcp_flags_dist"]
        flag_type = np.random.choice(list(dist.keys()), p=list(dist.values()))
        if flag_type == "other":
            return np.random.choice(TCP_FLAGS)
        return flag_type
    return np.random.choice(TCP_FLAGS)

def generate_error_rate(attack_type):
    """Generate an error rate based on attack type"""
    if attack_type == "normal":
        return max(0, min(1, np.random.beta(1, 20)))  # Mostly very low
    elif attack_type == "dos":
        return max(0, min(1, np.random.beta(5, 5)))   # Around 0.5
    elif attack_type == "probe":
        return max(0, min(1, np.random.beta(2, 8)))   # Low to medium
    else:
        return max(0, min(1, np.random.beta(2, 10)))  # Fairly low

def generate_synthetic_packet(attack_type="normal"):
    """Generate a synthetic network packet with features"""
    protocol = select_protocol(attack_type)
    packet_size = generate_packet_size(attack_type)
    
    # Split packet size into src and dst bytes
    if attack_type == "normal":
        # For normal traffic, somewhat balanced
        src_ratio = np.random.beta(5, 5)  # Centered around 0.5
    elif attack_type in ["dos", "probe"]:
        # More from src to dst for attacks
        src_ratio = np.random.beta(8, 2)  # Mostly high (source heavy)
    else:
        # Variable for other attacks
        src_ratio = np.random.beta(3, 3)  # Quite variable
    
    src_bytes = int(packet_size * src_ratio)
    dst_bytes = packet_size - src_bytes
    
    # Generate source/destination IPs
    if attack_type == "normal":
        # Normal traffic is often internal-to-internal or internal-to-external
        src_internal = np.random.choice([True, False], p=[0.7, 0.3])
        dst_internal = np.random.choice([True, False], p=[0.5, 0.5])
    elif attack_type in ["r2l", "u2r"]:
        # Remote attacks often come from external sources
        src_internal = np.random.choice([True, False], p=[0.2, 0.8])
        dst_internal = True  # Targeting internal systems
    else:
        # Other attacks can be from anywhere
        src_internal = np.random.choice([True, False], p=[0.5, 0.5])
        dst_internal = np.random.choice([True, False], p=[0.8, 0.2])
    
    # Create the packet record
    packet = {
        'protocol': protocol,
        'packet_size': packet_size,
        'src_bytes': src_bytes,
        'dst_bytes': dst_bytes,
        'src_ip': generate_ip(internal=src_internal),
        'dest_ip': generate_ip(internal=dst_internal),
        'service': select_service(protocol),
        'tcp_flags': select_tcp_flag(attack_type) if protocol == "tcp" else "",
        'error_rate': generate_error_rate(attack_type),
        'wrong_fragment': 1 if (attack_type != "normal" and np.random.random() < 0.1) else 0,
        'count': np.random.randint(1, 100),  # Connection count
        'is_threat': 1 if attack_type != "normal" else 0,
        'attack_type': attack_type
    }
    
    return packet

def generate_training_data(num_samples=10000, output_file=None):
    """
    Generate synthetic network traffic data for training
    
    Args:
        num_samples: Number of packet samples to generate
        output_file: Path to save the generated data
        
    Returns:
        DataFrame with the generated data
    """
    logger.info(f"Generating {num_samples} synthetic network packets for training...")
    start_time = time.time()
    
    # Set distribution of attack types (70% normal, 30% attacks distributed among types)
    attack_distribution = {
        "normal": 0.7,
        "dos": 0.1,
        "probe": 0.1,
        "r2l": 0.05,
        "u2r": 0.05
    }
    
    # Generate packets
    packets = []
    for _ in range(num_samples):
        # Select attack type based on distribution
        attack_type = np.random.choice(
            list(attack_distribution.keys()),
            p=list(attack_distribution.values())
        )
        
        # Generate a packet of this type
        packet = generate_synthetic_packet(attack_type)
        packets.append(packet)
    
    # Convert to DataFrame
    df = pd.DataFrame(packets)
    
    # Set default output file if not provided
    if output_file is None:
        data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')
        os.makedirs(data_dir, exist_ok=True)
        output_file = os.path.join(data_dir, 'synthetic_network_data.csv')
    
    # Save to CSV
    df.to_csv(output_file, index=False)
    
    # Log statistics
    duration = time.time() - start_time
    attack_counts = df['attack_type'].value_counts()
    
    logger.info(f"Generated {len(df)} packets in {duration:.2f} seconds")
    logger.info(f"Attack distribution:")
    for attack_type, count in attack_counts.items():
        logger.info(f"  {attack_type}: {count} ({count/len(df)*100:.1f}%)")
    
    logger.info(f"Data saved to {output_file}")
    
    return df

if __name__ == "__main__":
    logger.info("Starting synthetic network data generation...")
    
    # Generate 10,000 packets by default
    df = generate_training_data(num_samples=10000)
    
    logger.info("Data generation complete!")
    logger.info(f"Generated dataset with shape: {df.shape}")
    logger.info(f"Threat percentage: {df['is_threat'].mean()*100:.2f}%")
