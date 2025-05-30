"""
FinGuardAI - Network Packet Feature Extraction Module

This module extracts features from network packet data for machine learning-based threat detection.
It processes raw packet data captured via TShark and converts it into numerical features
suitable for classification algorithms.
"""

import pandas as pd
import numpy as np
import re
import ipaddress
from typing import Dict, List, Union, Tuple

# Common ports that might indicate suspicious activity when unexpected
HIGH_RISK_PORTS = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS', 
    135: 'RPC',
    139: 'NetBIOS',
    445: 'SMB',
    1433: 'MSSQL',
    1434: 'MSSQL Browser',
    3306: 'MySQL',
    3389: 'RDP',
    4444: 'Metasploit',
    5900: 'VNC'
}

def is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is in private address space."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private
    except ValueError:
        return False

def extract_packet_features(packet_data: Dict) -> Dict[str, float]:
    """
    Extract numerical features from a packet dictionary.
    
    Args:
        packet_data: Dictionary containing packet information
        
    Returns:
        Dictionary of numerical features suitable for ML model
    """
    features = {}
    
    # Basic packet metrics
    features['packet_size'] = float(packet_data.get('length', 0))
    features['ttl'] = float(packet_data.get('ttl', 0))
    
    # Protocol features (one-hot encoding)
    protocol = packet_data.get('protocol', '').lower()
    features['is_tcp'] = 1.0 if protocol == 'tcp' else 0.0
    features['is_udp'] = 1.0 if protocol == 'udp' else 0.0
    features['is_icmp'] = 1.0 if protocol == 'icmp' else 0.0
    features['is_http'] = 1.0 if protocol == 'http' else 0.0
    features['is_dns'] = 1.0 if protocol == 'dns' else 0.0
    features['is_other_protocol'] = 1.0 if protocol not in ['tcp', 'udp', 'icmp', 'http', 'dns'] else 0.0
    
    # Port risk features
    src_port = int(packet_data.get('src_port', 0))
    dst_port = int(packet_data.get('dst_port', 0))
    features['src_port_risk'] = 1.0 if src_port in HIGH_RISK_PORTS else 0.0
    features['dst_port_risk'] = 1.0 if dst_port in HIGH_RISK_PORTS else 0.0
    features['high_port_number'] = 1.0 if max(src_port, dst_port) > 30000 else 0.0
    
    # IP features
    src_ip = packet_data.get('src', '')
    dst_ip = packet_data.get('dst', '')
    features['src_ip_private'] = 1.0 if is_private_ip(src_ip) else 0.0
    features['dst_ip_private'] = 1.0 if is_private_ip(dst_ip) else 0.0
    
    # Traffic direction
    features['outbound'] = 1.0 if features['src_ip_private'] and not features['dst_ip_private'] else 0.0
    features['inbound'] = 1.0 if not features['src_ip_private'] and features['dst_ip_private'] else 0.0
    features['internal'] = 1.0 if features['src_ip_private'] and features['dst_ip_private'] else 0.0
    
    # Flag features (for TCP)
    if protocol == 'tcp':
        tcp_flags = packet_data.get('tcp_flags', 0)
        # Convert to int if it's a string
        if isinstance(tcp_flags, str):
            tcp_flags = int(tcp_flags, 16) if '0x' in tcp_flags else int(tcp_flags)
        
        features['flag_syn'] = 1.0 if tcp_flags & 0x02 else 0.0
        features['flag_ack'] = 1.0 if tcp_flags & 0x10 else 0.0
        features['flag_fin'] = 1.0 if tcp_flags & 0x01 else 0.0
        features['flag_rst'] = 1.0 if tcp_flags & 0x04 else 0.0
        features['flag_psh'] = 1.0 if tcp_flags & 0x08 else 0.0
        features['flag_urg'] = 1.0 if tcp_flags & 0x20 else 0.0
    else:
        # Non-TCP packets get zero values for TCP flags
        features['flag_syn'] = 0.0
        features['flag_ack'] = 0.0
        features['flag_fin'] = 0.0
        features['flag_rst'] = 0.0
        features['flag_psh'] = 0.0
        features['flag_urg'] = 0.0
    
    return features

def extract_features_from_tshark_data(tshark_output: str) -> List[Dict[str, float]]:
    """
    Process raw TShark output and extract features for ML.
    
    Args:
        tshark_output: Raw output string from TShark
        
    Returns:
        List of feature dictionaries for each packet
    """
    features_list = []
    lines = tshark_output.strip().split('\n')
    
    for line in lines:
        # Skip header lines and empty lines
        if not line or line.startswith('#') or 'Frames:' in line or 'Interval:' in line:
            continue
        
        # Extract packet data
        packet_data = parse_tshark_line(line)
        if packet_data:
            features = extract_packet_features(packet_data)
            features_list.append(features)
    
    return features_list

def parse_tshark_line(line: str) -> Dict[str, str]:
    """
    Parse a line from TShark output into a structured dictionary.
    
    Args:
        line: A single line from TShark output
        
    Returns:
        Dictionary with packet information
    """
    # This is a simplified parser - adapt based on your actual TShark output format
    parts = line.strip().split()
    if len(parts) < 5:  # Minimum fields we expect
        return {}
    
    packet_data = {}
    
    # Try to extract common fields - adapt this to your TShark output format
    # Example format: "1 0.000000 192.168.1.5 → 142.250.190.78 TCP 74 53444 → 443 [SYN]"
    
    # Extract source and destination
    ip_pattern = r'(\d+\.\d+\.\d+\.\d+)'
    src_dst = re.findall(ip_pattern, line)
    if len(src_dst) >= 2:
        packet_data['src'] = src_dst[0]
        packet_data['dst'] = src_dst[1]
    
    # Extract protocol
    protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'DNS', 'ARP']
    for proto in protocols:
        if f" {proto} " in line or line.endswith(f" {proto}"):
            packet_data['protocol'] = proto.lower()
            break
    
    # Extract ports (if present)
    port_pattern = r'(\d+) → (\d+)'
    ports = re.search(port_pattern, line)
    if ports:
        packet_data['src_port'] = ports.group(1)
        packet_data['dst_port'] = ports.group(2)
    
    # Extract packet length
    length_pattern = r' (\d+) '
    length = re.search(length_pattern, line)
    if length:
        packet_data['length'] = length.group(1)
    
    # Extract TCP flags
    if 'protocol' in packet_data and packet_data['protocol'] == 'tcp':
        flag_pattern = r'\[(.*?)\]'
        flags = re.search(flag_pattern, line)
        if flags:
            flag_str = flags.group(1)
            packet_data['tcp_flags_text'] = flag_str
            # Convert text flags to numeric - this is simplified
            tcp_flags = 0
            if 'SYN' in flag_str: tcp_flags |= 0x02
            if 'ACK' in flag_str: tcp_flags |= 0x10
            if 'FIN' in flag_str: tcp_flags |= 0x01
            if 'RST' in flag_str: tcp_flags |= 0x04
            if 'PSH' in flag_str: tcp_flags |= 0x08
            if 'URG' in flag_str: tcp_flags |= 0x20
            packet_data['tcp_flags'] = tcp_flags
    
    return packet_data

def preprocess_for_training(dataframe: pd.DataFrame) -> Tuple[np.ndarray, List[str]]:
    """
    Prepare packet features for model training.
    
    Args:
        dataframe: DataFrame containing packet features
        
    Returns:
        Tuple of (feature_matrix, feature_names)
    """
    # Ensure all columns are numeric
    for col in dataframe.columns:
        if dataframe[col].dtype == 'object':
            dataframe[col] = pd.to_numeric(dataframe[col], errors='coerce')
    
    # Fill NaN values with 0
    dataframe = dataframe.fillna(0)
    
    # Return feature matrix and column names
    feature_names = dataframe.columns.tolist()
    return dataframe.values, feature_names
