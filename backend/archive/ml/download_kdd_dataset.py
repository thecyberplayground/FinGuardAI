"""
FinGuardAI - KDD Cup 1999 Dataset Downloader

This script downloads the KDD Cup 1999 dataset (small sample) which contains
labeled network connections including normal and attack traffic.
"""

import os
import pandas as pd
import numpy as np
import requests
import gzip
import logging
import time
import io

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('finguardai.datasets')

def download_kdd_dataset():
    """
    Download a small sample of the KDD Cup 1999 dataset
    
    Returns:
        Path to downloaded dataset
    """
    logger.info("Downloading KDD Cup 1999 dataset sample...")
    
    # Create data directory
    data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')
    os.makedirs(data_dir, exist_ok=True)
    
    # Define output paths
    output_file = os.path.join(data_dir, "kdd_sample.csv")
    
    # Check if already downloaded
    if os.path.exists(output_file):
        logger.info(f"Dataset already exists at {output_file}")
        return output_file
    
    # Original KDD Cup 1999 dataset link (small 10% subset)
    url = "https://kdd.org/cupfiles/KDDCupData/1999/kddcup.data_10_percent.gz"
    
    try:
        logger.info(f"Downloading from {url}...")
        response = requests.get(url, timeout=60)
        response.raise_for_status()
        
        # Decompress gzip content
        logger.info("Decompressing data...")
        compressed_data = io.BytesIO(response.content)
        with gzip.GzipFile(fileobj=compressed_data) as gzipfile:
            content = gzipfile.read()
        
        # Save to file (first 10,000 lines)
        logger.info("Processing data...")
        lines = content.decode('latin1').splitlines()[:10000]  # Take first 10K lines
        
        # Define column names
        columns = [
            'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 
            'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
            'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell',
            'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
            'num_access_files', 'num_outbound_cmds', 'is_host_login',
            'is_guest_login', 'count', 'srv_count', 'serror_rate',
            'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
            'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
            'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
            'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
            'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
            'dst_host_srv_rerror_rate', 'label'
        ]
        
        # Parse data into DataFrame
        data = []
        for line in lines:
            values = line.strip().split(',')
            if len(values) >= 42:  # Ensure line has all columns
                data.append(values)
        
        df = pd.DataFrame(data, columns=columns)
        
        # Save to CSV
        df.to_csv(output_file, index=False)
        logger.info(f"Saved {len(df)} records to {output_file}")
        
        return output_file
        
    except Exception as e:
        logger.error(f"Error downloading KDD dataset: {e}")
        
        # Fallback: Create synthetic data
        logger.warning("Creating synthetic KDD-like dataset...")
        return create_synthetic_kdd(output_file, 5000)

def create_synthetic_kdd(output_file, n_samples=5000):
    """Create a synthetic dataset based on KDD format as fallback"""
    logger.info(f"Creating synthetic KDD-format dataset with {n_samples} samples...")
    
    # Define column names
    columns = [
        'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 
        'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
        'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell',
        'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
        'num_access_files', 'num_outbound_cmds', 'is_host_login',
        'is_guest_login', 'count', 'srv_count', 'serror_rate',
        'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
        'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
        'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
        'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
        'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
        'dst_host_srv_rerror_rate', 'label'
    ]
    
    # List of protocol types
    protocols = ['tcp', 'udp', 'icmp']
    
    # List of services
    services = ['http', 'ftp_data', 'smtp', 'ssh', 'dns', 'ftp', 'telnet',
                'finger', 'pop_3', 'nntp', 'imap4', 'sql_net', 'time', 'auth']
    
    # List of flags
    flags = ['SF', 'S0', 'REJ', 'RSTO', 'RSTOS0', 'SH', 'RSTR', 'S1', 'S2', 'S3']
    
    # List of attack types
    attack_types = ['normal', 'back', 'buffer_overflow', 'ftp_write', 'guess_passwd',
                   'imap', 'ipsweep', 'land', 'loadmodule', 'multihop', 'neptune',
                   'nmap', 'perl', 'phf', 'pod', 'portsweep', 'rootkit', 'satan',
                   'smurf', 'spy', 'teardrop', 'warezclient', 'warezmaster']
    
    # Generate synthetic data
    data = []
    for i in range(n_samples):
        # 70% normal, 30% attack
        is_attack = np.random.random() < 0.3
        
        # Set attack type
        label = 'normal' if not is_attack else np.random.choice(attack_types[1:])
        
        # Set protocol type
        if is_attack:
            if label in ['ipsweep', 'nmap', 'portsweep', 'satan']:
                protocol = np.random.choice(['tcp', 'icmp'], p=[0.3, 0.7])
            elif label in ['pod', 'teardrop', 'smurf']:
                protocol = np.random.choice(['udp', 'icmp'], p=[0.3, 0.7])
            else:
                protocol = np.random.choice(protocols, p=[0.7, 0.2, 0.1])
        else:
            protocol = np.random.choice(protocols, p=[0.8, 0.15, 0.05])
        
        # Set service based on protocol
        if protocol == 'tcp':
            service = np.random.choice(['http', 'ftp_data', 'smtp', 'telnet', 'ssh', 'ftp'])
        elif protocol == 'udp':
            service = np.random.choice(['dns', 'ntp', 'time'])
        else:  # icmp
            service = 'eco_i'
        
        # Set flag based on attack type
        if is_attack:
            if label in ['neptune', 'syn_flood']:
                flag = 'S0'
            elif label in ['land', 'teardrop']:
                flag = np.random.choice(['SF', 'S0', 'REJ'])
            else:
                flag = np.random.choice(flags)
        else:
            flag = np.random.choice(['SF', 'S0', 'REJ'], p=[0.8, 0.1, 0.1])
        
        # Set traffic characteristics based on attack type
        if is_attack:
            duration = np.random.exponential(20)
            src_bytes = np.random.gamma(1, 500) if label != 'neptune' else np.random.randint(0, 100)
            dst_bytes = np.random.gamma(1, 1000) if label != 'neptune' else np.random.randint(0, 100)
            land = 1 if label == 'land' else 0
            wrong_fragment = np.random.randint(0, 3) if label in ['pod', 'teardrop'] else 0
            urgent = np.random.randint(0, 2)
            count = np.random.randint(20, 500) if label in ['neptune', 'smurf'] else np.random.randint(1, 50)
            serror_rate = np.random.beta(5, 2) if label in ['neptune', 'syn_flood'] else np.random.beta(2, 5)
        else:
            duration = np.random.gamma(0.5, 10)
            src_bytes = np.random.gamma(2, 500)
            dst_bytes = np.random.gamma(2, 1000)
            land = 0
            wrong_fragment = 0
            urgent = 0
            count = np.random.randint(1, 20)
            serror_rate = np.random.beta(1, 10)
        
        # Generate row with all attributes
        row = {
            'duration': duration,
            'protocol_type': protocol,
            'service': service,
            'flag': flag,
            'src_bytes': int(src_bytes),
            'dst_bytes': int(dst_bytes),
            'land': land,
            'wrong_fragment': wrong_fragment,
            'urgent': urgent,
            'hot': np.random.randint(0, 3),
            'num_failed_logins': np.random.randint(0, 2),
            'logged_in': np.random.randint(0, 2),
            'num_compromised': np.random.randint(0, 3),
            'root_shell': np.random.randint(0, 2),
            'su_attempted': np.random.randint(0, 2),
            'num_root': np.random.randint(0, 3),
            'num_file_creations': np.random.randint(0, 3),
            'num_shells': np.random.randint(0, 2),
            'num_access_files': np.random.randint(0, 3),
            'num_outbound_cmds': 0,
            'is_host_login': 0,
            'is_guest_login': np.random.randint(0, 2),
            'count': count,
            'srv_count': np.random.randint(1, 10),
            'serror_rate': serror_rate,
            'srv_serror_rate': serror_rate * np.random.random(),
            'rerror_rate': np.random.beta(1, 10),
            'srv_rerror_rate': np.random.beta(1, 10),
            'same_srv_rate': np.random.beta(5, 1) if not is_attack else np.random.beta(1, 1),
            'diff_srv_rate': np.random.beta(1, 5) if not is_attack else np.random.beta(1, 1),
            'srv_diff_host_rate': np.random.beta(1, 5),
            'dst_host_count': np.random.randint(1, 255),
            'dst_host_srv_count': np.random.randint(1, 100),
            'dst_host_same_srv_rate': np.random.random(),
            'dst_host_diff_srv_rate': np.random.random(),
            'dst_host_same_src_port_rate': np.random.random(),
            'dst_host_srv_diff_host_rate': np.random.random(),
            'dst_host_serror_rate': serror_rate * np.random.random(),
            'dst_host_srv_serror_rate': serror_rate * np.random.random(),
            'dst_host_rerror_rate': np.random.beta(1, 10),
            'dst_host_srv_rerror_rate': np.random.beta(1, 10),
            'label': label
        }
        
        data.append(row)
    
    # Create DataFrame
    df = pd.DataFrame(data)
    
    # Save to CSV
    df.to_csv(output_file, index=False)
    logger.info(f"Created synthetic KDD dataset with {len(df)} rows")
    
    return output_file

def convert_to_finguardai_format(kdd_file, output_file=None):
    """
    Convert KDD dataset to FinGuardAI format
    
    Args:
        kdd_file: Path to KDD CSV file
        output_file: Path to save the converted data
    
    Returns:
        Path to the converted file
    """
    logger.info(f"Converting KDD dataset to FinGuardAI format...")
    
    # Load KDD dataset
    try:
        df = pd.read_csv(kdd_file)
        logger.info(f"Loaded KDD dataset with {len(df)} records")
    except Exception as e:
        logger.error(f"Error loading KDD dataset: {e}")
        return None
    
    # Set default output path
    if output_file is None:
        output_file = os.path.join(os.path.dirname(kdd_file), 'network_training_data.csv')
    
    # Map KDD attack labels to attack/normal
    attack_types = ['normal']
    attack_categories = {
        'neptune': 'DoS', 'smurf': 'DoS', 'pod': 'DoS', 'teardrop': 'DoS', 'land': 'DoS', 'back': 'DoS',
        'apache2': 'DoS', 'udpstorm': 'DoS', 'processtable': 'DoS', 'mailbomb': 'DoS',
        'ipsweep': 'Probe', 'portsweep': 'Probe', 'nmap': 'Probe', 'satan': 'Probe', 'mscan': 'Probe', 'saint': 'Probe',
        'guess_passwd': 'R2L', 'ftp_write': 'R2L', 'imap': 'R2L', 'phf': 'R2L', 'multihop': 'R2L', 'warezmaster': 'R2L',
        'warezclient': 'R2L', 'spy': 'R2L', 'sendmail': 'R2L', 'named': 'R2L', 'snmpgetattack': 'R2L', 'snmpguess': 'R2L',
        'xlock': 'R2L', 'xsnoop': 'R2L', 'worm': 'R2L',
        'buffer_overflow': 'U2R', 'loadmodule': 'U2R', 'perl': 'U2R', 'rootkit': 'U2R', 'xterm': 'U2R', 'ps': 'U2R',
        'sqlattack': 'U2R', 'httptunnel': 'U2R'
    }
    
    # Map KDD features to FinGuardAI features
    results = []
    for _, row in df.iterrows():
        # Determine if it's an attack and get type
        label = row['label'].strip().lower() if isinstance(row['label'], str) else str(row['label']).lower()
        is_attack = label != 'normal'
        
        attack_category = attack_categories.get(label, 'Unknown') if is_attack else 'BENIGN'
        
        # Get protocol
        protocol = str(row['protocol_type']).lower()
        
        # Calculate packet size
        try:
            src_bytes = float(row['src_bytes'])
            dst_bytes = float(row['dst_bytes'])
        except:
            src_bytes = 0
            dst_bytes = 0
        
        packet_size = src_bytes + dst_bytes
        
        # Get TCP flags
        tcp_flags = ""
        flag = str(row['flag']).upper()
        
        if protocol == 'tcp':
            if 'S' in flag:
                tcp_flags += "S"
            if 'F' in flag:
                tcp_flags += "F"
            if 'R' in flag:
                tcp_flags += "R"
            if 'A' in flag and 'SF' in flag:
                tcp_flags += "A"
            if 'P' in flag:
                tcp_flags += "P"
            
            # If no flags, add some reasonable default
            if not tcp_flags:
                tcp_flags = "SA"
        
        # Convert error rates
        try:
            error_rate = float(row['serror_rate'])
        except:
            error_rate = 0.01  # Default
        
        # Get wrong fragment
        try:
            wrong_fragment = int(row['wrong_fragment'])
        except:
            wrong_fragment = 0
        
        # Get count
        try:
            count = int(row['count'])
        except:
            count = 1
        
        # Create packet record in FinGuardAI format
        packet = {
            'protocol': protocol,
            'packet_size': max(40, int(packet_size)),
            'src_bytes': max(0, src_bytes),
            'dst_bytes': max(0, dst_bytes),
            'src_ip': f"192.168.1.{np.random.randint(1, 255)}",  # Generate synthetic IP
            'dest_ip': f"10.0.0.{np.random.randint(1, 255)}",    # Generate synthetic IP
            'service': str(row['service']).lower(),
            'tcp_flags': tcp_flags,
            'error_rate': min(1.0, max(0.0, error_rate)),
            'wrong_fragment': wrong_fragment,
            'count': count,
            'is_threat': 1 if is_attack else 0,
            'attack_type': attack_category
        }
        
        # Add to results
        results.append(packet)
    
    # Convert to DataFrame and save
    output_df = pd.DataFrame(results)
    output_df.to_csv(output_file, index=False)
    
    # Log statistics
    attack_count = output_df['is_threat'].sum()
    attack_percent = attack_count / len(output_df) * 100
    
    logger.info(f"Converted {len(output_df)} records to FinGuardAI format")
    logger.info(f"Attack distribution: {attack_count} attacks ({attack_percent:.1f}%)")
    logger.info(f"Saved to {output_file}")
    
    return output_file

if __name__ == "__main__":
    logger.info("Starting KDD Cup 1999 dataset download and preparation...")
    start_time = time.time()
    
    # Download dataset
    kdd_file = download_kdd_dataset()
    
    if kdd_file:
        # Convert to FinGuardAI format
        finguardai_file = convert_to_finguardai_format(kdd_file)
        
        # Print execution time
        duration = time.time() - start_time
        logger.info(f"Completed in {duration:.2f} seconds")
        
        if finguardai_file:
            logger.info(f"KDD Cup 1999 dataset is ready for ML model training at {finguardai_file}")
    else:
        logger.error("Failed to download dataset. Please check your internet connection and try again.")
