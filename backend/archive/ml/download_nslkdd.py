"""
FinGuardAI - NSL-KDD Dataset Downloader and Preprocessor

This script downloads the NSL-KDD dataset (a lightweight, pre-labeled network security dataset)
and converts it to the format required by our ML model.
"""

import pandas as pd
import numpy as np
import os
import requests
import time
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('finguardai.datasets')

def download_nslkdd(force_download=False):
    """
    Download the NSL-KDD dataset
    
    Args:
        force_download: If True, download even if files exist
    """
    logger.info("Preparing to download NSL-KDD dataset...")
    
    # Create data directory
    data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')
    os.makedirs(data_dir, exist_ok=True)
    
    # File paths
    train_path = os.path.join(data_dir, "KDDTrain+.csv")
    test_path = os.path.join(data_dir, "KDDTest+.csv")
    
    # Check if already downloaded
    if not force_download and os.path.exists(train_path) and os.path.exists(test_path):
        logger.info("Dataset files already exist. Use force_download=True to re-download.")
        return (train_path, test_path)
    
    # For NSL-KDD, download directly from alternate source
    train_url = "https://github.com/defcom17/NSL_KDD/raw/master/KDDTrain%2B.csv"
    test_url = "https://github.com/defcom17/NSL_KDD/raw/master/KDDTest%2B.csv"
    
    # Download train data
    logger.info(f"Downloading training data from {train_url}...")
    try:
        r = requests.get(train_url, timeout=30)
        r.raise_for_status()  # Raise exception for HTTP errors
        with open(train_path, "wb") as f:
            f.write(r.content)
        logger.info(f"Training data saved to {train_path}")
    except Exception as e:
        logger.error(f"Error downloading training data: {e}")
        return None
    
    # Download test data
    logger.info(f"Downloading test data from {test_url}...")
    try:
        r = requests.get(test_url, timeout=30)
        r.raise_for_status()
        with open(test_path, "wb") as f:
            f.write(r.content)
        logger.info(f"Test data saved to {test_path}")
    except Exception as e:
        logger.error(f"Error downloading test data: {e}")
        return None
    
    logger.info("Download complete!")
    return (train_path, test_path)

def prepare_nslkdd_for_training(output_file=None):
    """
    Convert NSL-KDD dataset to our ML model format
    
    Args:
        output_file: Path to save the processed data
    
    Returns:
        DataFrame with the prepared data
    """
    # Download the dataset if needed
    file_paths = download_nslkdd()
    if not file_paths:
        logger.error("Failed to download or locate dataset files.")
        return None
    
    train_path, test_path = file_paths
    
    # Set default output path if not provided
    if not output_file:
        output_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), 
                                 'data', 'network_training_data.csv')
    
    try:
        # Load the dataset
        logger.info(f"Loading NSL-KDD training data from {train_path}...")
        
        # NSL-KDD dataset has a standard format with unlabeled columns
        # Define column names based on KDD99 documentation
        columns = [
            'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 
            'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins',
            'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 'num_root',
            'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds',
            'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate',
            'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
            'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
            'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
            'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
            'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'class', 'difficulty_level'
        ]
        
        # Read the data
        train_df = pd.read_csv(train_path, header=None, names=columns)
        
        # Optionally include test data
        test_df = pd.read_csv(test_path, header=None, names=columns)
        full_df = pd.concat([train_df, test_df], ignore_index=True)
        
        logger.info(f"Loaded dataset with {len(full_df)} records")
        
        # Map to our format
        logger.info("Converting dataset to FinGuardAI format...")
        result = []
        for _, row in full_df.iterrows():
            # Determine if this is an attack
            is_attack = row['class'] != 'normal'
            
            # Extract protocol details
            protocol = row['protocol_type'].lower()  # tcp, udp, icmp
            
            # Create a synthetic packet representation
            packet = {
                'protocol': protocol,
                'packet_size': int(row['src_bytes']) + int(row['dst_bytes']),
                'src_ip': f"192.168.1.{np.random.randint(1, 255)}",  # Generate synthetic IP
                'dest_ip': f"10.0.0.{np.random.randint(1, 255)}",    # Generate synthetic IP
                'tcp_flags': row['flag'] if protocol == 'tcp' else '',
                'is_threat': 1 if is_attack else 0,
                'attack_type': row['class'] if is_attack else 'normal',
                'src_bytes': row['src_bytes'],
                'dst_bytes': row['dst_bytes'],
                'service': row['service'],
                'wrong_fragment': row['wrong_fragment'],
                'count': row['count'],  # Connection count 
                'error_rate': row['serror_rate']  # SYN error rate
            }
            result.append(packet)
        
        # Convert to DataFrame
        output_df = pd.DataFrame(result)
        
        # Save to CSV
        output_df.to_csv(output_file, index=False)
        logger.info(f"Saved {len(output_df)} prepared records to {output_file}")
        
        # Calculate attack statistics
        attack_count = output_df['is_threat'].sum()
        attack_percent = attack_count / len(output_df) * 100
        logger.info(f"Attack distribution: {attack_count} attacks ({attack_percent:.1f}%)")
        
        # Show attack type distribution
        attack_types = output_df['attack_type'].value_counts()
        logger.info("Attack type distribution:")
        for attack_type, count in attack_types.items():
            logger.info(f"  {attack_type}: {count} ({count/len(output_df)*100:.1f}%)")
        
        return output_df
        
    except Exception as e:
        logger.error(f"Error processing NSL-KDD dataset: {e}")
        return None

if __name__ == "__main__":
    logger.info("Starting NSL-KDD dataset download and preparation...")
    start_time = time.time()
    
    # Process dataset
    df = prepare_nslkdd_for_training()
    
    # Print execution time
    duration = time.time() - start_time
    logger.info(f"Completed in {duration:.2f} seconds")
    
    if df is not None:
        logger.info("NSL-KDD dataset is ready for ML model training!")
