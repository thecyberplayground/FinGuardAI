import pandas as pd
import numpy as np
import joblib
import os
import random
from sklearn.ensemble import RandomForestClassifier
from typing import List, Dict, Union, Optional

class NetworkThreatDetector:
    """
    Enhanced network threat detection model that analyzes packet features 
    to identify potential security threats.
    """
    
    def __init__(self):
        """Initialize the threat detector"""
        self.model = None
        self.model_path = os.path.join(os.path.dirname(__file__), 'models', 'threat_model.pkl')
        self.feature_names = [
            'protocol_tcp', 'protocol_udp', 'protocol_icmp', 'protocol_http', 'protocol_dns',
            'packet_size', 'is_high_port', 'has_risky_flags', 'is_to_risky_port', 'is_from_risky_port'
        ]
        
        # Define risky ports (commonly associated with vulnerabilities)
        self.risky_ports = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet', 
            25: 'SMTP',
            53: 'DNS', 
            135: 'RPC',
            139: 'NetBIOS',
            445: 'SMB',
            1433: 'MSSQL',
            3306: 'MySQL',
            3389: 'RDP',
            4444: 'Metasploit',
            5900: 'VNC'
        }
        
        # Create models directory if it doesn't exist
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        
    def load_model(self) -> bool:
        """Load a pre-trained model if it exists"""
        if not os.path.exists(self.model_path):
            return False
            
        try:
            self.model = joblib.load(self.model_path)
            return True
        except Exception as e:
            print(f"Error loading model: {e}")
            return False
            
    def train(self, data_file: str) -> RandomForestClassifier:
        """
        Train the threat detection model on packet data.
        
        Args:
            data_file: Path to CSV file with training data
            
        Returns:
            Trained RandomForestClassifier model
        """
        # Load data
        try:
            df = pd.read_csv(data_file)
            print(f"Loaded {len(df)} training samples from {data_file}")
        except Exception as e:
            print(f"Error loading training data: {e}")
            raise ValueError(f"Cannot train model: Training data file '{data_file}' not found or invalid.")
            
        # Extract features
        X = self._extract_features(df)
        
        # Create labels
        y = self._create_labels(df)
        
        # Train model
        self.model = RandomForestClassifier(
            n_estimators=100, 
            max_depth=10,
            random_state=42
        )
        self.model.fit(X, y)
        
        # Save model
        joblib.dump(self.model, self.model_path)
        print(f"Model trained and saved to {self.model_path}")
        
        # Calculate and report feature importances
        if hasattr(self.model, 'feature_importances_'):
            importances = dict(zip(self.feature_names, self.model.feature_importances_))
            print("Feature importances:")
            for feature, importance in sorted(importances.items(), key=lambda x: x[1], reverse=True):
                print(f"  {feature}: {importance:.4f}")
        
        return self.model
    
    def predict(self, packet_data: Union[Dict, List[Dict]]) -> List[Dict]:
        """
        Predict threats in network packet data.
        
        Args:
            packet_data: Dictionary or list of dictionaries with packet information
            
        Returns:
            List of dictionaries with threat detection results
        """
        # Ensure model is loaded
        if not self.model:
            if not self.load_model():
                raise ValueError("No trained model available. Please train a model first.")
        
        # Convert to DataFrame
        if isinstance(packet_data, dict):
            packet_data = [packet_data]
        
        # Create a DataFrame
        df = pd.DataFrame(packet_data)
        
        # Extract features
        X = self._extract_features(df)
        
        # Make prediction
        if hasattr(self.model, 'predict_proba'):
            # Get probability of threat (class 1)
            probas = self.model.predict_proba(X)[:,1]  
            predictions = probas > 0.5
        else:
            # Fallback to simple prediction
            predictions = self.model.predict(X)
            probas = np.array([1.0 if p else 0.0 for p in predictions])
        
        # Create threat level categories
        threat_levels = []
        for p in probas:
            if p < 0.3:
                threat_levels.append('low')
            elif p < 0.6:
                threat_levels.append('medium')
            elif p < 0.8:
                threat_levels.append('high')
            else:
                threat_levels.append('critical')
                
        # Combine with original data
        results = []
        for i, (prob, pred, level) in enumerate(zip(probas, predictions, threat_levels)):
            # Get original packet info for reference
            packet_info = {}
            if i < len(packet_data):
                packet_info = packet_data[i]
            
            results.append({
                'packet_id': i,
                'is_threat': bool(pred),
                'threat_probability': float(prob),
                'threat_level': level,
                'protocol': packet_info.get('protocol', ''),
                'src_ip': packet_info.get('src_ip', ''),
                'dest_ip': packet_info.get('dest_ip', ''),
                'packet_size': packet_info.get('packet_size', 0)
            })
        
        return results
    
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
                'threat_levels': {'low': 0, 'medium': 0, 'high': 0, 'critical': 0},
                'highest_threat': 0.0,
                'detailed_results': []
            }
        
        # Get threat detection results
        results = self.predict(packet_batch)
        
        # Compute statistics
        threat_count = sum(1 for r in results if r.get('is_threat', False))
        threat_percentage = (threat_count / len(results)) * 100 if results else 0
        
        # Count by threat level
        threat_levels = {
            'low': sum(1 for r in results if r.get('threat_level') == 'low'),
            'medium': sum(1 for r in results if r.get('threat_level') == 'medium'),
            'high': sum(1 for r in results if r.get('threat_level') == 'high'),
            'critical': sum(1 for r in results if r.get('threat_level') == 'critical')
        }
        
        # Find highest threat probability
        highest_threat = max((r.get('threat_probability', 0.0) for r in results), default=0.0)
        
        return {
            'total_packets': len(results),
            'threat_count': threat_count,
            'threat_percentage': threat_percentage,
            'threat_levels': threat_levels,
            'highest_threat': highest_threat,
            'detailed_results': results
        }
    
    def _extract_features(self, df: pd.DataFrame) -> np.ndarray:
        """
        Extract relevant features for threat detection.
        
        Args:
            df: DataFrame with packet data
            
        Returns:
            NumPy array of features
        """
        # Create feature DataFrame
        features = pd.DataFrame(index=df.index)
        
        # Protocol one-hot encoding
        features['protocol_tcp'] = df['protocol'].str.lower().str.contains('tcp').fillna(False).astype(float)
        features['protocol_udp'] = df['protocol'].str.lower().str.contains('udp').fillna(False).astype(float)
        features['protocol_icmp'] = df['protocol'].str.lower().str.contains('icmp').fillna(False).astype(float)
        features['protocol_http'] = df['protocol'].str.lower().str.contains('http').fillna(False).astype(float)
        features['protocol_dns'] = df['protocol'].str.lower().str.contains('dns').fillna(False).astype(float)
        
        # Packet size
        if 'packet_size' in df.columns:
            try:
                features['packet_size'] = pd.to_numeric(df['packet_size'], errors='coerce').fillna(0)
            except:
                features['packet_size'] = 0
        else:
            features['packet_size'] = 0
            
        # High port detection
        def extract_port(ip_port):
            if isinstance(ip_port, str) and ':' in ip_port:
                try:
                    return int(ip_port.split(':')[-1])
                except:
                    return 0
            return 0
            
        src_port = df['src_ip'].apply(extract_port) if 'src_ip' in df.columns else 0
        dst_port = df['dest_ip'].apply(extract_port) if 'dest_ip' in df.columns else 0
        features['is_high_port'] = ((src_port > 30000) | (dst_port > 30000)).astype(float)
        
        # TCP flags analysis
        if 'tcp_flags' in df.columns:
            # Look for suspicious flag combinations (e.g., SYN+FIN)
            features['has_risky_flags'] = df['tcp_flags'].str.contains('SF|FPU|XMAS', case=False, na=False).astype(float)
        else:
            features['has_risky_flags'] = 0
            
        # Risky port detection
        features['is_to_risky_port'] = dst_port.isin(self.risky_ports.keys()).astype(float)
        features['is_from_risky_port'] = src_port.isin(self.risky_ports.keys()).astype(float)
        
        # Ensure all features are present
        for feature in self.feature_names:
            if feature not in features.columns:
                features[feature] = 0
        
        # Return only the defined features in the right order
        return features[self.feature_names].values
    
    def _create_labels(self, df: pd.DataFrame) -> np.ndarray:
        """
        Create target labels for training.
        
        Args:
            df: DataFrame with packet data
            
        Returns:
            NumPy array of binary labels (1 = threat, 0 = safe)
        """
        # If the DataFrame already has a 'is_threat' column, use it
        if 'is_threat' in df.columns:
            return df['is_threat'].fillna(0).astype(int).values
        
        # Otherwise, create labels based on rules
        packet_size = pd.to_numeric(df['packet_size'], errors='coerce').fillna(0) if 'packet_size' in df.columns else 0
        
        # Extract ports for analysis
        def extract_port(ip_port):
            if isinstance(ip_port, str) and ':' in ip_port:
                try:
                    return int(ip_port.split(':')[-1])
                except:
                    return 0
            return 0
            
        src_port = df['src_ip'].apply(extract_port) if 'src_ip' in df.columns else 0
        dst_port = df['dest_ip'].apply(extract_port) if 'dest_ip' in df.columns else 0
        
        # Define threat conditions (more sophisticated than the original repo)
        is_threat = (
            # Unusually large packets
            (packet_size > 1500) | 
            # Known vulnerability ports
            (dst_port.isin([445, 135, 139, 3389, 21, 22, 23])) |
            # Suspicious flag combinations (if present)
            (df['tcp_flags'].str.contains('SF|FPU|XMAS', case=False, na=False) 
             if 'tcp_flags' in df.columns else False)
        )
        
        return is_threat.astype(int).values
    
    def _generate_synthetic_data(self, n_samples: int = 1000) -> pd.DataFrame:
        """
        Generate synthetic network packet data for training.
        Note: This method is only for training and testing purposes
        and should not be used in production.
        
        Args:
            n_samples: Number of samples to generate
            
        Returns:
            DataFrame with synthetic packet data
        """
        print(f"WARNING: Using synthetic data generation. This should only be used for testing.")
        print(f"In production environments, use real network data for model training.")
        
        # Import the real data generator only when needed
        try:
            from ..integrated_system.port_range_helper import parse_port_range
            from enhanced_training_data import generate_training_data
            
            # Use the real data generator instead of static data
            print(f"Attempting to use enhanced_training_data module for realistic data generation")
            return generate_training_data(num_samples=n_samples)
            
        except ImportError as e:
            print(f"Could not import enhanced data generator: {e}")
            print(f"Falling back to minimal generator for testing only")
            
            # Only as an absolute fallback for testing
            columns = ['protocol', 'packet_size', 'tcp_flags', 'src_ip', 'dest_ip', 'is_threat']
            return pd.DataFrame(columns=columns)
