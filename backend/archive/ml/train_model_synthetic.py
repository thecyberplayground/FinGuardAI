"""
FinGuardAI - ML Model Training with Synthetic Dataset

This script trains the FinGuardAI threat detection model using synthetic network traffic
data that mimics real-world attack patterns and behaviors.
"""

import os
import pandas as pd
import numpy as np
import joblib
import logging
import time
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

# Import our synthetic data generator
from enhanced_training_data import generate_training_data

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('finguardai.ml.training')

def train_threat_detection_model(num_samples=10000, model_output_path=None):
    """
    Train a threat detection model using synthetic network traffic data
    
    Args:
        num_samples: Number of samples to generate for training
        model_output_path: Path to save the trained model
        
    Returns:
        Trained model and accuracy score
    """
    start_time = time.time()
    logger.info("Starting threat detection model training process...")
    
    # Ensure output directory exists
    if model_output_path is None:
        model_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'models')
        os.makedirs(model_dir, exist_ok=True)
        model_output_path = os.path.join(model_dir, 'threat_detection_model.joblib')
    else:
        os.makedirs(os.path.dirname(os.path.abspath(model_output_path)), exist_ok=True)
    
    # Generate synthetic training data
    logger.info(f"Generating {num_samples} synthetic network packets for training...")
    df = generate_training_data(num_samples=num_samples)
    
    logger.info(f"Dataset generated with {len(df)} records")
    
    # Feature selection for our synthetic data
    features = [
        'packet_size', 'src_bytes', 'dst_bytes', 'wrong_fragment', 
        'count', 'error_rate'
    ]
    
    # Add categorical features (one-hot encoded)
    # Convert protocol to one-hot encoding
    protocol_dummies = pd.get_dummies(df['protocol'], prefix='protocol')
    df = pd.concat([df, protocol_dummies], axis=1)
    
    # Add protocol columns to features
    for col in protocol_dummies.columns:
        features.append(col)
    
    # One-hot encode services (limited to top 5 to avoid too many features)
    top_services = df['service'].value_counts().nlargest(5).index
    for service in top_services:
        df[f'service_{service}'] = (df['service'] == service).astype(int)
        features.append(f'service_{service}')
    
    # Ensure all features exist
    for feature in list(features):  # Create a copy of the list to iterate
        if feature not in df.columns:
            logger.warning(f"Feature {feature} not found in dataset, skipping")
            features.remove(feature)
    
    logger.info(f"Using {len(features)} features: {', '.join(features)}")
    
    # Prepare feature matrix and target variable
    X = df[features]
    y = df['is_threat']
    
    # Split data into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    logger.info(f"Training set: {X_train.shape[0]} samples")
    logger.info(f"Testing set: {X_test.shape[0]} samples")
    
    # Train Random Forest model
    logger.info("Training Random Forest classifier...")
    model = RandomForestClassifier(
        n_estimators=100, 
        max_depth=10,
        random_state=42,
        n_jobs=-1  # Use all available cores
    )
    
    model.fit(X_train, y_train)
    
    # Evaluate model
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    
    # Print model performance
    logger.info(f"Model accuracy: {accuracy:.4f}")
    logger.info("\nClassification Report:")
    logger.info("\n" + classification_report(y_test, y_pred))
    
    # Print confusion matrix
    logger.info("\nConfusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    logger.info(f"\n{cm}")
    
    # Calculate performance metrics
    tn, fp, fn, tp = cm.ravel()
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    logger.info(f"True Positives: {tp}, False Positives: {fp}")
    logger.info(f"True Negatives: {tn}, False Negatives: {fn}")
    logger.info(f"Precision: {precision:.4f}, Recall: {recall:.4f}, F1 Score: {f1:.4f}")
    
    # Feature importance
    importances = model.feature_importances_
    feature_importance = pd.DataFrame({
        'Feature': features,
        'Importance': importances
    }).sort_values('Importance', ascending=False)
    
    logger.info("\nFeature Importance:")
    for i, row in feature_importance.head(10).iterrows():
        logger.info(f"{row['Feature']}: {row['Importance']:.4f}")
    
    # Save model
    logger.info(f"Saving trained model to {model_output_path}")
    joblib.dump(model, model_output_path)
    
    # Also save feature list for inference
    feature_list_path = os.path.join(os.path.dirname(model_output_path), 'model_features.joblib')
    joblib.dump(features, feature_list_path)
    logger.info(f"Saved feature list to {feature_list_path}")
    
    # Calculate and log execution time
    duration = time.time() - start_time
    logger.info(f"Model training completed in {duration:.2f} seconds")
    
    return model, accuracy, features

def predict_threat(model, features_list, packet_data):
    """
    Make a threat prediction on a single packet
    
    Args:
        model: Trained model
        features_list: List of features used by the model
        packet_data: Dictionary with packet features
        
    Returns:
        Dictionary with prediction results
    """
    # Create a DataFrame with required features
    df = pd.DataFrame([packet_data])
    
    # Handle categorical features (protocols)
    protocols = [col for col in features_list if col.startswith('protocol_')]
    for protocol in protocols:
        protocol_name = protocol.replace('protocol_', '')
        df[protocol] = 1 if packet_data.get('protocol', '') == protocol_name else 0
    
    # Handle service features
    service_features = [col for col in features_list if col.startswith('service_')]
    for service_feature in service_features:
        service_name = service_feature.replace('service_', '')
        df[service_feature] = 1 if packet_data.get('service', '') == service_name else 0
    
    # Ensure all model features exist in the DataFrame
    for feature in features_list:
        if feature not in df.columns:
            df[feature] = 0  # Default value if feature is missing
    
    # Select only the features used by the model
    X = df[features_list]
    
    # Make prediction
    is_threat = model.predict(X)[0]
    threat_probability = model.predict_proba(X)[0][1]  # Probability of being a threat
    
    # Determine threat level based on probability
    if threat_probability < 0.3:
        threat_level = "low"
    elif threat_probability < 0.7:
        threat_level = "medium"
    else:
        threat_level = "high"
    
    # Return prediction results
    return {
        "is_threat": bool(is_threat),
        "threat_probability": float(threat_probability),
        "threat_level": threat_level
    }

if __name__ == "__main__":
    logger.info("Starting FinGuardAI threat detection model training...")
    model, accuracy, features = train_threat_detection_model(num_samples=10000)
    
    if model is not None:
        logger.info(f"Model training successful with accuracy: {accuracy:.4f}")
        
        # Test a prediction with a few different packet types
        test_packets = [
            {
                'protocol': 'tcp',
                'packet_size': 1200,
                'src_bytes': 1000,
                'dst_bytes': 200,
                'service': 'http',
                'wrong_fragment': 0,
                'count': 5,
                'error_rate': 0.01
            },
            {
                'protocol': 'tcp',
                'packet_size': 64,
                'src_bytes': 60,
                'dst_bytes': 4,
                'service': 'ssh',
                'wrong_fragment': 0,
                'count': 120,
                'error_rate': 0.8
            },
            {
                'protocol': 'icmp',
                'packet_size': 84,
                'src_bytes': 42,
                'dst_bytes': 42,
                'service': 'echo-request',
                'wrong_fragment': 1,
                'count': 50,
                'error_rate': 0.4
            }
        ]
        
        logger.info("Testing model with sample packets:")
        for i, packet in enumerate(test_packets):
            prediction = predict_threat(model, features, packet)
            logger.info(f"Packet {i+1} ({packet['protocol']}, size: {packet['packet_size']}): {prediction}")
        
        logger.info("Model is ready for integration with FinGuardAI threat detection system")
