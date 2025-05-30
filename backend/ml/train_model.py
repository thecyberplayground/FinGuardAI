"""
FinGuardAI - Machine Learning Model Training

This module handles training of the ML model for network threat detection.
It leverages scikit-learn's Random Forest classifier to train on packet features
and detect potentially malicious network activity.
"""

import os
import pandas as pd
import numpy as np
import joblib
import logging
from typing import Tuple, Optional
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

from feature_extraction import preprocess_for_training

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('fingurardai.ml')

# Configuration
MODEL_DIR = os.path.join(os.path.dirname(__file__), 'models')
DEFAULT_MODEL_PATH = os.path.join(MODEL_DIR, 'threat_detection_model.joblib')
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')
NETWORK_DATA_PATH = os.path.join(DATA_DIR, 'network_data.csv')

def ensure_dirs_exist():
    """Ensure required directories exist"""
    os.makedirs(MODEL_DIR, exist_ok=True)
    os.makedirs(DATA_DIR, exist_ok=True)

def load_training_data() -> Tuple[pd.DataFrame, Optional[pd.Series]]:
    """
    Load network packet data for training.
    
    Returns:
        Tuple of (features_df, labels_series)
        If no labels found, labels_series will be None
    """
    if not os.path.exists(NETWORK_DATA_PATH):
        logger.warning(f"Training data file not found: {NETWORK_DATA_PATH}")
        return pd.DataFrame(), None
    
    try:
        data = pd.read_csv(NETWORK_DATA_PATH)
        logger.info(f"Loaded {len(data)} records from {NETWORK_DATA_PATH}")
        
        # Check if the data has labels
        if 'is_threat' not in data.columns:
            logger.warning("No 'is_threat' column found in training data")
            return data, None
        
        features_df = data.drop(['is_threat'], axis=1)
        labels = data['is_threat']
        
        return features_df, labels
    
    except Exception as e:
        logger.error(f"Error loading training data: {str(e)}")
        return pd.DataFrame(), None

def train_threat_detection_model(features: pd.DataFrame, labels: pd.Series, 
                                model_path: str = DEFAULT_MODEL_PATH) -> RandomForestClassifier:
    """
    Train a Random Forest model for threat detection.
    
    Args:
        features: DataFrame with packet features
        labels: Series with labels (1 for threat, 0 for safe)
        model_path: Path to save the trained model
        
    Returns:
        Trained RandomForestClassifier model
    """
    logger.info("Preprocessing features for training")
    feature_matrix, feature_names = preprocess_for_training(features)
    
    # Split data for training and validation
    X_train, X_test, y_train, y_test = train_test_split(
        feature_matrix, labels, test_size=0.2, random_state=42
    )
    
    logger.info(f"Training Random Forest model on {len(X_train)} samples")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=None,
        min_samples_split=2,
        random_state=42,
        n_jobs=-1
    )
    
    model.fit(X_train, y_train)
    
    # Evaluate the model
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    conf_matrix = confusion_matrix(y_test, y_pred)
    
    logger.info(f"Model evaluation metrics:")
    logger.info(f"  Accuracy:  {accuracy:.4f}")
    logger.info(f"  Precision: {precision:.4f}")
    logger.info(f"  Recall:    {recall:.4f}")
    logger.info(f"  F1 Score:  {f1:.4f}")
    logger.info(f"  Confusion Matrix:\n{conf_matrix}")
    
    # Get feature importances
    feature_importance = dict(zip(feature_names, model.feature_importances_))
    top_features = sorted(feature_importance.items(), key=lambda x: x[1], reverse=True)[:10]
    logger.info("Top 10 important features:")
    for feature, importance in top_features:
        logger.info(f"  {feature}: {importance:.4f}")
    
    # Save model and metadata
    ensure_dirs_exist()
    joblib.dump(model, model_path)
    
    # Save model metadata
    metadata = {
        'feature_names': feature_names,
        'training_date': datetime.now().isoformat(),
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1_score': f1,
        'top_features': top_features
    }
    
    metadata_path = os.path.splitext(model_path)[0] + '_metadata.joblib'
    joblib.dump(metadata, metadata_path)
    
    logger.info(f"Model and metadata saved to {model_path}")
    return model

def initialize_model(train_if_missing: bool = True) -> Optional[RandomForestClassifier]:
    """
    Load the existing model or train a new one if requested.
    
    Args:
        train_if_missing: Whether to train a new model if none exists
        
    Returns:
        Loaded or newly trained model, or None if unavailable
    """
    # Check if model exists
    if os.path.exists(DEFAULT_MODEL_PATH):
        try:
            logger.info(f"Loading existing model from {DEFAULT_MODEL_PATH}")
            return joblib.load(DEFAULT_MODEL_PATH)
        except Exception as e:
            logger.error(f"Error loading model: {str(e)}")
            if not train_if_missing:
                return None
    
    # Train new model if requested
    if train_if_missing:
        logger.info("No existing model found, training new model")
        features, labels = load_training_data()
        
        if features.empty or labels is None:
            logger.error("Cannot train model: no training data available")
            return None
        
        return train_threat_detection_model(features, labels)
    
    logger.warning("No model available and training not requested")
    return None

if __name__ == "__main__":
    # If run directly, train a new model
    logger.info("Starting model training")
    
    features, labels = load_training_data()
    if features.empty or labels is None:
        logger.error("No valid training data found. Please generate training data first.")
    else:
        trained_model = train_threat_detection_model(features, labels)
        logger.info("Model training complete")
