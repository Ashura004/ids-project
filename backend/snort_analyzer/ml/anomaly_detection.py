# snort_analyzer/ml/anomaly_detection.py

import numpy as np
import joblib
import os
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from django.conf import settings
from .feature_engineering import extract_features_for_alert, prepare_training_data

# Define paths for saving/loading models
MODEL_PATH = os.path.join(settings.BASE_DIR, 'ml_models', 'isolation_forest.pkl')
SCALER_PATH = os.path.join(settings.BASE_DIR, 'ml_models', 'scaler.pkl')

def ensure_model_directory():
    """Ensure the directory for ML models exists"""
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)

def train_anomaly_detection_model():
    """
    Train an Isolation Forest model on historical data and save it
    """
    ensure_model_directory()
    
    # Get training data
    X_train = prepare_training_data()
    
    if X_train.shape[0] < 10:  # Need at least some data to train
        print("Not enough data for training")
        return None, None
    
    # Scale the features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    
    # Train Isolation Forest
    model = IsolationForest(
        n_estimators=100,
        max_samples='auto',
        contamination=0.05,  # Assuming 5% of data is anomalous
        random_state=42
    )
    
    model.fit(X_train_scaled)
    
    # Save the model and scaler
    joblib.dump(model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    
    return model, scaler

def load_anomaly_detection_model():
    """
    Load the trained model and scaler
    If they don't exist, train a new model
    """
    try:
        model = joblib.load(MODEL_PATH)
        scaler = joblib.load(SCALER_PATH)
        return model, scaler
    except (FileNotFoundError, EOFError):
        print("Model or scaler not found, training new model...")
        return train_anomaly_detection_model()

def detect_anomaly(alert):
    """
    Detect if an alert is anomalous using the trained model
    Returns (is_anomalous, anomaly_score)
    """
    # Load model and scaler
    model, scaler = load_anomaly_detection_model()
    
    if model is None or scaler is None:
        # Default to non-anomalous if model can't be loaded/trained
        return False, 0.0
    
    # Extract features
    features = extract_features_for_alert(alert)
    
    # Scale features
    features_scaled = scaler.transform(features)
    
    # Predict anomaly (-1 for anomalies, 1 for normal)
    prediction = model.predict(features_scaled)[0]
    
    # Get anomaly score
    anomaly_score = model.score_samples(features_scaled)[0]
    
    # Convert to boolean and return with score
    is_anomalous = prediction == -1
    
    return is_anomalous, -anomaly_score  # Negate score so higher = more anomalous