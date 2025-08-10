"""
Production ML Engine for Network Intrusion Detection System
Handles real-time threat classification for Snort alerts
"""

import os
import sys
import numpy as np
import joblib
import logging
from datetime import datetime, timedelta
from django.conf import settings
from django.utils import timezone

# Setup logging
logger = logging.getLogger(__name__)

class MLThreatClassifier:
    """
    Production ML engine for classifying network threats
    Loads trained models and preprocessors for real-time prediction
    """
    
    def __init__(self, model_dir=None):
        if model_dir is None:
            model_dir = os.path.join(settings.BASE_DIR, 'ml_models')
        
        self.model_dir = model_dir
        self.classifier = None
        self.preprocessor_components = {}
        self.feature_columns = None
        self.is_loaded = False
        
        # Model performance thresholds
        self.high_confidence_threshold = 0.8
        self.medium_confidence_threshold = 0.6
        
        # Feature mapping for Snort alerts to KDD features
        self.snort_to_kdd_mapping = self._initialize_feature_mapping()
        
        # Load models on initialization
        self._load_models()
    
    def _initialize_feature_mapping(self):
        """Initialize mapping from Snort alert features to KDD dataset features"""
        return {
            # Direct mappings
            'protocol': 'protocol_type',
            'source_port': 'src_port_mapped',
            'destination_port': 'dst_port_mapped',
            'severity': 'severity',
            
            # Computed mappings (will be calculated from alert context)
            'duration': 'duration',
            'src_bytes': 'src_bytes',
            'dst_bytes': 'dst_bytes',
            'count': 'count',
            'srv_count': 'srv_count',
            'same_srv_rate': 'same_srv_rate',
            'diff_srv_rate': 'diff_srv_rate',
            'dst_host_count': 'dst_host_count',
            'dst_host_srv_count': 'dst_host_srv_count'
        }
    
    def _load_models(self):
        """Load the trained classifier and preprocessing components"""
        try:
            # Try to load available models in order of preference
            model_files = [
                'random_forest_model.pkl',
                'gradient_boosting_model.pkl', 
                'logistic_regression_model.pkl'
            ]
            
            classifier_loaded = False
            for model_file in model_files:
                classifier_path = os.path.join(self.model_dir, model_file)
                if os.path.exists(classifier_path):
                    self.classifier = joblib.load(classifier_path)
                    logger.info(f"Loaded {model_file} successfully")
                    classifier_loaded = True
                    break
            
            if not classifier_loaded:
                logger.error("No trained classifier found")
                return False
            
            # Load preprocessing components with correct filenames
            preprocessor_files = {
                'label_encoders': 'label_encoders.pkl',
                'scaler': 'scaler.pkl',
                'feature_columns': 'feature_columns.pkl'
            }
            
            for component_name, filename in preprocessor_files.items():
                filepath = os.path.join(self.model_dir, filename)
                if os.path.exists(filepath):
                    self.preprocessor_components[component_name] = joblib.load(filepath)
                    logger.info(f"Loaded {component_name} successfully")
                else:
                    logger.error(f"Missing preprocessing component: {filename}")
                    return False
            
            # Extract feature columns for easier access
            self.feature_columns = self.preprocessor_components['feature_columns']
            self.is_loaded = True
            
            logger.info("ML Threat Classifier loaded successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error loading ML models: {str(e)}")
            self.is_loaded = False
            return False
    
    def _extract_features_from_snort_alert(self, alert, context_data=None):
        """
        Extract KDD-compatible features from a Snort alert
        
        Args:
            alert: SnortAlert model instance
            context_data: Additional context data for feature computation
            
        Returns:
            dict: Feature dictionary compatible with KDD dataset
        """
        # Initialize features with default values
        features = {
            'duration': 0,
            'protocol_type': self._normalize_protocol(alert.protocol),
            'service': self._map_service_from_port(alert.destination_port),
            'flag': 'SF',  # Default to normal flag
            'src_bytes': 0,
            'dst_bytes': 0,
            'land': int(alert.source_ip == alert.destination_ip),
            'wrong_fragment': 0,
            'urgent': 0,
            'hot': 0,
            'num_failed_logins': 0,
            'logged_in': 1,  # Assume logged in for simplicity
            'num_compromised': 0,
            'root_shell': 0,
            'su_attempted': 0,
            'num_root': 0,
            'num_file_creations': 0,
            'num_shells': 0,
            'num_access_files': 0,
            'num_outbound_cmds': 0,
            'is_host_login': 0,
            'is_guest_login': 0,
            'count': 1,
            'srv_count': 1,
            'serror_rate': 0.0,
            'srv_serror_rate': 0.0,
            'rerror_rate': 0.0,
            'srv_rerror_rate': 0.0,
            'same_srv_rate': 1.0,
            'diff_srv_rate': 0.0,
            'srv_diff_host_rate': 0.0,
            'dst_host_count': 1,
            'dst_host_srv_count': 1,
            'dst_host_same_srv_rate': 1.0,
            'dst_host_diff_srv_rate': 0.0,
            'dst_host_same_src_port_rate': 1.0,
            'dst_host_srv_diff_host_rate': 0.0,
            'dst_host_serror_rate': 0.0,
            'dst_host_srv_serror_rate': 0.0,
            'dst_host_rerror_rate': 0.0,
            'dst_host_srv_rerror_rate': 0.0
        }
        
        # Use context data if provided to compute more accurate features
        if context_data:
            features.update(self._compute_contextual_features(alert, context_data))
        else:
            # Compute basic features from signature and severity
            features.update(self._compute_signature_based_features(alert))
        
        return features
    
    def _normalize_protocol(self, protocol):
        """Normalize protocol to KDD format"""
        protocol_map = {
            'TCP': 'tcp',
            'UDP': 'udp',
            'ICMP': 'icmp',
            'IP': 'tcp'  # Default mapping
        }
        return protocol_map.get(protocol.upper(), 'tcp')
    
    def _map_service_from_port(self, port):
        """Map port number to service name"""
        common_ports = {
            20: 'ftp_data', 21: 'ftp', 22: 'ssh', 23: 'telnet',
            25: 'smtp', 53: 'domain', 80: 'http', 110: 'pop_3',
            143: 'imap4', 443: 'https', 993: 'imaps', 995: 'pop_3s'
        }
        return common_ports.get(port, 'other')
    
    def _compute_signature_based_features(self, alert):
        """Compute features based on Snort signature analysis"""
        features = {}
        
        signature_lower = alert.signature.lower()
        
        # Check for attack indicators in signature
        attack_indicators = [
            'trojan', 'backdoor', 'exploit', 'overflow', 'injection',
            'scan', 'probe', 'dos', 'flood', 'suspicious'
        ]
        
        # Adjust features based on signature content
        if any(indicator in signature_lower for indicator in attack_indicators):
            features.update({
                'hot': 1,
                'num_compromised': 1,
                'serror_rate': 0.5,
                'srv_serror_rate': 0.5,
            })
        
        # Port-based adjustments
        if alert.destination_port in [21, 23, 25, 53, 80, 443]:
            features['logged_in'] = 1
        
        # Severity-based adjustments
        if alert.severity == 1:  # High severity
            features.update({
                'hot': 1,
                'urgent': 1,
                'num_compromised': 1
            })
        elif alert.severity == 2:  # Medium severity
            features['hot'] = 1
        
        return features
    
    def _compute_contextual_features(self, alert, context_data):
        """Compute features using contextual information"""
        features = {}
        
        # Extract context information
        src_ip_stats = context_data.get('src_ip_stats', {})
        dst_ip_stats = context_data.get('dst_ip_stats', {})
        time_window_stats = context_data.get('time_window_stats', {})
        
        # Update features based on context
        if src_ip_stats:
            features.update({
                'count': min(src_ip_stats.get('alert_count', 1), 500),
                'same_srv_rate': src_ip_stats.get('same_service_rate', 1.0),
                'diff_srv_rate': src_ip_stats.get('different_service_rate', 0.0)
            })
        
        if dst_ip_stats:
            features.update({
                'dst_host_count': min(dst_ip_stats.get('connection_count', 1), 255),
                'dst_host_srv_count': min(dst_ip_stats.get('service_count', 1), 255)
            })
        
        return features
    
    def predict_threat(self, alert, context_data=None):
        """
        Predict if an alert represents a threat
        
        Args:
            alert: SnortAlert model instance
            context_data: Optional context data for better prediction
            
        Returns:
            dict: Prediction results with confidence scores
        """
        if not self.is_loaded:
            logger.warning("ML classifier not loaded, attempting to reload...")
            if not self._load_models():
                return self._get_default_prediction(alert)
        
        try:
            # Extract features
            features = self._extract_features_from_snort_alert(alert, context_data)
            
            # Prepare features for prediction
            processed_features = self._preprocess_features(features)
            
            # Make prediction
            prediction = self.classifier.predict(processed_features)[0]
            
            # Get prediction probability if available
            if hasattr(self.classifier, 'predict_proba'):
                probabilities = self.classifier.predict_proba(processed_features)[0]
                confidence = float(probabilities[prediction])
                attack_probability = float(probabilities[1])
            else:
                confidence = 0.8 if prediction == 1 else 0.9
                attack_probability = float(prediction)
            
            # Determine threat level
            threat_level = self._determine_threat_level(attack_probability)
            
            # Prepare result
            result = {
                'is_threat': bool(prediction),
                'threat_probability': attack_probability,
                'confidence': confidence,
                'threat_level': threat_level,
                'model_prediction': int(prediction),
                'algorithm_used': type(self.classifier).__name__,
                'timestamp': timezone.now()
            }
            
            logger.info(f"ML prediction for alert {alert.id}: {result}")
            return result
            
        except Exception as e:
            logger.error(f"Error during ML prediction: {str(e)}")
            return self._get_default_prediction(alert)
    
    def _preprocess_features(self, features):
        """Preprocess features using loaded preprocessor components"""
        # Create DataFrame from features
        import pandas as pd
        df = pd.DataFrame([features])
        
        # Ensure all expected columns are present
        for col in self.feature_columns:
            if col not in df.columns:
                df[col] = 0
        
        # Select only the features used in training
        df = df[self.feature_columns]
        
        # Encode categorical features
        label_encoders = self.preprocessor_components['label_encoders']
        categorical_features = ['protocol_type', 'service', 'flag']
        
        for col in categorical_features:
            if col in df.columns and col in label_encoders:
                try:
                    df[col] = label_encoders[col].transform(df[col].astype(str))
                except ValueError:
                    # Handle unseen categories
                    df[col] = 0
        
        # Scale features
        scaler = self.preprocessor_components['scaler']
        scaled_features = scaler.transform(df)
        
        return scaled_features
    
    def _determine_threat_level(self, attack_probability):
        """Determine threat level based on prediction probability"""
        if attack_probability >= self.high_confidence_threshold:
            return 'HIGH'
        elif attack_probability >= self.medium_confidence_threshold:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _get_default_prediction(self, alert):
        """Return default prediction when ML model is unavailable"""
        # Use rule-based approach as fallback
        is_threat = alert.severity <= 2  # High or medium severity
        
        return {
            'is_threat': is_threat,
            'threat_probability': 0.7 if is_threat else 0.3,
            'confidence': 0.5,
            'threat_level': 'MEDIUM' if is_threat else 'LOW',
            'model_prediction': 1 if is_threat else 0,
            'algorithm_used': 'RuleBased_Fallback',
            'timestamp': timezone.now()
        }
    
    def get_model_info(self):
        """Get information about the loaded model"""
        if not self.is_loaded:
            return {'status': 'not_loaded', 'error': 'ML models not loaded'}
        
        return {
            'status': 'loaded',
            'algorithm': type(self.classifier).__name__,
            'model_dir': self.model_dir,
            'feature_count': len(self.feature_columns),
            'has_probability': hasattr(self.classifier, 'predict_proba'),
            'thresholds': {
                'high_confidence': self.high_confidence_threshold,
                'medium_confidence': self.medium_confidence_threshold
            }
        }
    
    def reload_models(self):
        """Reload ML models (useful after retraining)"""
        logger.info("Reloading ML models...")
        return self._load_models()


# Lazy-loading ML engine that handles Django settings properly
class LazyMLEngine:
    """Lazy-loading ML engine that handles Django settings properly"""
    
    def __init__(self):
        self._engine = None
    
    def _get_engine(self):
        """Get or create the ML engine instance"""
        if self._engine is None:
            try:
                from django.conf import settings
                models_dir = os.path.join(settings.BASE_DIR, 'ml_models')
            except:
                # Fallback to relative path if Django settings not available
                models_dir = 'ml_models'
            
            # Fix: Use correct parameter name
            self._engine = MLThreatClassifier(model_dir=models_dir)
        return self._engine
    
    def predict_threat(self, alert, context_data=None):
        """Predict threat using lazy-loaded engine"""
        return self._get_engine().predict_threat(alert, context_data)
    
    def get_model_stats(self):
        """Get model stats using lazy-loaded engine"""
        
        return self._get_engine().get_model_info()
    
    def load_models(self):
        """Load models using lazy-loaded engine"""
        return self._get_engine().reload_models()


# Global lazy ML engine instance
ml_engine = LazyMLEngine()


# Convenience functions for Django views and services
def predict_snort_alert_threat(alert, context_data=None):
    """
    Convenience function to predict threat for a Snort alert
    
    Args:
        alert: SnortAlert model instance
        context_data: Optional context data
        
    Returns:
        dict: Prediction results
    """
    return ml_engine.predict_threat(alert, context_data)


def get_ml_model_status():
    """Get the current status of the ML classifier"""
    return ml_engine.get_model_stats()


def reload_ml_models():
    """Reload ML models (useful after retraining)"""
    return ml_engine.load_models()


# Example usage and testing
if __name__ == "__main__":
    # This would be run for testing purposes
    print("ML Threat Classifier - Test Mode")
    
    # Initialize classifier
    classifier = MLThreatClassifier()
    
    # Print model info
    print("Model Info:", classifier.get_model_info())

