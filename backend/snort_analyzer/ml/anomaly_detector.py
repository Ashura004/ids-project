import os
import pickle
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from django.utils import timezone
from django.conf import settings
from django.db import models
import joblib
import logging

logger = logging.getLogger(__name__)

class MLAnomalyDetector:
    """
    Machine Learning-based Anomaly Detection System
    Uses multiple ML models for comprehensive threat detection
    """
    
    def __init__(self, model_path=None):
        self.model_path = model_path or os.path.join(settings.BASE_DIR, 'ml_models')
        self.ensure_model_directory()
        
        # ML Models
        self.isolation_forest = None
        self.random_forest = None
        self.scaler = StandardScaler()
        
        # Encoders for categorical features
        self.protocol_encoder = LabelEncoder()
        self.ip_encoder = LabelEncoder()
        
        # Model metadata
        self.is_trained = False
        self.feature_names = []
        self.training_stats = {}
        
        # Load existing models if available
        self.load_models()
    
    def ensure_model_directory(self):
        """Create model directory if it doesn't exist"""
        if not os.path.exists(self.model_path):
            os.makedirs(self.model_path)
    
    def extract_features(self, alerts_queryset):
        """
        Extract comprehensive features from alerts for ML training
        """
        features_list = []
        labels_list = []
        
        for alert in alerts_queryset:
            try:
                # Basic features
                features = {
                    # Protocol encoding
                    'protocol_tcp': 1 if alert.protocol.lower() == 'tcp' else 0,
                    'protocol_udp': 1 if alert.protocol.lower() == 'udp' else 0,
                    'protocol_icmp': 1 if alert.protocol.lower() == 'icmp' else 0,
                    
                    # Severity features
                    'severity': alert.severity,
                    'severity_high': 1 if alert.severity == 1 else 0,
                    'severity_medium': 1 if alert.severity == 2 else 0,
                    'severity_low': 1 if alert.severity == 3 else 0,
                    
                    # Port features
                    'source_port': alert.source_port if alert.source_port else 0,
                    'dest_port': alert.destination_port if alert.destination_port else 0,
                    'is_well_known_port': 1 if (alert.destination_port and alert.destination_port <= 1024) else 0,
                    
                    # IP features
                    'is_internal_src': 1 if self.is_internal_ip(alert.source_ip) else 0,
                    'is_internal_dst': 1 if self.is_internal_ip(alert.destination_ip) else 0,
                    'is_external_to_internal': 1 if (not self.is_internal_ip(alert.source_ip) and self.is_internal_ip(alert.destination_ip)) else 0,
                    
                    # Time features
                    'hour_of_day': alert.timestamp.hour if alert.timestamp else 0,
                    'day_of_week': alert.timestamp.weekday() if alert.timestamp else 0,
                    'is_weekend': 1 if (alert.timestamp and alert.timestamp.weekday() >= 5) else 0,
                    'is_night_time': 1 if (alert.timestamp and (alert.timestamp.hour < 6 or alert.timestamp.hour > 22)) else 0,
                    
                    # Signature features
                    'signature_length': len(alert.signature) if alert.signature else 0,
                    'signature_id': alert.signature_id if alert.signature_id else 0,
                }
                
                # Text-based features from signature
                signature_lower = alert.signature.lower() if alert.signature else ""
                
                # Threat keywords
                features.update({
                    'has_malware_keywords': 1 if any(word in signature_lower for word in ['malware', 'trojan', 'virus', 'backdoor', 'rootkit']) else 0,
                    'has_attack_keywords': 1 if any(word in signature_lower for word in ['attack', 'exploit', 'injection', 'overflow', 'payload']) else 0,
                    'has_scan_keywords': 1 if any(word in signature_lower for word in ['scan', 'probe', 'reconnaissance', 'enumeration']) else 0,
                    'has_normal_keywords': 1 if any(word in signature_lower for word in ['ping', 'echo', 'normal', 'legitimate', 'dns', 'http']) else 0,
                    'has_suspicious_keywords': 1 if any(word in signature_lower for word in ['suspicious', 'unusual', 'unauthorized', 'brute force']) else 0,
                })
                
                # Behavioral features (if we have historical data)
                features.update(self.get_behavioral_features(alert))
                
                features_list.append(features)
                
                # Use existing anomaly flag as label for supervised learning
                labels_list.append(1 if alert.is_anomalous else 0)
                
            except Exception as e:
                logger.error(f"Error extracting features from alert {alert.id}: {e}")
                continue
        
        # Convert to DataFrame
        df = pd.DataFrame(features_list)
        labels = np.array(labels_list)
        
        return df, labels
    
    def get_behavioral_features(self, alert):
        """
        Extract behavioral features based on historical patterns
        """
        from snort_analyzer.models import SnortAlert
        
        try:
            # Time window for behavioral analysis
            time_window = timezone.now() - timedelta(hours=24)
            
            # Historical alerts from same source IP
            src_alerts = SnortAlert.objects.filter(
                source_ip=alert.source_ip,
                timestamp__gte=time_window
            )
            
            # Historical alerts to same destination
            dst_alerts = SnortAlert.objects.filter(
                destination_ip=alert.destination_ip,
                timestamp__gte=time_window
            )
            
            return {
                'src_ip_alert_count_24h': src_alerts.count(),
                'dst_ip_alert_count_24h': dst_alerts.count(),
                'src_ip_unique_dests': src_alerts.values('destination_ip').distinct().count(),
                'dst_ip_unique_sources': dst_alerts.values('source_ip').distinct().count(),
                'src_ip_protocol_diversity': src_alerts.values('protocol').distinct().count(),
                'src_ip_severity_avg': src_alerts.aggregate(avg_sev=models.Avg('severity'))['avg_sev'] or 3.0,
            }
        except Exception as e:
            logger.error(f"Error calculating behavioral features: {e}")
            return {
                'src_ip_alert_count_24h': 0,
                'dst_ip_alert_count_24h': 0,
                'src_ip_unique_dests': 0,
                'dst_ip_unique_sources': 0,
                'src_ip_protocol_diversity': 0,
                'src_ip_severity_avg': 3.0,
            }
    
    def is_internal_ip(self, ip_str):
        """Check if IP is in private/internal range"""
        try:
            import ipaddress
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private
        except:
            return False
    
    def train_models(self, alerts_queryset, retrain=False):
        """
        Train ML models on historical alert data
        """
        logger.info("Starting ML model training...")
        
        if self.is_trained and not retrain:
            logger.info("Models already trained. Use retrain=True to force retraining.")
            return
        
        # Extract features
        features_df, labels = self.extract_features(alerts_queryset)
        
        if len(features_df) < 50:
            logger.warning(f"Insufficient data for training: {len(features_df)} samples. Need at least 50.")
            return
        
        logger.info(f"Training on {len(features_df)} samples with {len(features_df.columns)} features")
        
        # Store feature names
        self.feature_names = features_df.columns.tolist()
        
        # Handle missing values
        features_df = features_df.fillna(0)
        
        # Split data for supervised learning
        X_train, X_test, y_train, y_test = train_test_split(
            features_df, labels, test_size=0.2, random_state=42, stratify=labels
        )
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train Isolation Forest (Unsupervised)
        logger.info("Training Isolation Forest...")
        self.isolation_forest = IsolationForest(
            contamination=0.1,  # Expect 10% anomalies
            random_state=42,
            n_estimators=100
        )
        self.isolation_forest.fit(X_train_scaled)
        
        # Train Random Forest (Supervised)
        logger.info("Training Random Forest...")
        self.random_forest = RandomForestClassifier(
            n_estimators=100,
            random_state=42,
            class_weight='balanced'  # Handle class imbalance
        )
        self.random_forest.fit(X_train_scaled, y_train)
        
        # Evaluate models
        self.evaluate_models(X_test_scaled, y_test)
        
        # Save models
        self.save_models()
        
        self.is_trained = True
        logger.info("ML model training completed successfully!")
    
    def evaluate_models(self, X_test, y_test):
        """Evaluate trained models"""
        try:
            # Random Forest evaluation
            rf_predictions = self.random_forest.predict(X_test)
            rf_probabilities = self.random_forest.predict_proba(X_test)[:, 1]
            
            logger.info("Random Forest Classification Report:")
            logger.info(f"\n{classification_report(y_test, rf_predictions)}")
            
            # Isolation Forest evaluation
            if_predictions = self.isolation_forest.predict(X_test)
            if_predictions = [1 if pred == -1 else 0 for pred in if_predictions]  # Convert to binary
            
            logger.info("Isolation Forest Classification Report:")
            logger.info(f"\n{classification_report(y_test, if_predictions)}")
            
            # Store evaluation stats
            self.training_stats = {
                'samples_trained': len(X_test) * 5,  # Approximate total samples
                'features_count': len(self.feature_names),
                'rf_accuracy': sum(rf_predictions == y_test) / len(y_test),
                'if_accuracy': sum(np.array(if_predictions) == y_test) / len(y_test),
                'training_date': timezone.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error evaluating models: {e}")
    
    def predict_anomaly(self, alert):
        """
        Predict if an alert is anomalous using trained ML models
        Returns: (is_anomalous: bool, anomaly_score: float, confidence: float)
        """
        
        signature_lower = alert.signature.lower() if alert.signature else ""
        
       
        strong_normal_indicators = [
            'icmp ping', 'ping request', 'ping reply', 'echo request', 'echo reply',
            'normal', 'legitimate', 'standard'
        ]
        
        if any(indicator in signature_lower for indicator in strong_normal_indicators):
            if alert.protocol.lower() == 'icmp' and alert.severity >= 3:
                return False, 0.1, 0.95  
        
        if not self.is_trained:
            print("Models not trained. Using fallback rule-based detection.")
            return self.fallback_rule_based_detection(alert)
        
        try:
            # Extract features for single alert
            features = self.extract_single_alert_features(alert)
            features_df = pd.DataFrame([features])
            
            # Ensure all expected features are present
            for feature in self.feature_names:
                if feature not in features_df.columns:
                    features_df[feature] = 0
            
            # Reorder columns to match training
            features_df = features_df[self.feature_names]
            
            # Scale features
            features_scaled = self.scaler.transform(features_df)
            
            # Isolation Forest prediction
            if_prediction = self.isolation_forest.predict(features_scaled)[0]
            if_score = self.isolation_forest.decision_function(features_scaled)[0]
            
            # Random Forest prediction
            rf_prediction = self.random_forest.predict(features_scaled)[0]
            rf_probability = self.random_forest.predict_proba(features_scaled)[0]
            
            # IMPROVED ENSEMBLE DECISION
            if_anomalous = if_prediction == -1
            rf_anomalous = rf_prediction == 1
            
            # Special handling for ICMP ping
            if alert.protocol.lower() == 'icmp' and alert.severity >= 3:
                if any(word in signature_lower for word in ['ping', 'echo']):
                    # Force normal for clear ICMP ping traffic
                    return False, 0.1, 0.9
            
            # Ensemble decision with improved logic
            if if_anomalous and rf_anomalous:
                # Both models agree it's anomalous
                is_anomalous = True
                confidence = 0.9
                anomaly_score = max(abs(if_score), rf_probability[1])
            elif if_anomalous or rf_anomalous:
                # One model thinks it's anomalous - be more conservative
                if rf_anomalous and rf_probability[1] > 0.7:
                    # High confidence from supervised model
                    is_anomalous = True
                    confidence = 0.7
                    anomaly_score = rf_probability[1]
                else:
                    # Low confidence - lean towards normal
                    is_anomalous = False
                    confidence = 0.6
                    anomaly_score = (abs(if_score) + rf_probability[1]) / 2
            else:
                # Both models think it's normal
                is_anomalous = False
                confidence = 0.8
                anomaly_score = min(abs(if_score), rf_probability[1])
            
            # Normalize anomaly score to 0-1 range
            anomaly_score = min(max(anomaly_score, 0.0), 1.0)
            
            return is_anomalous, anomaly_score, confidence
        
        except Exception as e:
            print(f"Error in ML prediction: {e}")
            return self.fallback_rule_based_detection(alert)
    
    def extract_single_alert_features(self, alert):
        """Extract features from a single alert for prediction"""
        # Basic features
        features = {
            'protocol_tcp': 1 if alert.protocol.lower() == 'tcp' else 0,
            'protocol_udp': 1 if alert.protocol.lower() == 'udp' else 0,
            'protocol_icmp': 1 if alert.protocol.lower() == 'icmp' else 0,
            'severity': alert.severity,
            'severity_high': 1 if alert.severity == 1 else 0,
            'severity_medium': 1 if alert.severity == 2 else 0,
            'severity_low': 1 if alert.severity == 3 else 0,  # ICMP ping should be severity 3
            'source_port': alert.source_port if alert.source_port else 0,
            'dest_port': alert.destination_port if alert.destination_port else 0,
            'is_well_known_port': 1 if (alert.destination_port and alert.destination_port <= 1024) else 0,
            'is_internal_src': 1 if self.is_internal_ip(alert.source_ip) else 0,
            'is_internal_dst': 1 if self.is_internal_ip(alert.destination_ip) else 0,
            'is_external_to_internal': 1 if (not self.is_internal_ip(alert.source_ip) and self.is_internal_ip(alert.destination_ip)) else 0,
            'hour_of_day': alert.timestamp.hour if alert.timestamp else 0,
            'day_of_week': alert.timestamp.weekday() if alert.timestamp else 0,
            'is_weekend': 1 if (alert.timestamp and alert.timestamp.weekday() >= 5) else 0,
            'is_night_time': 1 if (alert.timestamp and (alert.timestamp.hour < 6 or alert.timestamp.hour > 22)) else 0,
            'signature_length': len(alert.signature) if alert.signature else 0,
            'signature_id': alert.signature_id if alert.signature_id else 0,
        }
        
        # Text-based features - THIS IS THE KEY FIX
        signature_lower = alert.signature.lower() if alert.signature else ""
        
        # Enhanced normal keyword detection for ICMP
        normal_icmp_keywords = ['ping', 'echo', 'icmp ping', 'ping request', 'ping reply', 'echo request', 'echo reply']
        has_normal_icmp = any(keyword in signature_lower for keyword in normal_icmp_keywords)
        
        features.update({
            'has_malware_keywords': 1 if any(word in signature_lower for word in ['malware', 'trojan', 'virus', 'backdoor', 'rootkit']) else 0,
            'has_attack_keywords': 1 if any(word in signature_lower for word in ['attack', 'exploit', 'injection', 'overflow', 'payload']) else 0,
            'has_scan_keywords': 1 if any(word in signature_lower for word in ['scan', 'probe', 'reconnaissance', 'enumeration']) else 0,
            'has_normal_keywords': 1 if (has_normal_icmp or any(word in signature_lower for word in ['normal', 'legitimate', 'dns', 'http'])) else 0,
            'has_suspicious_keywords': 1 if any(word in signature_lower for word in ['suspicious', 'unusual', 'unauthorized', 'brute force']) else 0,
            
            # ICMP-specific features
            'is_icmp_ping': 1 if (alert.protocol.lower() == 'icmp' and has_normal_icmp) else 0,
            'is_normal_icmp': 1 if (alert.protocol.lower() == 'icmp' and alert.severity >= 3 and has_normal_icmp) else 0,
        })
        
        # Simplified behavioral features
        features.update({
            'src_ip_alert_count_24h': 0,
            'dst_ip_alert_count_24h': 0,
            'src_ip_unique_dests': 0,
            'dst_ip_unique_sources': 0,
            'src_ip_protocol_diversity': 0,
            'src_ip_severity_avg': 3.0,
        })
        
        return features
    
    def fallback_rule_based_detection(self, alert):
        """Fallback rule-based detection when ML models aren't available"""
        signature_lower = alert.signature.lower() if alert.signature else ""
        
        # High confidence anomalies
        if any(word in signature_lower for word in ['malware', 'trojan', 'exploit', 'injection']):
            return True, 0.9, 0.8
        
        # Medium confidence anomalies
        if any(word in signature_lower for word in ['scan', 'suspicious', 'unauthorized']):
            return True, 0.6, 0.6
        
        # Normal traffic
        if any(word in signature_lower for word in ['ping', 'echo', 'normal', 'dns']):
            return False, 0.1, 0.7
        
        # Default based on severity
        if alert.severity == 1:
            return True, 0.7, 0.5
        elif alert.severity == 2:
            return True, 0.5, 0.4
        else:
            return False, 0.2, 0.3
    
    def save_models(self):
        """Save trained models to disk"""
        try:
            # Save Isolation Forest
            joblib.dump(self.isolation_forest, os.path.join(self.model_path, 'isolation_forest.pkl'))
            
            # Save Random Forest
            joblib.dump(self.random_forest, os.path.join(self.model_path, 'random_forest.pkl'))
            
            # Save Scaler
            joblib.dump(self.scaler, os.path.join(self.model_path, 'scaler.pkl'))
            
            # Save metadata
            metadata = {
                'feature_names': self.feature_names,
                'training_stats': self.training_stats,
                'is_trained': True
            }
            with open(os.path.join(self.model_path, 'metadata.pkl'), 'wb') as f:
                pickle.dump(metadata, f)
            
            logger.info(f"Models saved to {self.model_path}")
            
        except Exception as e:
            logger.error(f"Error saving models: {e}")
    
    def load_models(self):
        """Load trained models from disk"""
        try:
            # Check if models exist
            if_path = os.path.join(self.model_path, 'isolation_forest.pkl')
            rf_path = os.path.join(self.model_path, 'random_forest.pkl')
            scaler_path = os.path.join(self.model_path, 'scaler.pkl')
            metadata_path = os.path.join(self.model_path, 'metadata.pkl')
            
            if all(os.path.exists(path) for path in [if_path, rf_path, scaler_path, metadata_path]):
                # Load models
                self.isolation_forest = joblib.load(if_path)
                self.random_forest = joblib.load(rf_path)
                self.scaler = joblib.load(scaler_path)
                
                # Load metadata
                with open(metadata_path, 'rb') as f:
                    metadata = pickle.load(f)
                
                self.feature_names = metadata.get('feature_names', [])
                self.training_stats = metadata.get('training_stats', {})
                self.is_trained = metadata.get('is_trained', False)
                
                logger.info("Models loaded successfully from disk")
            else:
                logger.info("No existing models found. Training required.")
                
        except Exception as e:
            logger.error(f"Error loading models: {e}")
            self.is_trained = False
    
    def get_model_info(self):
        """Get information about the current models"""
        return {
            'is_trained': self.is_trained,
            'feature_count': len(self.feature_names),
            'training_stats': self.training_stats,
            'models_available': {
                'isolation_forest': self.isolation_forest is not None,
                'random_forest': self.random_forest is not None,
                'scaler': self.scaler is not None
            }
        }


# Global instance
ml_detector = MLAnomalyDetector()