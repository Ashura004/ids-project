

import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
import joblib
import os

class KDDPreprocessor:
    """Preprocessor for KDD Cup 1999 dataset"""
    
    def __init__(self):
        self.label_encoders = {}
        self.scaler = StandardScaler()
        self.feature_columns = []
        self.target_column = 'labels'
        
    def load_data(self, file_path):
        """Load KDD dataset"""
        print(f"📊 Loading dataset: {file_path}")
        
        # KDD Cup 1999 column names
        column_names = [
            'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
            'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
            'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
            'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
            'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
            'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
            'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
            'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
            'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
            'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'labels'
        ]
        
        # Load data
        if os.path.exists(file_path):
            df = pd.read_csv(file_path)
            if df.columns.tolist() != column_names:
                # If columns don't match, assume no header and assign names
                df = pd.read_csv(file_path, header=None, names=column_names)
        else:
            raise FileNotFoundError(f"Dataset file not found: {file_path}")
            
        print(f"✅ Dataset loaded: {df.shape} samples")
        return df
    
    def preprocess_features(self, df):
        """Preprocess features for ML training"""
        print("🔧 Preprocessing features...")
        
        # Separate features and target
        X = df.drop(columns=[self.target_column]).copy()
        y = df[self.target_column].copy()
        
        # Store feature columns
        self.feature_columns = X.columns.tolist()
        
        # Encode categorical features
        categorical_columns = ['protocol_type', 'service', 'flag']
        
        for col in categorical_columns:
            if col in X.columns:
                le = LabelEncoder()
                X[col] = le.fit_transform(X[col].astype(str))
                self.label_encoders[col] = le
        
        # Scale numerical features
        numerical_columns = X.select_dtypes(include=[np.number]).columns
        X[numerical_columns] = self.scaler.fit_transform(X[numerical_columns])
        
        # Process target variable (binary classification: normal vs attack)
        y_binary = (y != 'normal').astype(int)  # 0 for normal, 1 for attack
        
        print("✅ Feature preprocessing complete")
        print(f"📊 Features: {X.shape[1]}, Samples: {X.shape[0]}")
        print(f"📈 Attack ratio: {y_binary.mean():.2%}")
        
        return X, y_binary
    
    def save_preprocessor(self, save_dir):
        """Save preprocessing components"""
        os.makedirs(save_dir, exist_ok=True)
        
        # Save encoders and scaler
        joblib.dump(self.label_encoders, os.path.join(save_dir, 'label_encoders.pkl'))
        joblib.dump(self.scaler, os.path.join(save_dir, 'scaler.pkl'))
        joblib.dump(self.feature_columns, os.path.join(save_dir, 'feature_columns.pkl'))
        
        print(f"💾 Preprocessor saved to {save_dir}")
    
    def load_preprocessor(self, save_dir):
        """Load preprocessing components"""
        self.label_encoders = joblib.load(os.path.join(save_dir, 'label_encoders.pkl'))
        self.scaler = joblib.load(os.path.join(save_dir, 'scaler.pkl'))
        self.feature_columns = joblib.load(os.path.join(save_dir, 'feature_columns.pkl'))
        
        print(f"📥 Preprocessor loaded from {save_dir}")
    
    def transform_features(self, X):
        """Transform features using fitted preprocessor"""
        X_transformed = X.copy()
        
        # Encode categorical features
        for col, encoder in self.label_encoders.items():
            if col in X_transformed.columns:
                # Handle unseen categories
                X_transformed[col] = X_transformed[col].astype(str)
                mask = X_transformed[col].isin(encoder.classes_)
                X_transformed.loc[~mask, col] = encoder.classes_[0]  # Use first class for unknown
                X_transformed[col] = encoder.transform(X_transformed[col])
        
        # Scale numerical features
        numerical_columns = X_transformed.select_dtypes(include=[np.number]).columns
        X_transformed[numerical_columns] = self.scaler.transform(X_transformed[numerical_columns])
        
        # Ensure correct column order
        X_transformed = X_transformed[self.feature_columns]
        
        return X_transformed

def main():
    """Test preprocessing"""
    preprocessor = KDDPreprocessor()
    
    # Test with sample data
    try:
        df = preprocessor.load_data('kdd_test.csv')
        X, y = preprocessor.preprocess_features(df)
        preprocessor.save_preprocessor('ml_models')
        print("🎉 Preprocessing test successful!")
        return True
    except Exception as e:
        print(f"❌ Preprocessing test failed: {e}")
        return False

if __name__ == "__main__":
    main()
