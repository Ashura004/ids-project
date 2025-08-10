import os
import sys
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import accuracy_score, classification_report, roc_auc_score
import joblib
from datetime import datetime
from django.core.management.base import BaseCommand
from snort_analyzer.models import SnortAlert
from snort_analyzer.ml.anomaly_detector import ml_detector


sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from ml_training.kdd_preprocessing import KDDPreprocessor
except ImportError:
    from kdd_preprocessing import KDDPreprocessor

class MLModelTrainer:
    """Train and evaluate ML models for intrusion detection"""
    
    def __init__(self, models_dir='ml_models'):
        self.models_dir = models_dir
        self.models = {}
        self.results = {}
        self.preprocessor = KDDPreprocessor()
        
        # Initialize models
        self.model_configs = {
            'random_forest': RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42,
                n_jobs=-1
            ),
            'logistic_regression': LogisticRegression(
                random_state=42,
                max_iter=1000,
                solver='liblinear'
            ),
            'gradient_boosting': GradientBoostingClassifier(
                n_estimators=100,
                max_depth=6,
                random_state=42
            )
        }
    
    def load_and_preprocess_data(self, dataset_path):
        """Load and preprocess the dataset"""
        print("Starting ML Model Training...")
        print("=" * 50)
        
        # Load data
        df = self.preprocessor.load_data(dataset_path)
        
        # Preprocess features
        X, y = self.preprocessor.preprocess_features(df)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        print(f"Training set: {X_train.shape[0]} samples")
        print(f"Test set: {X_test.shape[0]} samples")
        
        return X_train, X_test, y_train, y_test
    
    def train_models(self, X_train, y_train):
        """Train all models"""
        print("\nTraining Models...")
        print("-" * 30)
        
        for name, model in self.model_configs.items():
            print(f"Training {name.replace('_', ' ').title()}...")
            
            # Train model
            model.fit(X_train, y_train)
            self.models[name] = model
            
            # Cross-validation score
            cv_scores = cross_val_score(model, X_train, y_train, cv=5, scoring='accuracy')
            
            print(f" {name.replace('_', ' ').title()} trained")
            print(f"   CV Accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
    
    def evaluate_models(self, X_test, y_test):
        """Evaluate trained models"""
        print("\nModel Evaluation...")
        print("-" * 30)
        
        for name, model in self.models.items():
            # Predictions
            y_pred = model.predict(X_test)
            y_pred_proba = model.predict_proba(X_test)[:, 1]  # Probability of attack
            
            # Metrics
            accuracy = accuracy_score(y_test, y_pred)
            auc_score = roc_auc_score(y_test, y_pred_proba)
            
            # Store results
            self.results[name] = {
                'accuracy': accuracy,
                'auc_score': auc_score,
                'predictions': y_pred,
                'probabilities': y_pred_proba
            }
            
            print(f" {name.replace('_', ' ').title()}")
            print(f"   Accuracy: {accuracy:.4f}")
            print(f"   AUC Score: {auc_score:.4f}")
        
        # Find best model
        best_model_name = max(self.results.keys(), key=lambda x: self.results[x]['accuracy'])
        best_accuracy = self.results[best_model_name]['accuracy']
        
        print(f"\nBest Model: {best_model_name.replace('_', ' ').title()}")
        print(f"Best Accuracy: {best_accuracy:.4f}")
        
        return best_model_name
    
    def save_models(self):
        """Save trained models and preprocessor"""
        os.makedirs(self.models_dir, exist_ok=True)
        
        print(f"\n💾 Saving models to {self.models_dir}...")
        
        # Save each model
        for name, model in self.models.items():
            model_path = os.path.join(self.models_dir, f'{name}_model.pkl')
            joblib.dump(model, model_path)
            print(f" Saved {name} model")
        
        # Save preprocessor
        self.preprocessor.save_preprocessor(self.models_dir)
        
        # Save training metadata
        metadata = {
            'training_date': datetime.now().isoformat(),
            'models': list(self.models.keys()),
            'results': {name: {k: v for k, v in results.items() if k not in ['predictions', 'probabilities']} 
                       for name, results in self.results.items()},
            'feature_count': len(self.preprocessor.feature_columns)
        }
        
        metadata_path = os.path.join(self.models_dir, 'training_metadata.pkl')
        joblib.dump(metadata, metadata_path)
        
        print("All models and preprocessor saved successfully!")
    
    def train_full_pipeline(self, dataset_path):
        """Complete training pipeline"""
        try:
            # Load and preprocess data
            X_train, X_test, y_train, y_test = self.load_and_preprocess_data(dataset_path)
            
            # Train models
            self.train_models(X_train, y_train)
            
            # Evaluate models
            best_model = self.evaluate_models(X_test, y_test)
            
            # Save models
            self.save_models()
            
            print(f"\n Training Complete!")
            print(f" Models saved in: {self.models_dir}")
            print(f" Ready for production use!")
            
            return True
            
        except Exception as e:
            print(f" Training failed: {e}")
            import traceback
            traceback.print_exc()
            return False

class Command(BaseCommand):
    help = 'Train ML models for anomaly detection'

    def add_arguments(self, parser):
        parser.add_argument(
            '--retrain',
            action='store_true',
            help='Force retraining even if models exist',
        )
        parser.add_argument(
            '--min-samples',
            type=int,
            default=100,
            help='Minimum number of samples required for training',
        )

    def handle(self, *args, **options):
        retrain = options['retrain']
        min_samples = options['min_samples']
        
        # Get all alerts for training
        alerts = SnortAlert.objects.all().order_by('-timestamp')
        alert_count = alerts.count()
        
        self.stdout.write(f'Found {alert_count} alerts in database')
        
        if alert_count < min_samples:
            self.stdout.write(
                self.style.ERROR(
                    f'Insufficient data for training. Need at least {min_samples} samples, got {alert_count}'
                )
            )
            return
        
        # Check if already trained
        if ml_detector.is_trained and not retrain:
            self.stdout.write(
                self.style.WARNING('Models already trained. Use --retrain to force retraining.')
            )
            return
        
        self.stdout.write('Starting ML model training...')
        
        try:
            ml_detector.train_models(alerts, retrain=retrain)
            
            # Display model info
            model_info = ml_detector.get_model_info()
            self.stdout.write(
                self.style.SUCCESS(
                    f'Training completed successfully!\n'
                    f'Features: {model_info["feature_count"]}\n'
                    f'Training stats: {model_info["training_stats"]}'
                )
            )
            
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Training failed: {str(e)}')
            )

def main():
    """Main training function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Train ML models for intrusion detection')
    parser.add_argument('--dataset-path', default='kdd_test.csv', help='Path to KDD dataset')
    parser.add_argument('--models-dir', default='ml_models', help='Directory to save models')
    
    args = parser.parse_args()
    
    # Train models
    trainer = MLModelTrainer(models_dir=args.models_dir)
    success = trainer.train_full_pipeline(args.dataset_path)
    
    return success

if __name__ == "__main__":
    main()
