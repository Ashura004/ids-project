"""
Django management command to train ML models for intrusion detection
"""

from django.core.management.base import BaseCommand
from snort_analyzer.models import SnortAlert
from snort_analyzer.ml.anomaly_detector import ml_detector

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
        
        self.stdout.write("Starting ML Model Training...")
        self.stdout.write("=" * 50)
        
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
            self.stdout.write("Generate more sample data with:")
            self.stdout.write("  python generate_sample_alerts.py")
            return
        
        # Check if already trained
        if ml_detector.is_trained and not retrain:
            self.stdout.write(
                self.style.WARNING('Models already trained. Use --retrain to force retraining.')
            )
            model_info = ml_detector.get_model_info()
            self.stdout.write(f"Current model info: {model_info}")
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
            import traceback
            self.stdout.write(traceback.format_exc())
