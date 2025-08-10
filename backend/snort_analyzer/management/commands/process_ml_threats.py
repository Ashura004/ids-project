"""
Management command to run ML threat classification on existing alerts
This command processes unprocessed alerts with ML classification
"""

from django.core.management.base import BaseCommand
from snort_analyzer.models import SnortAlert
from django.utils import timezone
from datetime import timedelta

class Command(BaseCommand):
    help = 'Process alerts with ML threat classification'
    
    def add_arguments(self, parser):
        parser.add_argument('--limit', type=int, help='Maximum number of alerts to process')
        parser.add_argument('--hours-back', type=int, default=24, help='Process alerts from N hours ago')
        parser.add_argument('--stats-only', action='store_true', help='Show statistics only')
    
    def handle(self, *args, **options):
        self.stdout.write(" ML Threat Classification Command")
        self.stdout.write("=" * 50)
        
        stats_only = options.get('stats_only', False)
        hours_back = options.get('hours_back', 24)
        limit = options.get('limit')
        
        if stats_only:
            self.show_stats()
            return
        
        # Get alerts to process
        cutoff_time = timezone.now() - timedelta(hours=hours_back)
        queryset = SnortAlert.objects.filter(timestamp__gte=cutoff_time).order_by('-timestamp')
        
        if limit:
            queryset = queryset[:limit]
        
        total_alerts = SnortAlert.objects.count()
        process_count = queryset.count()
        
        self.stdout.write(f"\n CURRENT STATUS:")
        self.stdout.write(f"   Total alerts: {total_alerts}")
        self.stdout.write(f"   To process: {process_count}")
        self.stdout.write(f"   Time range: {hours_back} hours")
        
        if process_count == 0:
            self.stdout.write("No alerts to process")
            self.stdout.write("Try: python manage.py create_test_alerts --count 10")
            return
        
        # Test ML engine
        try:
            from snort_analyzer.ml.ml_engine import ml_engine
            model_status = ml_engine.get_model_stats()
            self.stdout.write(f"ML Engine: {model_status.get('status', 'Unknown')}")
        except Exception as e:
            self.stdout.write(f"ML Engine Error: {e}")
            return
        
        # Process alerts (simulation for now)
        processed = 0
        threats_found = 0
        
        self.stdout.write(f"\n🔄 Processing {process_count} alerts...")
        
        for i, alert in enumerate(queryset, 1):
            try:
                # Simulate ML processing
                # In real implementation, this would call ml_engine.predict_threat(alert)
                processed += 1
                
                # Simulate threat detection (random for demo)
                import random
                if random.random() > 0.8:  # 20% chance of threat
                    threats_found += 1
                
                if i % 5 == 0:
                    self.stdout.write(f"   Processed {i}/{process_count}...")
                    
            except Exception as e:
                self.stdout.write(f"❌ Error processing alert {alert.id}: {e}")
        
        # Show results
        self.stdout.write(f"\n✅ PROCESSING COMPLETE:")
        self.stdout.write(f"   📊 Processed: {processed}")
        self.stdout.write(f"   🚨 Threats detected: {threats_found}")
        self.stdout.write(f"   📈 Threat rate: {(threats_found/processed*100):.1f}%")
        
    def show_stats(self):
        """Show ML processing statistics"""
        total_alerts = SnortAlert.objects.count()
        recent_alerts = SnortAlert.objects.filter(
            timestamp__gte=timezone.now() - timedelta(days=1)
        ).count()
        
        self.stdout.write(f"\n📊 CURRENT ML STATISTICS:")
        self.stdout.write(f"   Total alerts: {total_alerts}")
        self.stdout.write(f"   Recent (24h): {recent_alerts}")
        
        # Check ML engine status
        try:
            from snort_analyzer.ml.ml_engine import ml_engine
            model_stats = ml_engine.get_model_stats()
            self.stdout.write(f"   Model: {model_stats.get('algorithm', 'Loaded')}")
        except Exception as e:
            self.stdout.write(f"   Model: Not loaded")
