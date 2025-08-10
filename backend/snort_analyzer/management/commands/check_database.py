from django.core.management.base import BaseCommand
from snort_analyzer.models import SnortAlert
from django.utils import timezone
from datetime import timedelta

class Command(BaseCommand):
    help = 'Check database content for ML processing'
    
    def handle(self, *args, **options):
        self.stdout.write("🔍 Checking Database Content...")
        self.stdout.write("=" * 40)
        
        # Check total alerts
        total_alerts = SnortAlert.objects.count()
        self.stdout.write(f"📊 Total alerts in database: {total_alerts}")
        
        if total_alerts == 0:
            self.stdout.write("❌ No alerts found in database!")
            self.stdout.write("💡 Run: python manage.py create_test_alerts --count 20")
            return
        
        # Check recent alerts
        recent_24h = SnortAlert.objects.filter(
            timestamp__gte=timezone.now() - timedelta(days=1)
        ).count()
        
        self.stdout.write(f"📅 Recent alerts (24h): {recent_24h}")
        
        # Show sample alerts
        sample_alerts = SnortAlert.objects.all()[:3]
        
        self.stdout.write("\n📋 Sample Alerts:")
        for i, alert in enumerate(sample_alerts, 1):
            self.stdout.write(f"  {i}. {alert.source_ip}:{alert.source_port} -> {alert.destination_ip}:{alert.destination_port}")
            self.stdout.write(f"     Protocol: {alert.protocol}")
            self.stdout.write(f"     Signature: {alert.signature[:60]}...")
            self.stdout.write(f"     Time: {alert.timestamp}")
        
        # Check if ML fields exist
        first_alert = SnortAlert.objects.first()
        ml_fields = []
        for field in ['ml_processed', 'ml_prediction', 'threat_level', 'threat_probability']:
            if hasattr(first_alert, field):
                ml_fields.append(field)
        
        if ml_fields:
            self.stdout.write(f"\n🤖 ML fields available: {', '.join(ml_fields)}")
        else:
            self.stdout.write(f"\n⚠️ ML fields not found. Run migration first.")
        
        self.stdout.write(f"\n✅ Database ready for processing!")