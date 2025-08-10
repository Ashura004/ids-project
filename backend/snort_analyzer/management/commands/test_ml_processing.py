# Create file: test_ml_processing.py
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ids_project.settings')
django.setup()

from snort_analyzer.models import SnortAlert
from django.utils import timezone
from datetime import timedelta

def test_ml_processing():
    print("🤖 Testing ML Processing")
    print("=" * 30)
    
    # Get recent alerts
    recent_alerts = SnortAlert.objects.order_by('-timestamp')[:10]
    print(f"📊 Processing {len(recent_alerts)} recent alerts...")
    
    try:
        from snort_analyzer.ml.ml_engine import ml_engine
        
        processed = 0
        threats_detected = 0
        
        for alert in recent_alerts:
            try:
                # Test ML prediction
                result = ml_engine.predict_threat(alert)
                processed += 1
                
                print(f"Alert {alert.id}: {alert.source_ip} -> {alert.destination_ip}")
                print(f"  Threat Level: {result['threat_level']}")
                print(f"  Probability: {result['threat_probability']:.3f}")
                print(f"  Confidence: {result['confidence']:.3f}")
                
                if result['is_threat']:
                    threats_detected += 1
                    
                # Update alert with ML results (if fields exist)
                if hasattr(alert, 'ml_processed'):
                    alert.ml_processed = True
                    alert.ml_prediction = result['is_threat']
                    alert.threat_level = result['threat_level']
                    alert.threat_probability = result['threat_probability']
                    alert.save()
                    print(f"  ✅ Updated alert in database")
                
                print()
                
            except Exception as e:
                print(f"  ❌ Error processing alert {alert.id}: {e}")
        
        print(f"🎉 RESULTS:")
        print(f"   Processed: {processed}")
        print(f"   Threats: {threats_detected}")
        print(f"   Rate: {(threats_detected/processed*100):.1f}%")
        
    except Exception as e:
        print(f"❌ ML Engine Error: {e}")

if __name__ == "__main__":
    test_ml_processing()