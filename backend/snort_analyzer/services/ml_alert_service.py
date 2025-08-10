import logging
from datetime import datetime, timedelta
from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.db import transaction


from snort_analyzer.models import SnortAlert, IPStats, AttackNotification
from snort_analyzer.ml.ml_engine import ml_engine

logger = logging.getLogger(__name__)

class MLAlertProcessor:
    """Process alerts with ML predictions and handle notifications"""
    
    def __init__(self):
        self.ml_engine = ml_engine
        self.processed_count = 0
        self.threat_count = 0
        self.notification_count = 0
    
    def process_single_alert(self, alert):
        """Process a single alert with ML prediction"""
        try:
            # Get ML prediction
            ml_result = self.ml_engine.predict_threat(alert)
            
            # Update alert with ML results using correct field names
            with transaction.atomic():
                alert.ml_prediction = ml_result['is_threat']
                alert.threat_probability = ml_result['threat_probability']  # Fix: Use correct field
                alert.threat_level = ml_result['threat_level']
                alert.ml_processed = True  # Fix: Use correct field name
                alert.save()
            
            self.processed_count += 1
            
            # Handle high-priority threats
            if ml_result['threat_level'] in ['HIGH', 'MEDIUM'] and ml_result['is_threat']:
                self.threat_count += 1
                self._handle_threat_notification(alert, ml_result)
            
            logger.info(f"Processed alert {alert.id}: {ml_result['threat_level']} threat")
            return ml_result
            
        except Exception as e:
            logger.error(f"Error processing alert {alert.id}: {e}")
            return None
    
    def _handle_threat_notification(self, alert, ml_result):
        """Handle notifications for detected threats"""
        try:
            # Create database notification
            notification = AttackNotification.objects.create(
                alert=alert,
                threat_type='ml_detection',
                severity=alert.severity,
                message=f"ML detected {ml_result['threat_level']} threat from {alert.source_ip}",
                source_ip=alert.source_ip,
                dest_ip=alert.dest_ip,
                is_read=False
            )
            
            # Send email for high-priority threats
            if ml_result['threat_level'] == 'HIGH':
                self._send_threat_email(alert, ml_result, notification)
                self.notification_count += 1
            
        except Exception as e:
            logger.error(f"Error creating notification for alert {alert.id}: {e}")
    
    def _send_threat_email(self, alert, ml_result, notification):
        """Send email notification for high-priority threats"""
        try:
            # Email configuration
            recipient_emails = getattr(settings, 'ML_NOTIFICATION_EMAILS', ['admin@example.com'])
            
            if not recipient_emails:
                logger.warning("No notification emails configured")
                return
            
            # Prepare email context
            context = {
                'alert': alert,
                'ml_result': ml_result,
                'notification': notification,
                'source': f"{alert.source_ip}:{alert.source_port}",
                'destination': f"{alert.dest_ip}:{alert.dest_port}",
                'timestamp': datetime.now(),
                'threat_level': ml_result['threat_level'],
                'confidence': f"{ml_result['confidence']:.2%}"
            }
            
            # Render email template
            html_message = render_to_string('snort_analyzer/threat_email.html', context)
            plain_message = strip_tags(html_message)
            
            # Send email
            subject = f"🚨 HIGH Priority Threat Detected - {alert.source_ip}"
            
            send_mail(
                subject=subject,
                message=plain_message,
                from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@ids.local'),
                recipient_list=recipient_emails,
                html_message=html_message,
                fail_silently=False
            )
            
            logger.info(f"Threat email sent for alert {alert.id}")
            
        except Exception as e:
            logger.error(f"Error sending threat email for alert {alert.id}: {e}")

def batch_process_alerts(hours_back=24, limit=None):
    """Process multiple alerts with ML predictions"""
    processor = MLAlertProcessor()
    
    try:
        # Get alerts to process
        cutoff_time = datetime.now() - timedelta(hours=hours_back)
        
        # Fix: Use correct field name 'ml_processed' not 'ml_processed_at'
        queryset = SnortAlert.objects.filter(
            timestamp__gte=cutoff_time,
            ml_processed=False  # Fix: Changed from ml_processed_at__isnull=True
        ).order_by('-timestamp')
        
        if limit:
            queryset = queryset[:limit]
        
        alert_count = queryset.count()
        logger.info(f"Processing {alert_count} alerts with ML...")
        
        # Process alerts
        for alert in queryset:
            processor.process_single_alert(alert)
        
        # Update IP statistics
        _update_ip_stats(processor.threat_count)
        
        results = {
            'processed_count': processor.processed_count,
            'threat_count': processor.threat_count,
            'notification_count': processor.notification_count,
            'total_alerts': alert_count
        }
        
        logger.info(f"ML processing complete: {results}")
        return results
        
    except Exception as e:
        logger.error(f"Error in batch processing: {e}")
        return None

def _update_ip_stats(threat_count):
    """Update IP statistics with ML threat counts"""
    try:
        pass
    except Exception as e:
        logger.error(f"Error updating IP stats: {e}")

def get_ml_processing_stats():
    """Get ML processing statistics"""
    try:
        recent_alerts = SnortAlert.objects.filter(
            ml_processed=True, 
            timestamp__gte=datetime.now() - timedelta(days=1)
        )
        
        total_processed = recent_alerts.count()
        threats_detected = recent_alerts.filter(ml_prediction=True).count()
        high_threats = recent_alerts.filter(threat_level='HIGH').count()
        
        # Get model usage stats
        model_stats = ml_engine.get_model_stats()
        
        # Fix: Add None check for model_stats
        if model_stats is None:
            model_stats = {'status': 'error', 'models': []}
        
        return {
            'total_processed_24h': total_processed,
            'threats_detected_24h': threats_detected,
            'high_threats_24h': high_threats,
            'threat_rate': (threats_detected / total_processed * 100) if total_processed > 0 else 0,
            'ml_engine_status': model_stats.get('status', 'unknown'),
            'models_available': model_stats.get('models', []),
            'last_training': model_stats.get('training_date', 'Unknown')
        }
        
    except Exception as e:
        logger.error(f"Error getting ML stats: {e}")
        return {
            'total_processed_24h': 0,
            'threats_detected_24h': 0,
            'high_threats_24h': 0,
            'threat_rate': 0,
            'ml_engine_status': 'error',
            'models_available': [],
            'last_training': 'Unknown'
        }
