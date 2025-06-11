import os
from celery import shared_task
from django.conf import settings
from django.core.management import call_command

@shared_task
def parse_snort_logs():
    """
    Parse the Snort logs from the configured file path
    """
    log_file = getattr(settings, 'SNORT_LOGS_FILE', 
                     os.path.join(settings.BASE_DIR.parent, 'snort_logs', 'alerts.csv'))
    
    
    if not os.path.exists(log_file):
        return f"Log file not found: {log_file}"
    
    try:
        
        call_command('parse_snort_logs', file=log_file)
        return f"Successfully parsed Snort logs from {log_file}"
    except Exception as e:
        return f"Error parsing Snort logs: {str(e)}"