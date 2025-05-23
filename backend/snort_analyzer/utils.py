# Add to snort_analyzer/utils.py
import csv
from datetime import datetime
from django.db import transaction
from .models import SnortAlert, IPStats, DailyStats
from .ml.anomaly_detection import detect_anomaly

def update_statistics(alert):
    """
    Update statistics for the given alert.
    This is a placeholder function. Implement the logic as needed.
    """
    pass

def parse_snort_csv(file_path, update_stats=True):
    """
    Parse a CSV file containing Snort alerts and store in database
    
    Args:
        file_path (str): Path to the CSV file
        update_stats (bool): Whether to update statistics
        
    Returns:
        int: Number of records imported
    """
    imported_count = 0
    
    try:
        with open(file_path, 'r') as csv_file:
            reader = csv.DictReader(csv_file)
            
            with transaction.atomic():
                for row in reader:
                    # Parse timestamp
                    timestamp = datetime.strptime(row.get('timestamp', ''), '%Y-%m-%d %H:%M:%S')
                    signature_id = int(row.get('signature_id', 0))
                    
                    # Create or update alert
                    alert, created = SnortAlert.objects.update_or_create(
                        signature_id=signature_id,
                        timestamp=timestamp,
                        defaults={
                            'signature': row.get('signature', ''),
                            'source_ip': row.get('src_ip', ''),
                            'source_port': int(row.get('src_port', 0)),
                            'destination_ip': row.get('dest_ip', ''),
                            'destination_port': int(row.get('dest_port', 0)),
                            'protocol': row.get('protocol', ''),
                            'severity': int(row.get('severity', 3)),
                            'raw_log': row.get('raw_log', ''),
                            'is_anomalous': row.get('is_anomalous', '').lower() in ('true', 't', '1', 'yes'),
                            'anomaly_score': float(row.get('anomaly_score', 0.0))
                        }
                    )
                    
                    if created:
                        imported_count += 1
                        
                    # Update statistics if needed
                    if update_stats:
                        update_statistics(alert)
        
        return imported_count
    except Exception as e:
        print(f"Error parsing CSV file: {e}")
        return 0