# snort_analyzer/ml/feature_engineering.py

import pandas as pd
import numpy as np
from datetime import timedelta
from ..models import SnortAlert, IPStats
from django.utils import timezone
from django.db.models import Count, Q

def extract_features_for_alert(alert):
    """
    Extract features for a single alert for real-time anomaly detection
    """
    # Time window for feature extraction (last hour)
    time_window = alert.timestamp - timedelta(hours=1)
    
    # Get related alerts in the time window
    related_alerts = SnortAlert.objects.filter(
        timestamp__gte=time_window,
        timestamp__lte=alert.timestamp
    )
    
    # Source IP features
    source_ip = alert.source_ip
    source_ip_alerts = related_alerts.filter(source_ip=source_ip)
    
    source_ip_alert_count = source_ip_alerts.count()
    source_ip_unique_destinations = source_ip_alerts.values('destination_ip').distinct().count()
    source_ip_unique_ports = source_ip_alerts.values('destination_port').distinct().count()
    source_ip_protocols = source_ip_alerts.values('protocol').annotate(count=Count('id'))
    source_ip_protocol_entropy = calculate_entropy([p['count'] for p in source_ip_protocols])
    
    # Destination IP features
    dest_ip = alert.destination_ip
    dest_ip_alerts = related_alerts.filter(destination_ip=dest_ip)
    
    dest_ip_alert_count = dest_ip_alerts.count()
    dest_ip_unique_sources = dest_ip_alerts.values('source_ip').distinct().count()
    dest_ip_unique_ports = dest_ip_alerts.values('destination_port').distinct().count()
    
    # Port-based features
    port = alert.destination_port
    port_alerts = related_alerts.filter(destination_port=port)
    port_alert_count = port_alerts.count()
    
    # Protocol features
    protocol = alert.protocol
    protocol_alerts = related_alerts.filter(protocol=protocol)
    protocol_alert_count = protocol_alerts.count()
    
    # Severity features
    high_severity_ratio = related_alerts.filter(severity=1).count() / max(1, related_alerts.count())
    
    # Time-based features
    # Count alerts in last 5 minutes
    last_5_min = alert.timestamp - timedelta(minutes=5)
    alerts_last_5_min = related_alerts.filter(timestamp__gte=last_5_min).count()
    
    # Combine features into a single array
    features = [
        source_ip_alert_count,
        source_ip_unique_destinations,
        source_ip_unique_ports,
        source_ip_protocol_entropy,
        dest_ip_alert_count,
        dest_ip_unique_sources, 
        dest_ip_unique_ports,
        port_alert_count,
        protocol_alert_count,
        high_severity_ratio,
        alerts_last_5_min,
        alert.severity,
    ]
    
    return np.array(features).reshape(1, -1)

def calculate_entropy(counts):
    """Calculate Shannon entropy for a list of counts"""
    if not counts:
        return 0
    
    total = sum(counts)
    if total == 0:
        return 0
        
    probs = [count/total for count in counts]
    entropy = -sum(p * np.log2(p) for p in probs if p > 0)
    return entropy

def prepare_training_data():
    """
    Prepare historical data for model training
    This would be run periodically to retrain the model
    """
    # Get alerts from the last 30 days
    start_date = timezone.now() - timedelta(days=30)
    alerts = SnortAlert.objects.filter(timestamp__gte=start_date)
    
    features_list = []
    
    # Group alerts by day to process in chunks
    dates = alerts.dates('timestamp', 'day')
    
    for date in dates:
        next_date = date + timedelta(days=1)
        day_alerts = alerts.filter(timestamp__gte=date, timestamp__lt=next_date)
        
        for alert in day_alerts:
            features = extract_features_for_alert(alert)
            features_list.append(features[0])  # Flatten the array
    
    return np.array(features_list)