import os
import sys
import random
from datetime import datetime, timedelta

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ids_project.settings')
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import django
django.setup()

from snort_analyzer.models import SnortAlert
from django.utils import timezone

def generate_diverse_alerts():
    """Generate diverse types of security alerts with proper anomaly detection"""
    
    alert_templates = [
        # HIGH SEVERITY ALERTS (Always anomalies)
        {
            'signature': 'SQL Injection Attempt Detected',
            'protocol': 'tcp',
            'source_port': 80,
            'dest_port': 3306,
            'severity': 1,
            'signature_id': 100001,
            'is_anomalous': True,
            'anomaly_score': 0.9
        },
        {
            'signature': 'Malware Command and Control Communication',
            'protocol': 'tcp',
            'source_port': 443,
            'dest_port': 8080,
            'severity': 1,
            'signature_id': 100002,
            'is_anomalous': True,
            'anomaly_score': 0.95
        },
        {
            'signature': 'Buffer Overflow Exploit Attempt',
            'protocol': 'tcp',
            'source_port': 1234,
            'dest_port': 21,
            'severity': 1,
            'signature_id': 100003,
            'is_anomalous': True,
            'anomaly_score': 0.92
        },
        {
            'signature': 'Ransomware File Encryption Activity',
            'protocol': 'tcp',
            'source_port': 445,
            'dest_port': 445,
            'severity': 1,
            'signature_id': 100004,
            'is_anomalous': True,
            'anomaly_score': 0.98
        },
        {
            'signature': 'Backdoor Trojan Communication',
            'protocol': 'tcp',
            'source_port': 6666,
            'dest_port': 6667,
            'severity': 1,
            'signature_id': 100005,
            'is_anomalous': True,
            'anomaly_score': 0.88
        },
        
        # MEDIUM SEVERITY ALERTS (Suspicious - anomalies)
        {
            'signature': 'Port Scan Detected',
            'protocol': 'tcp',
            'source_port': 12345,
            'dest_port': 22,
            'severity': 2,
            'signature_id': 200001,
            'is_anomalous': True,
            'anomaly_score': 0.6
        },
        {
            'signature': 'Suspicious DNS Query',
            'protocol': 'udp',
            'source_port': 53,
            'dest_port': 53,
            'severity': 2,
            'signature_id': 200002,
            'is_anomalous': True,
            'anomaly_score': 0.5
        },
        {
            'signature': 'Brute Force Login Attempt',
            'protocol': 'tcp',
            'source_port': 2222,
            'dest_port': 22,
            'severity': 2,
            'signature_id': 200003,
            'is_anomalous': True,
            'anomaly_score': 0.7
        },
        {
            'signature': 'Unauthorized Access Attempt',
            'protocol': 'tcp',
            'source_port': 8080,
            'dest_port': 80,
            'severity': 2,
            'signature_id': 200004,
            'is_anomalous': True,
            'anomaly_score': 0.65
        },
        {
            'signature': 'Network Reconnaissance Activity',
            'protocol': 'tcp',
            'source_port': 1111,
            'dest_port': 443,
            'severity': 2,
            'signature_id': 200005,
            'is_anomalous': True,
            'anomaly_score': 0.55
        },
        
        # LOW SEVERITY ALERTS (Normal traffic - NOT anomalies)
        {
            'signature': 'ICMP Ping Request',
            'protocol': 'icmp',
            'source_port': 0,
            'dest_port': 0,
            'severity': 3,
            'signature_id': 300001,
            'is_anomalous': False,
            'anomaly_score': 0.0
        },
        {
            'signature': 'ICMP Echo Reply',
            'protocol': 'icmp',
            'source_port': 0,
            'dest_port': 0,
            'severity': 3,
            'signature_id': 300002,
            'is_anomalous': False,
            'anomaly_score': 0.0
        },
        {
            'signature': 'ICMP Time Exceeded',
            'protocol': 'icmp',
            'source_port': 0,
            'dest_port': 0,
            'severity': 3,
            'signature_id': 300003,
            'is_anomalous': False,
            'anomaly_score': 0.0
        },
        {
            'signature': 'Normal HTTP Request',
            'protocol': 'tcp',
            'source_port': 80,
            'dest_port': 80,
            'severity': 3,
            'signature_id': 300004,
            'is_anomalous': False,
            'anomaly_score': 0.0
        },
        {
            'signature': 'DNS Query Response',
            'protocol': 'udp',
            'source_port': 53,
            'dest_port': 1234,
            'severity': 3,
            'signature_id': 300005,
            'is_anomalous': False,
            'anomaly_score': 0.0
        },
        {
            'signature': 'DHCP Request',
            'protocol': 'udp',
            'source_port': 68,
            'dest_port': 67,
            'severity': 3,
            'signature_id': 300006,
            'is_anomalous': False,
            'anomaly_score': 0.0
        }
    ]
    
    # IP address pools
    internal_ips = [
        '192.168.1.10', '192.168.1.15', '192.168.1.20', '192.168.1.25',
        '10.0.0.5', '10.0.0.10', '10.0.0.15', '10.0.0.20',
        '172.16.1.10', '172.16.1.15', '172.16.1.20'
    ]
    
    external_ips = [
        '203.0.113.5', '198.51.100.10', '203.0.113.15', '198.51.100.20',
        '8.8.8.8', '1.1.1.1', '208.67.222.222', '9.9.9.9'
    ]
    
    malicious_ips = [
        '45.142.212.61', '91.203.68.194', '139.180.216.104', '159.203.75.57',
        '178.128.83.165', '206.189.85.18', '167.172.248.37', '134.209.24.42'
    ]
    
    created_count = 0
    
    print("Generating diverse security alerts...")
    print("=" * 50)
    
    # Generate alerts over the last 7 days
    for day in range(7):
        base_time = timezone.now() - timedelta(days=day)
        daily_alert_count = random.randint(20, 40)
        
        print(f"Day {day + 1}: Generating {daily_alert_count} alerts...")
        
        for _ in range(daily_alert_count):
            template = random.choice(alert_templates)
            
            # Choose IPs based on severity
            if template['severity'] == 1:
                source_ip = random.choice(malicious_ips + external_ips)
                dest_ip = random.choice(internal_ips)
            elif template['severity'] == 2:
                source_ip = random.choice(external_ips + malicious_ips)
                dest_ip = random.choice(internal_ips)
            else:
                source_ip = random.choice(internal_ips + external_ips)
                dest_ip = random.choice(internal_ips)
            
            # Random time within the day
            random_seconds = random.randint(0, 86400)
            timestamp = base_time + timedelta(seconds=random_seconds)
            
            # Create raw log
            raw_log = f"{random.randint(1000, 9999)} {timestamp.strftime('%m/%d-%H:%M:%S.%f')[:-3]} {template['severity']} {template['signature_id']} 1 {template['signature']} {template['protocol'].upper()} {source_ip} {dest_ip}"
            
            try:
                # Create unique key to avoid duplicates
                unique_key = f"{source_ip}_{dest_ip}_{template['signature_id']}_{timestamp.strftime('%Y%m%d%H%M%S')}"
                
                # Create alert - use create() instead of get_or_create() to avoid the issue
                alert = SnortAlert.objects.create(
                    source_ip=source_ip,
                    destination_ip=dest_ip,
                    signature_id=template['signature_id'],
                    timestamp=timestamp,
                    signature=template['signature'],
                    source_port=template['source_port'],
                    destination_port=template['dest_port'],
                    protocol=template['protocol'],
                    severity=template['severity'],
                    raw_log=raw_log,
                    is_anomalous=template['is_anomalous'],
                    anomaly_score=template['anomaly_score'],
                    created_at=timestamp  # Explicitly set created_at
                )
                
                created_count += 1
                
            except Exception as e:
                print(f"Error creating alert: {e}")
                continue
    
    print("\n" + "=" * 50)
    print(f"Generated {created_count} diverse security alerts!")
    print(f"Total alerts in database: {SnortAlert.objects.count()}")
    
    # Show statistics
    high = SnortAlert.objects.filter(severity=1).count()
    medium = SnortAlert.objects.filter(severity=2).count()
    low = SnortAlert.objects.filter(severity=3).count()
    
    anomalies = SnortAlert.objects.filter(is_anomalous=True).count()
    normal = SnortAlert.objects.filter(is_anomalous=False).count()
    
    icmp_normal = SnortAlert.objects.filter(protocol='icmp', is_anomalous=False).count()
    icmp_anomalies = SnortAlert.objects.filter(protocol='icmp', is_anomalous=True).count()
    
    print(f"\nAlert Statistics:")
    print(f"   Severity: High({high}) Medium({medium}) Low({low})")
    print(f"   Anomaly Status: Anomalies({anomalies}) Normal({normal})")
    print(f"   ICMP: Normal({icmp_normal}) Anomalous({icmp_anomalies})")
    print(f"\nICMP traffic correctly classified as normal!")

def clear_existing_alerts():
    """Clear all existing alerts"""
    count = SnortAlert.objects.count()
    if count > 0:
        SnortAlert.objects.all().delete()
        print(f" Cleared {count} existing alerts")

if __name__ == "__main__":
    print("Starting Alert Generation Process...")
    print("=" * 50)
    
    # First, let's run migrations to fix any database issues
    print("Checking database schema...")
    
    response = input("Do you want to clear existing alerts first? (y/N): ").strip().lower()
    if response in ['y', 'yes']:
        clear_existing_alerts()
        print()
    
    generate_diverse_alerts()