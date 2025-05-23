# snort_analyzer/management/commands/parse_csv_logs.py

import csv
import os

import pytz
from datetime import datetime
from django.core.management.base import BaseCommand
from django.db import transaction
from django.conf import settings
from snort_analyzer.models import SnortAlert, IPStats, DailyStats
from snort_analyzer.ml.anomaly_detection import detect_anomaly

class Command(BaseCommand):
    help = 'Parse Snort logs from CSV file and analyze them'

    def add_arguments(self, parser):
        parser.add_argument(
            '--file',
            type=str,
            default=os.path.join(os.getcwd(), '..', 'snort_logs', 'alerts.csv'),
            help='Path to CSV log file'
        )

    def handle(self, *args, **options):
        file_path = options['file']
        
        if not os.path.exists(file_path):
            self.stdout.write(self.style.ERROR(f'File not found: {file_path}'))
            return
        
        # Debug the CSV structure first
        self.debug_csv_structure(file_path)
            
        self.stdout.write(self.style.SUCCESS(f'Parsing CSV file: {file_path}'))
        count = self.parse_csv(file_path)
        self.stdout.write(self.style.SUCCESS(f'Successfully imported {count} alerts'))

    def debug_csv_structure(self, file_path):
        """Examine the CSV structure to debug field issues"""
        try:
            with open(file_path, 'r') as csv_file:
                # Print the first line to see headers
                headers = csv_file.readline().strip()
                self.stdout.write(self.style.SUCCESS(f"CSV Headers: {headers}"))
                
                # Reset and read the first data row
                csv_file.seek(0)
                reader = csv.DictReader(csv_file)
                for i, row in enumerate(reader):
                    if i >= 1:  # Only examine first row
                        break
                    self.stdout.write(self.style.SUCCESS(f"First row data:"))
                    for key, value in row.items():
                        self.stdout.write(f"  {key}: '{value}'")
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Error examining CSV: {str(e)}"))

    def parse_csv(self, file_path):
        """Parse CSV file and store alerts in database"""
        imported_count = 0
        
        try:
            with open(file_path, 'r') as csv_file:
                reader = csv.DictReader(csv_file)
                
                with transaction.atomic():
                    for row in reader:
                        alert = self.process_row(row)
                        if alert:
                            imported_count += 1
            
            return imported_count
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Error parsing CSV: {str(e)}'))
            return 0
    
    def process_row(self, row):
        """Process a single CSV row and store in database"""
        try:
            # Get the timestamp string
            timestamp_str = row.get('timestamp', '').strip()
            
            # The logs have format MM/DD-HH:MM:SS.ffffff without year
            # We need to add the current year to parse it
            if '/' in timestamp_str and '-' in timestamp_str:
                # Add current year since it's missing from timestamp
                current_year = datetime.now().year
                
                # Split the timestamp into parts
                date_part, time_part = timestamp_str.split('-')
                month, day = date_part.split('/')
                
                # Reconstruct with year
                timestamp_with_year = f"{current_year}-{month}-{day} {time_part}"
                
                # Try to parse with the reconstructed format
                try:
                    timestamp = datetime.strptime(timestamp_with_year, '%Y-%m-%d %H:%M:%S.%f')
                    # Add timezone to avoid Django warning
                    timezone = pytz.timezone(settings.TIME_ZONE)
                    timestamp = timezone.localize(timestamp)
                    
                    # Get source IP - check different possible field names
                    source_ip = row.get('src_ip', row.get('source_ip', row.get('ip_src', '')))
                    if not source_ip:
                        # If no source IP found, use a placeholder value
                        source_ip = '0.0.0.0'
                        self.stdout.write(self.style.WARNING(f"No source IP found in row, using placeholder"))
                    
                    # Get destination IP - check different possible field names
                    dest_ip = row.get('dest_ip', row.get('destination_ip', row.get('ip_dest', '')))
                    if not dest_ip:
                        # If no destination IP found, use a placeholder value
                        dest_ip = '0.0.0.0'
                    
                    # Get signature ID
                    signature_id = int(row.get('signature_id', row.get('sid', 0)))
                    
                    # Get protocol
                    protocol = row.get('protocol', row.get('proto', 'unknown'))
                    
                    # Get ports
                    src_port = int(row.get('src_port', row.get('sport', 0)))
                    dst_port = int(row.get('dest_port', row.get('dport', 0)))
                    
                    # Get severity
                    severity = int(row.get('severity', row.get('priority', 3)))
                    
                    # Get signature message
                    signature = row.get('signature', row.get('msg', ''))
                    
                    # Raw log data
                    raw_log = row.get('raw_log', row.get('full_log', ''))
                    
                    # Check if alert already exists to avoid duplicates
                    alert, created = SnortAlert.objects.update_or_create(
                        signature_id=signature_id,
                        timestamp=timestamp,
                        defaults={
                            'signature': signature,
                            'source_ip': source_ip,
                            'source_port': src_port,
                            'destination_ip': dest_ip,
                            'destination_port': dst_port,
                            'protocol': protocol,
                            'severity': severity,
                            'raw_log': raw_log,
                        }
                    )
                    
                    # Process anomaly detection if needed
                    if 'is_anomalous' in row:
                        alert.is_anomalous = row.get('is_anomalous', '').lower() in ('true', 't', '1', 'yes')
                    else:
                        # Run anomaly detection if not in CSV
                        alert.is_anomalous, alert.anomaly_score = detect_anomaly(alert)
                        
                    if 'anomaly_score' in row:
                        alert.anomaly_score = float(row.get('anomaly_score', 0.0))
                        
                    alert.save()
                    
                    # Update statistics
                    self.update_statistics(alert)
                    
                    if created:
                        self.stdout.write(self.style.SUCCESS(
                            f"Imported alert: {alert.signature} from {alert.source_ip} to {alert.destination_ip}"
                        ))
                        
                    return alert
                    
                except ValueError:
                    self.stdout.write(self.style.WARNING(f"Could not parse timestamp with year: {timestamp_with_year}"))
            
            # If we're here, the special format didn't work, try the original formats
            timestamp = None
            formats_to_try = [
                '%Y-%m-%d %H:%M:%S',        # 2023-05-18 14:30:45
                '%Y-%m-%d %H:%M:%S.%f',      # 2023-05-18 14:30:45.123
                '%m/%d/%Y %H:%M:%S',         # 05/18/2023 14:30:45
                '%m/%d/%Y %H:%M:%S.%f',      # 05/18/2023 14:30:45.123
                '%m-%d-%Y %H:%M:%S',         # 05-18-2023 14:30:45
                '%m-%d-%Y %H:%M:%S.%f',      # 05-18-2023 14:30:45.123
            ]
            
            for fmt in formats_to_try:
                try:
                    timestamp = datetime.strptime(timestamp_str, fmt)
                    # Add timezone
                    timezone = pytz.timezone(settings.TIME_ZONE)
                    timestamp = timezone.localize(timestamp)
                    break  # Exit the loop if parsing succeeds
                except ValueError:
                    continue
                
            # Original code for handling "standard" formats
            if timestamp is None:
                # If all formats failed, log the problematic timestamp and raise an error
                self.stdout.write(self.style.ERROR(f"Couldn't parse timestamp: {timestamp_str}"))
                raise ValueError(f"Timestamp format not recognized: {timestamp_str}")
                
            # The rest of your code (which will only run if the special format didn't work but one of the standard formats did)
            # ...
                
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Error processing CSV row: {str(e)}"))
            return None
            
    def update_statistics(self, alert):
        """Update IP and daily statistics"""
        # Update source IP stats
        source_stat, _ = IPStats.objects.get_or_create(
            ip_address=alert.source_ip,
            is_source=True
        )
        source_stat.alert_count += 1
        if alert.is_anomalous:
            source_stat.anomaly_count += 1
        source_stat.increment_protocol(alert.protocol)
        source_stat.increment_port(alert.destination_port)
        source_stat.save()
        
        # Update destination IP stats
        dest_stat, _ = IPStats.objects.get_or_create(
            ip_address=alert.destination_ip,
            is_source=False
        )
        dest_stat.alert_count += 1
        if alert.is_anomalous:
            dest_stat.anomaly_count += 1
        dest_stat.increment_protocol(alert.protocol)
        dest_stat.increment_port(alert.source_port)
        dest_stat.save()
        
        # Update daily stats
        day = alert.timestamp.date()
        daily_stat, _ = DailyStats.objects.get_or_create(date=day)
        daily_stat.total_alerts += 1
        
        if alert.severity == 1:
            daily_stat.high_severity += 1
        elif alert.severity == 2:
            daily_stat.medium_severity += 1
        else:
            daily_stat.low_severity += 1
            
        if alert.is_anomalous:
            daily_stat.anomaly_count += 1
            
        daily_stat.save()