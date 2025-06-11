import os
import time
import csv
import logging
from pathlib import Path
from datetime import datetime

import pytz
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from django.core.management.base import BaseCommand
from django.conf import settings
from django.utils import timezone

from snort_analyzer.models import SnortAlert, IPStats, DailyStats

logger = logging.getLogger(__name__)

class AlertLogHandler(FileSystemEventHandler):
    """Watches for changes to the Snort alerts.csv file and processes new entries"""
    
    def __init__(self, file_path):
        super().__init__()
        self.file_path = file_path
        self.last_position = 0
        self.header_row = None
        self.initialize_position()
        
    def initialize_position(self):
        """Set initial position to end of file to only process new alerts"""
        if os.path.exists(self.file_path):
            with open(self.file_path, 'r') as f:
                
                first_line = f.readline().strip()
                if first_line:
                    
                    self.header_row = [
                        'timestamp', 'classification', 'sid', 'severity', 'message', 
                        'protocol', 'source_ip', 'source_port', 'destination_ip', 
                        'destination_port', 'flags'
                    ]
                    logger.info(f"Using header: {self.header_row}")
            
                
                f.seek(0, os.SEEK_END)
                self.last_position = f.tell()
                logger.info(f"Initialized file position to {self.last_position}")
                
    def on_modified(self, event):
        """Handle file modification events"""
        if not event.src_path.endswith(self.file_path):
            return
            
        self.process_new_lines()
    
    def process_new_lines(self):
        """Process newly added lines in the log file"""
        if not os.path.exists(self.file_path):
            logger.error(f"File not found: {self.file_path}")
            return
            
        try:
            
            file_size = os.path.getsize(self.file_path)
            print(f"Current file size: {file_size} bytes, last_position: {self.last_position}")
            
            with open(self.file_path, 'r') as f:
                f.seek(self.last_position)
                
                new_lines = f.readlines()
                if not new_lines:
                    print("No new content detected")
                    return
                    
                print(f"Found {len(new_lines)} new line(s) to process")
                logger.info(f"Processing {len(new_lines)} new alert(s)")
                
                self.last_position = f.tell()
                
                for i, line in enumerate(new_lines):
                    print(f"Processing line {i+1}: {line[:50]}...")  # Show first 50 chars
                    self.process_line(line.strip())
        except Exception as e:
            logger.error(f"Error reading file: {str(e)}")
            print(f"File reading error: {str(e)}")
    
    def process_line(self, line):
        """Process a single line from the alerts file"""
        if not line or line.startswith('timestamp'):
            return
        
        try:
           
            logger.debug(f"Processing raw line: {line}")
            
            
            reader = csv.reader([line])
            row = next(reader)
            
            
            logger.debug(f"Parsed CSV row: {row}")
            
            
            fields = [
                'timestamp', 'classification', 'sid', 'severity', 'message', 
                'protocol', 'source_ip', 'source_port', 'destination_ip', 
                'destination_port', 'flags'
            ]
            
            alert_data = {}
            for i, field in enumerate(fields):
                if i < len(row):
                    alert_data[field] = row[i]
            
            
            logger.info(f"Alert data: {alert_data}")
            
            
            source_ip = alert_data.get('source_ip', '').strip()
            dest_ip = alert_data.get('destination_ip', '').strip()
            
            
            if not source_ip or not dest_ip:
                logger.warning(f"Missing IP addresses: src={source_ip}, dst={dest_ip}")
                return
            
            
            timestamp_str = alert_data.get('timestamp', '').strip()
            logger.debug(f"Parsing timestamp: '{timestamp_str}'")
            
            
            if '/' in timestamp_str and '-' in timestamp_str:
                try:
                    
                    current_year = datetime.now().year
                    
                    
                    date_part, time_part = timestamp_str.split('-')
                    month, day = date_part.split('/')
                    
                   
                    month = month.zfill(2)
                    day = day.zfill(2)
                    
                    
                    timestamp_with_year = f"{current_year}-{month}-{day} {time_part}"
                    
                    
                    if '.' in time_part:
                        timestamp = datetime.strptime(timestamp_with_year, '%Y-%m-%d %H:%M:%S.%f')
                    else:
                        timestamp = datetime.strptime(timestamp_with_year, '%Y-%m-%d %H:%M:%S')
                    
                    
                    if settings.USE_TZ:
                        tz = pytz.timezone(settings.TIME_ZONE)
                        timestamp = timezone.make_aware(timestamp, timezone=tz)
                    
                    logger.debug(f"Successfully parsed timestamp: {timestamp}")
                except Exception as e:
                    logger.error(f"Error parsing timestamp '{timestamp_str}': {str(e)}")
                    
                    try:
                       
                        time_parts = time_part.split('.')
                        clean_time = time_parts[0]
                        timestamp_with_year = f"{current_year}-{month}-{day} {clean_time}"
                        timestamp = datetime.strptime(timestamp_with_year, '%Y-%m-%d %H:%M:%S')
                        
                        if settings.USE_TZ:
                            tz = pytz.timezone(settings.TIME_ZONE)
                            timestamp = timezone.make_aware(timestamp, timezone=tz)
                            
                        logger.debug(f"Recovered timestamp without microseconds: {timestamp}")
                    except Exception as fallback_error:
                        logger.error(f"Failed to recover timestamp: {fallback_error}")
                        return
            else:
                logger.warning(f"Could not parse timestamp: '{timestamp_str}'")
                return
            
            
            try:
                signature_id = int(alert_data.get('sid', 0))
            except ValueError:
                signature_id = hash(alert_data.get('message', '')) % 1000000
            
            severity = int(alert_data.get('severity', 3))
            protocol = alert_data.get('protocol', '').strip()
            signature = alert_data.get('message', '').strip()
            
            try:
                src_port = int(alert_data.get('source_port', 0)) if alert_data.get('source_port') else 0
            except (ValueError, TypeError):
                src_port = 0
                
            try:
                dst_port = int(alert_data.get('destination_port', 0)) if alert_data.get('destination_port') else 0
            except (ValueError, TypeError):
                dst_port = 0
            
            
            existing_alert = SnortAlert.objects.filter(
                timestamp=timestamp,
                source_ip=source_ip,
                destination_ip=dest_ip,
                signature_id=signature_id
            ).first()
            
            if existing_alert:
                logger.debug(f"Skipping duplicate alert: {signature} from {source_ip} to {dest_ip}")
                return
                
            
            alert = SnortAlert.objects.create(
                timestamp=timestamp,
                source_ip=source_ip,
                destination_ip=dest_ip,
                source_port=src_port,
                destination_port=dst_port,
                protocol=protocol,
                severity=severity,
                signature=signature,
                signature_id=signature_id,
                raw_log=line
            )
            
            
            self.update_statistics(alert)
            
            logger.info(f"Processed alert: {signature} from {source_ip} to {dest_ip}")
            
        except Exception as e:
            logger.error(f"Error processing line: {str(e)}")
            logger.debug(f"Problem with line: {line}")
    
    def update_statistics(self, alert):
        """Update IP and daily statistics for the alert"""
        try:
           
            source_stat, _ = IPStats.objects.get_or_create(
                ip_address=alert.source_ip,
                is_source=True
            )
            source_stat.alert_count += 1
            
            
            protocols = source_stat.protocols
            if isinstance(protocols, str):
                protocols = {}
            if alert.protocol not in protocols:
                protocols[alert.protocol] = 0
            protocols[alert.protocol] += 1
            source_stat.protocols = protocols
            
            
            ports = source_stat.ports
            if isinstance(ports, str):
                ports = {}
            port_str = str(alert.destination_port)
            if port_str not in ports:
                ports[port_str] = 0
            ports[port_str] += 1
            source_stat.ports = ports
            source_stat.save()
            
            
            dest_stat, _ = IPStats.objects.get_or_create(
                ip_address=alert.destination_ip,
                is_source=False
            )
            dest_stat.alert_count += 1
            dest_stat.save()
            
           
            day = alert.timestamp.date()
            daily_stat, _ = DailyStats.objects.get_or_create(date=day)
            daily_stat.total_alerts += 1
            
            if alert.severity == 1:
                daily_stat.high_severity += 1
            elif alert.severity == 2:
                daily_stat.medium_severity += 1
            else:
                daily_stat.low_severity += 1
            
            daily_stat.save()
            
        except Exception as e:
            logger.error(f"Error updating statistics: {str(e)}")


class Command(BaseCommand):
    help = 'Continuously monitor Snort alerts.csv file and process new alerts'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--file',
            type=str,
            default=os.path.join(settings.BASE_DIR, '..', 'snort_logs', 'alerts.csv'),
            help='Path to CSV log file to monitor'
        )
        
        parser.add_argument(
            '--tail',
            action='store_true',
            help='Use simple tail mode instead of watchdog (better for containers)'
        )
    
    def handle(self, *args, **options):
        file_path = options['file']
        use_tail = options['tail']
        
       
        directory = os.path.dirname(file_path)
        if not os.path.exists(directory):
            os.makedirs(directory)
            
        
        if not os.path.exists(file_path):
            with open(file_path, 'w') as f:
                f.write('timestamp,src_ip,dst_ip,protocol,priority,signature_name,status\n')
        
        self.stdout.write(self.style.SUCCESS(f'Starting alert monitor for: {file_path}'))
        
        
        handler = AlertLogHandler(file_path)
        
        if use_tail:
            self.monitor_with_tail(handler)
        else:
            self.monitor_with_watchdog(handler, file_path)
    
    def monitor_with_watchdog(self, handler, file_path):
        """Use watchdog library for efficient event-based monitoring"""
        try:
            observer = Observer()
            observer.schedule(handler, os.path.dirname(file_path), recursive=False)
            observer.start()
            
            self.stdout.write(self.style.SUCCESS('Alert monitor started with watchdog'))
            
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                observer.stop()
                self.stdout.write(self.style.SUCCESS('Alert monitor stopped'))
            
            observer.join()
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Error in watchdog monitor: {str(e)}'))
    
    def monitor_with_tail(self, handler):
        """Use simple polling approach for compatibility with all environments"""
        try:
            self.stdout.write(self.style.SUCCESS('Alert monitor started with tail mode'))
            
            try:
                while True:
                    handler.process_new_lines()
                    time.sleep(1)  # Check once per second
            except KeyboardInterrupt:
                self.stdout.write(self.style.SUCCESS('Alert monitor stopped'))
                
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Error in tail monitor: {str(e)}'))