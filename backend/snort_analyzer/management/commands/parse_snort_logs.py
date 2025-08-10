import csv
import os
import re
import time
from datetime import datetime, timedelta
from django.core.management.base import BaseCommand
from django.utils import timezone
from django.contrib.auth.models import User
from snort_analyzer.models import SnortAlert, AttackNotification
import pytz 
from snort_analyzer.ml.anomaly_detector import ml_detector

class Command(BaseCommand):
    help = 'Parse Snort log files and populate the database'

    def __init__(self):
        super().__init__()
        self.monitoring = False
        self.processed_count = 0
        self.error_count = 0

    def add_arguments(self, parser):
        parser.add_argument(
            '--file',
            type=str,
            help='Path to the Snort log file',
            required=True
        )
        parser.add_argument(
            '--monitor',
            action='store_true',
            help='Enable monitoring mode (watch for new entries)',
        )
        parser.add_argument(
            '--format',
            type=str,
            choices=['csv', 'space_delimited'],
            default='csv',
            help='Log file format (default: csv)',
        )

    def handle(self, *args, **options):
        file_path = options['file']
        self.monitoring = options['monitor']
        log_format = options['format']

        if not os.path.exists(file_path):
            self.stdout.write(
                self.style.ERROR(f'File not found: {file_path}')
            )
            return

        self.stdout.write(
            self.style.SUCCESS(f'Starting to parse: {file_path}')
        )

        if self.monitoring:
            self.stdout.write(
                self.style.WARNING('Monitoring mode enabled. Press Ctrl+C to stop.')
            )
            self.monitor_file(file_path, log_format)
        else:
            self.parse_file(file_path, log_format)

        self.stdout.write(
            self.style.SUCCESS(
                f'Parsing completed. Processed: {self.processed_count}, Errors: {self.error_count}'
            )
        )

    def parse_file(self, file_path, log_format):
        """Parse the entire file once"""
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                if log_format == 'csv':
                    self.parse_csv_file(file)
                else:
                    self.parse_space_delimited_file(file)
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error reading file: {str(e)}')
            )

    def monitor_file(self, file_path, log_format):
        """Monitor file for new entries"""
        try:
            # Read existing file first
            self.parse_file(file_path, log_format)
            
            # Get initial file size
            last_size = os.path.getsize(file_path)
            
            self.stdout.write(
                self.style.SUCCESS(f'Monitoring {file_path} for new entries...')
            )
            
            while True:
                try:
                    current_size = os.path.getsize(file_path)
                    
                    if current_size > last_size:
                        # File has grown, read new content
                        with open(file_path, 'r', encoding='utf-8') as file:
                            file.seek(last_size)
                            new_content = file.read()
                            
                            if new_content.strip():
                                self.stdout.write(
                                    self.style.SUCCESS('New content detected!')
                                )
                                self.parse_new_content(new_content, log_format)
                        
                        last_size = current_size
                    
                    time.sleep(1)  # Check every second
                    
                except KeyboardInterrupt:
                    self.stdout.write(
                        self.style.SUCCESS('\nMonitoring stopped by user.')
                    )
                    break
                except Exception as e:
                    self.stdout.write(
                        self.style.ERROR(f'Monitoring error: {str(e)}')
                    )
                    time.sleep(5)  # Wait before retrying
                    
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Monitor setup error: {str(e)}')
            )

    def parse_csv_file(self, file):
        """Parse CSV format file"""
        try:
            csv_reader = csv.reader(file)
            for line_num, row in enumerate(csv_reader, 1):
                if row:  # Skip empty rows
                    self.parse_csv_row(row, line_num)
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'CSV parsing error: {str(e)}')
            )

    def parse_space_delimited_file(self, file):
        """Parse space-delimited format file"""
        for line_num, line in enumerate(file, 1):
            line = line.strip()
            if line:  # Skip empty lines
                self.parse_single_line(line, line_num)

    def parse_new_content(self, content, log_format):
        """Parse new content added to the file"""
        lines = content.strip().split('\n')
        for line in lines:
            if line.strip():
                if log_format == 'csv':
                    # Parse as CSV row
                    try:
                        import csv
                        from io import StringIO
                        csv_reader = csv.reader(StringIO(line))
                        row = next(csv_reader)
                        self.parse_csv_row(row, 0)
                    except:
                        self.parse_single_line(line, 0)
                else:
                    self.parse_single_line(line, 0)

    def parse_csv_row(self, row, line_num):
        """Parse a CSV row"""
        try:
            if len(row) < 8:
                return None

            # CSV format: timestamp, severity, signature_id, source_ip, dest_ip, protocol, signature, raw_log
            timestamp_str = row[0] if len(row) > 0 else ''
            severity = int(row[1]) if len(row) > 1 and row[1].isdigit() else 3
            signature_id = int(row[2]) if len(row) > 2 and row[2].isdigit() else 999999
            source_ip = row[3] if len(row) > 3 else '0.0.0.0'
            dest_ip = row[4] if len(row) > 4 else '0.0.0.0'
            protocol = row[5].lower() if len(row) > 5 else 'unknown'
            signature = row[6] if len(row) > 6 else f'Alert {signature_id}'
            raw_log = ' '.join(row) if len(row) > 7 else ''

            # Parse timestamp
            timestamp = self.parse_timestamp(timestamp_str)

            # Classify severity and detect anomaly
            severity = self.classify_severity(protocol, signature, severity, source_ip, dest_ip)
            is_anomalous, anomaly_score = self.detect_anomaly(protocol, signature, severity, source_ip, dest_ip)

            # Create alert
            alert, created = SnortAlert.objects.get_or_create(
                source_ip=source_ip,
                destination_ip=dest_ip,
                signature_id=signature_id,
                timestamp=timestamp,
                defaults={
                    'signature': signature[:200],
                    'source_port': 0,
                    'destination_port': 0,
                    'protocol': protocol,
                    'severity': severity,
                    'raw_log': raw_log[:500],
                    'is_anomalous': is_anomalous,
                    'anomaly_score': anomaly_score
                }
            )

            if created:
                self.processed_count += 1
                
                # Create notification for high severity alerts
                if alert.severity == 1:
                    self.create_high_severity_notification(alert)
                
                if self.monitoring:
                    anomaly_status = "ANOMALY" if is_anomalous else "NORMAL"
                    self.stdout.write(f'NEW ALERT: {source_ip} -> {dest_ip} | {signature} [Severity: {get_severity_display(severity)}] [{anomaly_status}]')

            return alert

        except Exception as e:
            self.error_count += 1
            self.stdout.write(self.style.ERROR(f'Error parsing CSV row {line_num}: {str(e)}'))
            return None

    def parse_timestamp(self, timestamp_str):
        """Parse timestamp from various formats with fixed timezone handling"""
        
        if not timestamp_str or timestamp_str.strip() == '':
            return timezone.now()
        
        timestamp_str = timestamp_str.strip()
        
        try:
            # Format 1: Snort format MM/DD-HH:MM:SS.microseconds (e.g., "08/03-20:15:16.917486")
            if '/' in timestamp_str and '-' in timestamp_str:
                try:
                    date_part, time_part = timestamp_str.split('-', 1)
                    month, day = date_part.split('/')
                    
                    current_year = timezone.now().year
                    
                    # Handle microseconds if present
                    if '.' in time_part:
                        time_base, microseconds = time_part.rsplit('.', 1)
                        # Ensure microseconds is exactly 6 digits
                        microseconds = microseconds[:6].ljust(6, '0')
                        full_datetime_str = f"{current_year}-{month.zfill(2)}-{day.zfill(2)} {time_base}.{microseconds}"
                        dt = datetime.strptime(full_datetime_str, '%Y-%m-%d %H:%M:%S.%f')
                    else:
                        full_datetime_str = f"{current_year}-{month.zfill(2)}-{day.zfill(2)} {time_part}"
                        dt = datetime.strptime(full_datetime_str, '%Y-%m-%d %H:%M:%S')
                    
                    # Make timezone aware using timezone.make_aware instead of timezone.utc
                    return timezone.make_aware(dt, timezone=pytz.UTC)
                    
                except Exception as e:
                    self.stdout.write(self.style.WARNING(f'Failed to parse Snort format timestamp "{timestamp_str}": {e}'))
            
            # Format 2: ISO format
            elif 'T' in timestamp_str:
                try:
                    clean_timestamp = timestamp_str.replace('Z', '+00:00')
                    dt = datetime.fromisoformat(clean_timestamp)
                    if dt.tzinfo is None:
                        return timezone.make_aware(dt, timezone=pytz.UTC)
                    return dt
                except Exception as e:
                    self.stdout.write(self.style.WARNING(f'Failed to parse ISO timestamp "{timestamp_str}": {e}'))
            
            # Format 3: Standard datetime
            elif ' ' in timestamp_str and ':' in timestamp_str:
                try:
                    if '.' in timestamp_str:
                        dt = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S.%f')
                    else:
                        dt = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                    return timezone.make_aware(dt, timezone=pytz.UTC)
                except Exception as e:
                    self.stdout.write(self.style.WARNING(f'Failed to parse standard timestamp "{timestamp_str}": {e}'))
            
            # If nothing worked, return current time
            self.stdout.write(self.style.WARNING(f'Using current time for unparseable timestamp: "{timestamp_str}"'))
            return timezone.now()
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Timestamp parsing error for "{timestamp_str}": {e}'))
            return timezone.now()

    def parse_single_line(self, line, line_num):
        """Parse a single space-delimited line with better IP extraction"""
        try:
            parts = [part for part in line.strip().split() if part]
            
            if len(parts) < 8:
                return None
            
            # Extract data from format: 2476 08/03-01:44:22.160189 1 1000001 1 ICMP Ping ICMP 10.0.2.2 10.0.2.15
            row_number = parts[0]
            timestamp_str = parts[1]
            original_severity = int(parts[2]) if parts[2].isdigit() else 3
            signature_id = int(parts[3]) if parts[3].isdigit() else 999999
            
            # Find IP addresses - improved regex and extraction
            ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
            ip_matches = re.findall(ip_pattern, line)
            
            # Debug IP extraction
            if self.monitoring:
                self.stdout.write(f'Found IPs in line: {ip_matches}')
            
            # Get the last two IPs as source and destination
            if len(ip_matches) >= 2:
                source_ip = ip_matches[-2]  # Second to last IP
                dest_ip = ip_matches[-1]    # Last IP
            elif len(ip_matches) == 1:
                source_ip = ip_matches[0]
                dest_ip = "0.0.0.0"
            else:
                source_ip = "0.0.0.0"
                dest_ip = "0.0.0.0"
            
            # Extract protocol
            protocol = "unknown"
            protocol_keywords = ['TCP', 'UDP', 'ICMP', 'IP', 'ARP', 'DNS', 'HTTP', 'HTTPS']
            for part in parts:
                if part.upper() in protocol_keywords:
                    protocol = part.lower()
                    break
            
            # Build signature - get the descriptive text between protocol and IPs
            signature_parts = []
            start_collecting = False
            
            for i, part in enumerate(parts):
                # Start collecting after we see the signature ID and skip the first "1"
                if part.isdigit() and int(part) == signature_id:
                    start_collecting = True
                    continue
                
                # Skip the "1" that often follows signature ID
                if start_collecting and part == "1":
                    continue
                
                # Start collecting signature parts
                if start_collecting and not re.match(ip_pattern, part):
                    if part.upper() not in protocol_keywords:
                        signature_parts.append(part)
                
                # Stop when we hit an IP address
                if start_collecting and re.match(ip_pattern, part):
                    break
            
            signature = " ".join(signature_parts) if signature_parts else f"Alert {signature_id}"
            
            # Clean up signature
            signature = signature.replace("Ping", "Ping Request").replace("ICMP", "ICMP")
            
            # Parse timestamp
            timestamp = self.parse_timestamp(timestamp_str)
            
            # Classify severity and detect anomaly
            severity = self.classify_severity(protocol, signature, signature_id, source_ip, dest_ip)
            is_anomalous, anomaly_score = self.detect_anomaly(protocol, signature, severity, source_ip, dest_ip)
            
            # Create alert
            alert, created = SnortAlert.objects.get_or_create(
                source_ip=source_ip,
                destination_ip=dest_ip,
                signature_id=signature_id,
                timestamp=timestamp,
                defaults={
                    'signature': signature[:200],
                    'source_port': 0,
                    'destination_port': 0,
                    'protocol': protocol,
                    'severity': severity,
                    'raw_log': line.strip()[:500],
                    'is_anomalous': is_anomalous,
                    'anomaly_score': anomaly_score
                }
            )
            
            if created:
                self.processed_count += 1
                
                # Create notification for high severity alerts
                if alert.severity == 1:
                    self.create_high_severity_notification(alert)
                
                if self.monitoring:
                    anomaly_status = "ANOMALY" if is_anomalous else "NORMAL"
                    self.stdout.write(f'NEW ALERT: {source_ip} -> {dest_ip} | {signature} [Severity: {get_severity_display(severity)}] [{anomaly_status}]')
                
            return alert
            
        except Exception as e:
            self.error_count += 1
            self.stdout.write(self.style.ERROR(f'Error parsing line {line_num}: {str(e)}'))
            return None

    def detect_anomaly(self, protocol, signature, severity, source_ip, dest_ip):
        """
        Enhanced anomaly detection with better high-severity threat detection
        Returns: (is_anomalous: bool, anomaly_score: float)
        """
        # Import ML detector if available
        try:
            from snort_analyzer.ml.anomaly_detector import ml_detector
            ml_available = ml_detector.is_trained
        except ImportError:
            ml_available = False
        
        # Create temporary alert for ML if available
        if ml_available:
            try:
                class TempAlert:
                    def __init__(self, protocol, signature, severity, source_ip, dest_ip):
                        self.protocol = protocol
                        self.signature = signature
                        self.severity = severity
                        self.source_ip = source_ip
                        self.destination_ip = dest_ip
                        self.source_port = 0
                        self.destination_port = 0
                        self.signature_id = 999999
                        self.timestamp = timezone.now()
                
                temp_alert = TempAlert(protocol, signature, severity, source_ip, dest_ip)
                is_anomalous, anomaly_score, confidence = ml_detector.predict_anomaly(temp_alert)
                
                if self.monitoring:
                    self.stdout.write(f'🤖 ML: Anomaly={is_anomalous}, Score={anomaly_score:.3f}, Confidence={confidence:.3f}')
                
                return is_anomalous, anomaly_score
            except Exception as e:
                if self.monitoring:
                    self.stdout.write(self.style.WARNING(f'ML prediction failed: {e}'))
        
        # Enhanced rule-based detection as fallback
        return self.enhanced_rule_based_detection(protocol, signature, severity, source_ip, dest_ip)

    def enhanced_rule_based_detection(self, protocol, signature, severity, source_ip, dest_ip):
        """
        Enhanced rule-based anomaly detection with better threat recognition
        """
        protocol = protocol.lower()
        signature_lower = signature.lower()
        anomaly_score = 0.0
        
        # HIGH SEVERITY ALERTS - These should ALWAYS be anomalies
        if severity == 1:
            anomaly_score = 0.9
            if self.monitoring:
                self.stdout.write(f'🚨 HIGH SEVERITY detected: {signature}')
        
        # DEFINITE THREAT PATTERNS (ALWAYS ANOMALIES)
        high_threat_patterns = [
            'malware', 'trojan', 'backdoor', 'exploit', 'injection', 'overflow',
            'ransomware', 'botnet', 'command and control', 'shellcode', 'payload',
            'sql injection', 'xss', 'cross site scripting', 'buffer overflow',
            'directory traversal', 'remote code execution', 'privilege escalation',
            'denial of service', 'dos attack', 'ddos', 'brute force',
            'password attack', 'credential stuffing', 'unauthorized access'
        ]
        
        for pattern in high_threat_patterns:
            if pattern in signature_lower:
                anomaly_score = max(anomaly_score, 0.9)
                if self.monitoring:
                    self.stdout.write(f'THREAT PATTERN detected: {pattern}')
                break
        
        # SUSPICIOUS PATTERNS (LIKELY ANOMALIES)
        suspicious_patterns = [
            'suspicious', 'unusual', 'scan', 'probe', 'reconnaissance',
            'enumeration', 'fingerprint', 'port scan', 'network scan',
            'vulnerability scan', 'attempted', 'possible attack'
        ]
        
        for pattern in suspicious_patterns:
            if pattern in signature_lower:
                anomaly_score = max(anomaly_score, 0.7)
                if self.monitoring:
                    self.stdout.write(f'SUSPICIOUS PATTERN detected: {pattern}')
                break
        
        # NORMAL TRAFFIC PATTERNS (NEVER ANOMALIES)
        normal_patterns = [
            'ping', 'echo request', 'echo reply', 'dns query', 'dns response',
            'http request', 'http response', 'dhcp', 'ntp', 'arp',
            'normal', 'legitimate', 'standard', 'icmp ping'
        ]
        
        for pattern in normal_patterns:
            if pattern in signature_lower:
                # Override previous scoring for clearly normal traffic
                if severity >= 3:  # Only for low severity
                    anomaly_score = 0.0
                    if self.monitoring:
                        self.stdout.write(f'NORMAL PATTERN detected: {pattern}')
                break
        
        # PROTOCOL-SPECIFIC RULES
        if protocol == 'tcp':
            if any(word in signature_lower for word in ['syn flood', 'rst flood', 'fin flood']):
                anomaly_score = max(anomaly_score, 0.8)
            elif any(word in signature_lower for word in ['connection', 'established']):
                if severity >= 3:
                    anomaly_score = min(anomaly_score, 0.2)
        
        elif protocol == 'udp':
            if any(word in signature_lower for word in ['udp flood', 'amplification']):
                anomaly_score = max(anomaly_score, 0.8)
        
        elif protocol == 'icmp':
            if any(word in signature_lower for word in ['flood', 'storm', 'attack']):
                anomaly_score = max(anomaly_score, 0.7)
            elif any(word in signature_lower for word in ['ping', 'echo']):
                if severity >= 3:
                    anomaly_score = 0.0
        
        # SEVERITY-BASED ADJUSTMENT
        if severity == 1:  # High severity
            anomaly_score = max(anomaly_score, 0.8)
        elif severity == 2:  # Medium severity
            anomaly_score = max(anomaly_score, 0.5)
        # Low severity (3) doesn't automatically increase score
        
        # EXTERNAL TO INTERNAL TRAFFIC (More suspicious)
        if self.is_external_ip(source_ip) and self.is_internal_ip(dest_ip):
            anomaly_score = min(anomaly_score + 0.1, 1.0)
            if self.monitoring:
                self.stdout.write(f'External to Internal traffic: {source_ip} -> {dest_ip}')
        
        # Final decision
        anomaly_score = min(anomaly_score, 1.0)
        is_anomalous = anomaly_score >= 0.5
        
        if self.monitoring:
            status = "ANOMALY" if is_anomalous else "NORMAL"
            self.stdout.write(f'{status}: Score={anomaly_score:.3f} | {signature[:50]}...')
        
        return is_anomalous, anomaly_score

    def is_internal_ip(self, ip):
        """Check if IP is in private/internal range"""
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except:
            return False

    def is_external_ip(self, ip):
        """Check if IP is external/public"""
        return not self.is_internal_ip(ip) and ip != "0.0.0.0"

    def classify_severity(self, protocol, signature, signature_id, source_ip, dest_ip):
        """Classify alert severity based on protocol, signature, and context"""
        
        # Convert to lowercase for easier matching
        protocol = protocol.lower()
        signature_lower = signature.lower()
        
        # HIGH SEVERITY (1) - Critical threats
        high_severity_indicators = [
            'malware', 'trojan', 'backdoor', 'rootkit', 'botnet',
            'sql injection', 'xss', 'buffer overflow', 'exploit',
            'brute force', 'password attack', 'shell', 'ransomware',
            'suspicious file', 'lateral movement', 'privilege escalation',
            'command and control', 'data exfiltration'
        ]
        
        # MEDIUM SEVERITY (2) - Suspicious activity
        medium_severity_indicators = [
            'scan', 'probe', 'reconnaissance', 'enumeration',
            'suspicious', 'anomaly', 'unusual', 'unauthorized',
            'login failure', 'access denied', 'port scan',
            'vulnerability', 'suspicious dns', 'failed attempt'
        ]
        
        # Check for high severity indicators
        for indicator in high_severity_indicators:
            if indicator in signature_lower:
                return 1
        
        # Check for medium severity indicators
        for indicator in medium_severity_indicators:
            if indicator in signature_lower:
                return 2
        
        # Protocol-specific classification
        if protocol == 'icmp':
            # ICMP is generally low severity unless it's attack-related
            if any(word in signature_lower for word in ['flood', 'dos', 'attack', 'malicious']):
                return 2  # Medium for suspicious ICMP
            return 3  # Low for normal ICMP (ping, echo, etc.)
        
        elif protocol == 'tcp':
            # TCP varies based on context
            if any(word in signature_lower for word in ['syn flood', 'connection refused', 'reset']):
                return 2
            elif any(word in signature_lower for word in ['http', 'https', 'ssh', 'ftp', 'normal']):
                return 3  # Normal TCP services
            return 2  # Default medium for unknown TCP
        
        elif protocol == 'udp':
            # UDP varies based on ports and content
            if any(word in signature_lower for word in ['dns', 'dhcp', 'ntp']):
                return 3  # Low for common UDP services
            return 2  # Medium for other UDP
        
        # Default classification
        return 3  # Low severity

    def create_high_severity_notification(self, alert):
        """Create notification for high severity alerts"""
        try:
            # Get or create admin user
            user, created = User.objects.get_or_create(
                username='admin',
                defaults={'email': 'admin@example.com', 'is_staff': True}
            )
            
            # Create notification
            AttackNotification.objects.create(
                user=user,
                attack_type=f'High Severity Alert',
                description=f'Alert: {alert.signature} from {alert.source_ip} to {alert.destination_ip}',
                severity='high'
            )
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Error creating notification: {e}'))

def get_severity_display(severity):
    """Convert severity number to display text"""
    severity_map = {1: 'High', 2: 'Medium', 3: 'Low'}
    return severity_map.get(severity, 'Unknown')