# snort_analyzer/serializers.py

from rest_framework import serializers
from .models import SnortAlert, IPStats, DailyStats

class SnortAlertSerializer(serializers.ModelSerializer):
    severity_display = serializers.CharField(source='get_severity_display', read_only=True)
    
    class Meta:
        model = SnortAlert
        fields = [
            'id', 'timestamp', 'source_ip', 'destination_ip', 'source_port', 
            'destination_port', 'protocol', 'signature', 'signature_id',
            'severity', 'severity_display', 'is_anomalous', 'anomaly_score', 'created_at'
        ]

class IPStatsSerializer(serializers.ModelSerializer):
    class Meta:
        model = IPStats
        fields = [
            'ip_address', 'alert_count', 'anomaly_count', 'last_seen',
            'is_source', 'protocols', 'ports'
        ]

class DailyStatsSerializer(serializers.ModelSerializer):
    class Meta:
        model = DailyStats
        fields = [
            'date', 'total_alerts', 'high_severity', 'medium_severity',
            'low_severity', 'anomaly_count'
        ]

class AlertCountByProtocolSerializer(serializers.Serializer):
    protocol = serializers.CharField()
    count = serializers.IntegerField()

class TopSourceIPsSerializer(serializers.Serializer):
    ip_address = serializers.IPAddressField()
    alert_count = serializers.IntegerField()

class TopDestinationIPsSerializer(serializers.Serializer):
    ip_address = serializers.IPAddressField()
    alert_count = serializers.IntegerField()

class AlertTrendSerializer(serializers.Serializer):
    date = serializers.DateField()
    count = serializers.IntegerField()
    anomaly_count = serializers.IntegerField()