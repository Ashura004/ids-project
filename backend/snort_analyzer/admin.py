from django.contrib import admin
from .models import SnortAlert, IPStats, DailyStats

@admin.register(SnortAlert)
class SnortAlertAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'source_ip', 'destination_ip', 'protocol', 
                    'signature', 'severity', 'is_anomalous')
    list_filter = ('severity', 'protocol', 'is_anomalous')
    search_fields = ('source_ip', 'destination_ip', 'signature')
    date_hierarchy = 'timestamp'

@admin.register(IPStats)
class IPStatsAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'is_source', 'alert_count', 'anomaly_count', 'last_seen')
    list_filter = ('is_source',)
    search_fields = ('ip_address',)

@admin.register(DailyStats)
class DailyStatsAdmin(admin.ModelAdmin):
    list_display = ('date', 'total_alerts', 'high_severity', 'medium_severity', 
                   'low_severity', 'anomaly_count')
