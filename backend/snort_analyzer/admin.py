from django.contrib import admin
from .models import SnortAlert, AttackNotification

@admin.register(SnortAlert)
class SnortAlertAdmin(admin.ModelAdmin):
    list_display = ['id', 'signature', 'source_ip', 'destination_ip', 'protocol', 'severity', 'timestamp']
    list_filter = ['severity', 'protocol', 'timestamp']
    search_fields = ['signature', 'source_ip', 'destination_ip']
    ordering = ['-timestamp']
    list_per_page = 50
    
    fieldsets = (
        ('Alert Information', {
            'fields': ('signature', 'signature_id', 'severity')
        }),
        ('Network Details', {
            'fields': ('source_ip', 'source_port', 'destination_ip', 'destination_port', 'protocol')
        }),
        ('Metadata', {
            'fields': ('timestamp', 'raw_log', 'is_anomalous', 'anomaly_score')
        }),
    )

@admin.register(AttackNotification)
class AttackNotificationAdmin(admin.ModelAdmin):
    list_display = ['id', 'attack_type', 'severity', 'user', 'is_read', 'created_at']
    list_filter = ['severity', 'is_read', 'created_at']
    search_fields = ['attack_type', 'description']
    ordering = ['-created_at']
    list_per_page = 50
    
    fieldsets = (
        ('Notification Details', {
            'fields': ('attack_type', 'description', 'severity')
        }),
        ('Status', {
            'fields': ('user', 'is_read', 'created_at')
        }),
    )
