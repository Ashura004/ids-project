from django.db import models
import json
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver

class SnortAlert(models.Model):
    SEVERITY_CHOICES = [
        (1, 'High'),
        (2, 'Medium'),
        (3, 'Low'),
    ]
    
    timestamp = models.DateTimeField()
    source_ip = models.GenericIPAddressField()
    destination_ip = models.GenericIPAddressField()
    source_port = models.PositiveIntegerField()
    destination_port = models.PositiveIntegerField()
    protocol = models.CharField(max_length=10)
    signature = models.CharField(max_length=255)
    signature_id = models.PositiveIntegerField()
    severity = models.PositiveSmallIntegerField(choices=SEVERITY_CHOICES)
    raw_log = models.TextField()
    is_anomalous = models.BooleanField(default=False)
    anomaly_score = models.FloatField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['-timestamp']),
            models.Index(fields=['source_ip']),
            models.Index(fields=['destination_ip']),
            models.Index(fields=['severity']),
            models.Index(fields=['is_anomalous']),
        ]
    
    def __str__(self):
        return f"{self.timestamp} - {self.signature} ({self.source_ip}:{self.source_port} -> {self.destination_ip}:{self.destination_port})"


class IPStats(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    alert_count = models.PositiveIntegerField(default=0)
    anomaly_count = models.PositiveIntegerField(default=0)
    last_seen = models.DateTimeField(auto_now=True)
    is_source = models.BooleanField(default=True)
    protocols = models.JSONField(default=dict)  # Format: {"TCP": 10, "UDP": 5, ...}
    ports = models.JSONField(default=dict)      # Format: {"80": 10, "443": 5, ...}
    
    class Meta:
        indexes = [
            models.Index(fields=['-alert_count']),
            models.Index(fields=['-anomaly_count']),
            models.Index(fields=['-last_seen']),
        ]
    
    def __str__(self):
        return f"{self.ip_address} (Alerts: {self.alert_count})"
    
    def increment_protocol(self, protocol):
        protocols = self.protocols
        if protocol not in protocols:
            protocols[protocol] = 0
        protocols[protocol] += 1
        self.protocols = protocols
    
    def increment_port(self, port):
        ports = self.ports
        port_str = str(port)
        if port_str not in ports:
            ports[port_str] = 0
        ports[port_str] += 1
        self.ports = ports


class DailyStats(models.Model):
    date = models.DateField(unique=True)
    total_alerts = models.PositiveIntegerField(default=0)
    high_severity = models.PositiveIntegerField(default=0)
    medium_severity = models.PositiveIntegerField(default=0)
    low_severity = models.PositiveIntegerField(default=0)
    anomaly_count = models.PositiveIntegerField(default=0)
    
    class Meta:
        ordering = ['-date']
    
    def __str__(self):
        return f"Stats for {self.date} (Alerts: {self.total_alerts})"


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    role = models.CharField(max_length=50, default='analyst')
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)
    login_count = models.PositiveIntegerField(default=0)
    
    def __str__(self):
        return f"{self.user.username}'s Profile"


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)


@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    instance.profile.save()
