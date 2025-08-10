from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

class AttackNotification(models.Model):
    SEVERITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    attack_type = models.CharField(max_length=100, default='Security Alert')
    description = models.TextField(default='No description available')
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='medium')
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(default=timezone.now)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.attack_type} - {self.severity}"

class SnortAlert(models.Model):
    signature = models.CharField(max_length=500, default='No signature')
    source_ip = models.GenericIPAddressField(default='0.0.0.0')
    source_port = models.IntegerField(default=0)
    destination_ip = models.GenericIPAddressField(default='0.0.0.0')
    destination_port = models.IntegerField(default=0)
    protocol = models.CharField(max_length=20, default='unknown')
    timestamp = models.DateTimeField(default=timezone.now)
    severity = models.IntegerField(default=3)  # 1=High, 2=Medium, 3=Low
    signature_id = models.IntegerField(default=0)
    raw_log = models.TextField(blank=True, default='')
    is_anomalous = models.BooleanField(default=False)
    anomaly_score = models.FloatField(default=0.0)
    created_at = models.DateTimeField(default=timezone.now, null=True, blank=True)
    
    class Meta:
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"{self.signature} - {self.source_ip} -> {self.destination_ip}"
