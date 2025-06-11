from rest_framework import serializers
from .models import AttackNotification

class AttackNotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = AttackNotification
        fields = ['timestamp', 'attack_type', 'description', 'severity', 'is_read']
        read_only_fields = ['timestamp']