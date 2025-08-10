"""
Database migration to add ML prediction fields to SnortAlert model
Run this migration after adding the new fields to your models.py
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('snort_analyzer', '0005_alter_ipstats_alert_count_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='snortalert',
            name='ml_prediction',
            field=models.JSONField(blank=True, null=True, help_text='ML prediction results including threat probability and confidence'),
        ),
        migrations.AddField(
            model_name='snortalert',
            name='threat_level',
            field=models.CharField(
                blank=True,
                choices=[('LOW', 'Low'), ('MEDIUM', 'Medium'), ('HIGH', 'High')],
                max_length=10,
                null=True,
                help_text='ML-determined threat level'
            ),
        ),
        migrations.AddField(
            model_name='snortalert',
            name='ml_processed',
            field=models.BooleanField(default=False, help_text='Whether this alert has been processed by ML classifier'),
        ),
        migrations.AddField(
            model_name='snortalert',
            name='threat_probability',
            field=models.FloatField(blank=True, null=True, help_text='ML-calculated probability of being a threat (0.0-1.0)'),
        ),
        migrations.AddIndex(
            model_name='snortalert',
            index=models.Index(fields=['threat_level'], name='snort_analy_threat_level_idx'),
        ),
        migrations.AddIndex(
            model_name='snortalert',
            index=models.Index(fields=['ml_processed'], name='snort_analy_ml_processed_idx'),
        ),
    ]
