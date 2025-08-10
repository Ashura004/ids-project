"""
Additional Django settings for ML Integration
Add these settings to your main settings.py file or create a separate ml_settings.py
"""

# ML Model Configuration
ML_MODELS_DIR = os.path.join(BASE_DIR, 'ml_models')

# ML Notification Settings
ML_NOTIFICATIONS_ENABLED = True
ML_EMAIL_NOTIFICATIONS = True

# Email Configuration for Threat Notifications
# Update these with your actual email settings
if ML_EMAIL_NOTIFICATIONS:
    EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
    EMAIL_HOST = 'smtp.gmail.com'  # Replace with your SMTP server
    EMAIL_PORT = 587
    EMAIL_USE_TLS = True
    EMAIL_HOST_USER = 'your-email@gmail.com'  # Replace with your email
    EMAIL_HOST_PASSWORD = 'your-app-password'  # Replace with your password/app password
    DEFAULT_FROM_EMAIL = 'IDS System <your-email@gmail.com>'

# ML Processing Settings
ML_BATCH_SIZE = 100  # Number of alerts to process in each batch
ML_HIGH_CONFIDENCE_THRESHOLD = 0.8  # Threshold for high confidence threats
ML_MEDIUM_CONFIDENCE_THRESHOLD = 0.6  # Threshold for medium confidence threats

# Logging Configuration for ML Components
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': os.path.join(BASE_DIR, 'logs', 'ml_processing.log'),
        },
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
        },
    },
    'loggers': {
        'snort_analyzer.ml': {
            'handlers': ['file', 'console'],
            'level': 'INFO',
            'propagate': True,
        },
        'snort_analyzer.services': {
            'handlers': ['file', 'console'],
            'level': 'INFO',
            'propagate': True,
        },
    },
}

# Create logs directory if it doesn't exist
import os
os.makedirs(os.path.join(BASE_DIR, 'logs'), exist_ok=True)
