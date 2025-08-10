# Machine Learning Integration Setup Guide
# Network Intrusion Detection System (IDS)

## Overview
This guide provides step-by-step instructions to integrate machine learning threat classification into your existing Django-based Network Intrusion Detection System.

## Prerequisites
- Existing Django IDS project with Snort log parsing
- Python 3.8+ (Python 3.13.5 confirmed working)
- Virtual environment (recommended)
- KDD Cup 1999 dataset (download separately)

## Important: Python Path Configuration
If you encounter "No Python at 'C:\Python312\python.exe'" or similar errors:

1. **Check your Python installation:**
   ```bash
   python --version
   ```

2. **Find correct Python path:**
   ```bash
   # PowerShell
   Get-Command python | Select-Object -ExpandProperty Source
   ```

3. **Configure VS Code Python interpreter:**
   - Press `Ctrl+Shift+P`
   - Type "Python: Select Interpreter"
   - Choose the correct Python path (e.g., `C:/Python313/python.exe`)

4. **Use the correct Python command:**
   Instead of `python`, you may need to use the full path:
   ```bash
   C:/Python313/python.exe manage.py train_ml_models
   ```

## Step 1: Install ML Dependencies

1. **Activate your virtual environment:**
   ```bash
   cd backend
   # Windows PowerShell
   .\.venv\Scripts\Activate.ps1
   # OR Windows Command Prompt
   .\.venv\Scripts\activate.bat
   # OR Linux/Mac
   source venv/bin/activate
   ```

2. **Install ML packages:**
   ```bash
   pip install scikit-learn pandas numpy joblib matplotlib seaborn scipy
   ```

3. **Verify installation:**
   ```bash
   # Test the installation
   C:/Python313/python.exe test_ml_setup.py
   # OR if python command works directly:
   python test_ml_setup.py
   ```

   Expected output:
   ```
   ✅ scikit-learn 1.7.1 imported successfully
   ✅ pandas 2.3.1 imported successfully
   ✅ numpy 2.3.1 imported successfully
   ✅ joblib 1.5.1 imported successfully
   🎉 All tests passed! ML environment is ready.
   ```

## Step 2: Download and Prepare Dataset

1. **Download KDD Cup 1999 dataset:**
   - Visit: https://www.kdd.org/kdd-cup/view/kdd-cup-1999/Data
   - Download the 10% subset: `kddcup.data_10_percent.gz`
   - Extract and rename to `kdd_test.csv`

2. **Place dataset in project root:**
   ```
   backend/
   ├── kdd_test.csv  # Place here
   ├── manage.py
   ├── ml_models/
   └── ...
   ```

## Step 3: Update Django Settings

1. **Add ML settings to your `settings.py`:**
   ```python
   # At the end of settings.py, add:
   
   # ML Configuration
   import os
   
   ML_MODELS_DIR = os.path.join(BASE_DIR, 'ml_models')
   ML_NOTIFICATIONS_ENABLED = True
   ML_EMAIL_NOTIFICATIONS = True
   
   # Email settings (update with your SMTP details)
   EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
   EMAIL_HOST = 'smtp.gmail.com'  # Your SMTP server
   EMAIL_PORT = 587
   EMAIL_USE_TLS = True
   EMAIL_HOST_USER = 'your-email@example.com'  # Your email
   EMAIL_HOST_PASSWORD = 'your-password'  # Your password
   DEFAULT_FROM_EMAIL = 'IDS System <your-email@example.com>'
   
   # Create logs directory
   os.makedirs(os.path.join(BASE_DIR, 'logs'), exist_ok=True)
   ```

2. **Create directories:**
   ```bash
   mkdir -p ml_models
   mkdir -p logs
   mkdir -p snort_analyzer/templates/snort_analyzer
   mkdir -p snort_analyzer/services
   ```

## Step 4: Run Database Migration

1. **Create and apply migration:**
   ```bash
   python manage.py makemigrations
   python manage.py migrate
   ```

## Step 5: Train ML Models

1. **Train models using the provided dataset:**
   ```bash
   # Use the correct Python path for your system
   C:/Python313/python.exe manage.py train_ml_models --dataset-path kdd_test.csv
   # OR if python command works directly:
   python manage.py train_ml_models --dataset-path kdd_test.csv
   ```

2. **Expected output:**
   ```
   🤖 ML Model Training Command
   ==================================================
   📊 Starting model training...
   Dataset loaded: 311,029 samples, 42 features
   
   Training Random Forest Classifier...
   ✅ Accuracy: 99.41%
   
   Training Logistic Regression...
   ✅ Accuracy: 91.56%
   
   🏆 Best model (random_forest) saved as default classifier
   🎉 TRAINING COMPLETE!
   ```

## Step 6: Process Existing Alerts with ML

1. **Process unprocessed alerts:**
   ```bash
   C:/Python313/python.exe manage.py process_ml_threats --batch-size 100
   # OR if python command works:
   python manage.py process_ml_threats --batch-size 100
   ```

2. **View processing statistics:**
   ```bash
   C:/Python313/python.exe manage.py process_ml_threats --stats-only
   # OR:
   python manage.py process_ml_threats --stats-only
   ```

## Step 7: Test Real-time Processing

1. **Parse new Snort logs (with ML integration):**
   ```bash
   python manage.py parse_snort_logs --file ../snort_logs/alerts.csv
   ```

2. **The system will now automatically:**
   - Parse Snort alerts
   - Run ML threat classification
   - Create notifications for threats
   - Send email alerts for high-priority threats

## Usage Examples

### Example 1: View ML Statistics
```bash
python manage.py process_ml_threats --stats-only
```

Output:
```
📊 CURRENT ML STATISTICS:
   Total alerts: 1,250
   Processed: 1,100
   Unprocessed: 150
   Processing rate: 88.0%
   Threats detected: 180
   - High severity: 25
   - Medium severity: 67
   Threat detection rate: 16.4%
   Model: ✅ RandomForestClassifier
```

### Example 2: Batch Process Alerts
```bash
python manage.py process_ml_threats --batch-size 50 --max-batches 10
```

### Example 3: Retrain Models
```bash
python manage.py train_ml_models --retrain
```

### Example 4: Process Recent Alerts Only
```bash
python manage.py process_ml_threats --since-hours 24 --batch-size 200
```

## Understanding the Results

### Alert Classification
- **Normal Traffic**: `threat_probability < 0.6`, `threat_level = "LOW"`
- **Suspicious Activity**: `0.6 <= threat_probability < 0.8`, `threat_level = "MEDIUM"`
- **High Threat**: `threat_probability >= 0.8`, `threat_level = "HIGH"`

### Database Fields Added
```python
class SnortAlert(models.Model):
    # ... existing fields ...
    
    # New ML fields
    ml_processed = models.BooleanField(default=False)
    threat_probability = models.FloatField(null=True, blank=True)
    threat_level = models.CharField(max_length=10, choices=THREAT_LEVEL_CHOICES)
    ml_prediction = models.JSONField(null=True, blank=True)
```

### Notification System
- **Database Notifications**: Created for all detected threats
- **Email Alerts**: Sent for HIGH threat level alerts only
- **Admin Panel**: View all notifications through Django admin

## Monitoring and Maintenance

### Daily Tasks
1. **Check ML processing status:**
   ```bash
   python manage.py process_ml_threats --stats-only
   ```

2. **Process any unprocessed alerts:**
   ```bash
   python manage.py process_ml_threats
   ```

### Weekly Tasks
1. **Review threat detection accuracy**
2. **Check email notification delivery**
3. **Monitor ML model performance**

### Monthly Tasks
1. **Consider retraining models with new data**
2. **Review and tune threat thresholds**
3. **Update ML dependencies if needed**

## Troubleshooting

### Common Issues

1. **ImportError: No module named 'sklearn'**
   ```bash
   pip install scikit-learn pandas numpy joblib
   ```

2. **ML models not found**
   ```bash
   python manage.py train_ml_models --dataset-path kdd_test.csv
   ```

3. **Email notifications not working**
   - Check SMTP settings in settings.py
   - Verify email credentials
   - Check firewall/network settings

4. **Low ML performance**
   - Retrain models with more recent data
   - Adjust confidence thresholds
   - Review feature engineering

### Debugging Commands

1. **Test ML engine directly:**
   ```bash
   python manage.py shell
   ```
   ```python
   from snort_analyzer.ml.ml_engine import get_ml_model_status
   print(get_ml_model_status())
   ```

2. **Check recent alerts:**
   ```python
   from snort_analyzer.models import SnortAlert
   recent = SnortAlert.objects.filter(ml_processed=True)[:5]
   for alert in recent:
       print(f"Alert {alert.id}: {alert.threat_level} - {alert.threat_probability}")
   ```

## Production Deployment

### Performance Considerations
1. **Batch Processing**: Use appropriate batch sizes (50-200 alerts)
2. **Background Tasks**: Consider using Celery for async processing
3. **Database Indexing**: Ensure ML-related fields are indexed
4. **Model Loading**: Models are cached in memory for performance

### Security Considerations
1. **Email Security**: Use app-specific passwords for Gmail
2. **Model Protection**: Secure ML models directory
3. **Log Security**: Protect ML processing logs
4. **Access Control**: Restrict admin access to ML features

## API Integration (Optional)

If you want to expose ML predictions via REST API, add to your views:

```python
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .ml.ml_engine import predict_snort_alert_threat

@api_view(['POST'])
def predict_threat(request):
    alert_id = request.data.get('alert_id')
    alert = SnortAlert.objects.get(id=alert_id)
    prediction = predict_snort_alert_threat(alert)
    return Response(prediction)
```

## Advanced Configuration

### Custom Feature Engineering
To modify feature extraction, edit:
`snort_analyzer/ml/ml_engine.py` - `_extract_features_from_snort_alert()`

### Custom Notification Logic
To customize notifications, edit:
`snort_analyzer/services/ml_alert_service.py` - `_handle_threat_notification()`

### Model Tuning
To adjust ML models, edit:
`ml_training/train_models.py` - `model_configs` dictionary

## Support and Updates

### Getting Help
1. Check the `ml_examples_output.md` file for example outputs
2. Review Django logs in `logs/ml_processing.log`
3. Use `--stats-only` flag to check system status

### Updating ML Components
1. **Update dependencies:** `pip install -U -r ml_requirements.txt`
2. **Retrain models:** `python manage.py train_ml_models --retrain`
3. **Test functionality:** `python manage.py process_ml_threats --stats-only`

This completes the ML integration setup. Your IDS now has intelligent threat detection capabilities powered by machine learning!
