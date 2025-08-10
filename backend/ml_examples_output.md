# Network Intrusion Detection System - ML Integration Examples

## Example 1: Normal Network Traffic Prediction

### Input Alert:
```json
{
    "id": 1001,
    "timestamp": "2024-01-15T10:30:45Z",
    "source_ip": "192.168.1.100",
    "source_port": 54321,
    "destination_ip": "172.16.0.10",
    "destination_port": 80,
    "protocol": "TCP",
    "signature": "HTTP GET Request to Web Server",
    "signature_id": 2001,
    "severity": 3,
    "raw_log": "[01:40001:2001] HTTP GET Request to Web Server [Classification: Web Traffic] [Priority: 3] 01/15-10:30:45.123456 192.168.1.100:54321 -> 172.16.0.10:80"
}
```

### ML Prediction Output:
```json
{
    "is_threat": false,
    "threat_probability": 0.15,
    "confidence": 0.92,
    "threat_level": "LOW",
    "model_prediction": 0,
    "algorithm_used": "RandomForestClassifier",
    "timestamp": "2024-01-15T10:30:46.123Z"
}
```

### Updated Alert Record:
```json
{
    "id": 1001,
    "ml_processed": true,
    "threat_probability": 0.15,
    "threat_level": "LOW",
    "ml_prediction": {
        "is_threat": false,
        "confidence": 0.92,
        "algorithm_used": "RandomForestClassifier",
        "prediction_timestamp": "2024-01-15T10:30:46.123Z",
        "model_prediction": 0
    }
}
```

---

## Example 2: Attack Traffic Detection (Port Scan)

### Input Alert:
```json
{
    "id": 1002,
    "timestamp": "2024-01-15T14:22:17Z",
    "source_ip": "203.0.113.25",
    "source_port": 0,
    "destination_ip": "192.168.1.50",
    "destination_port": 22,
    "protocol": "TCP",
    "signature": "SCAN nmap TCP SYN scan",
    "signature_id": 1001,
    "severity": 1,
    "raw_log": "[01:40001:1001] SCAN nmap TCP SYN scan [Classification: Attempted Reconnaissance] [Priority: 1] 01/15-14:22:17.456789 203.0.113.25 -> 192.168.1.50:22"
}
```

### ML Prediction Output:
```json
{
    "is_threat": true,
    "threat_probability": 0.94,
    "confidence": 0.89,
    "threat_level": "HIGH",
    "model_prediction": 1,
    "algorithm_used": "RandomForestClassifier",
    "timestamp": "2024-01-15T14:22:18.456Z"
}
```

### Updated Alert Record:
```json
{
    "id": 1002,
    "ml_processed": true,
    "threat_probability": 0.94,
    "threat_level": "HIGH",
    "is_anomalous": true,  // Updated for backward compatibility
    "anomaly_score": 0.94,
    "ml_prediction": {
        "is_threat": true,
        "confidence": 0.89,
        "algorithm_used": "RandomForestClassifier",
        "prediction_timestamp": "2024-01-15T14:22:18.456Z",
        "model_prediction": 1
    }
}
```

### Generated Notification:
```json
{
    "id": 501,
    "user_id": 1,
    "attack_type": "ML Threat Detected: SCAN nmap TCP SYN scan...",
    "description": "Machine Learning has detected a HIGH threat with 89.0% confidence.\nSource: 203.0.113.25:0\nDestination: 192.168.1.50:22\nProtocol: TCP\nSignature: SCAN nmap TCP SYN scan",
    "severity": "high",
    "is_read": false,
    "timestamp": "2024-01-15T14:22:18.456Z"
}
```

---

## Example 3: Medium Threat Detection (Suspicious Activity)

### Input Alert:
```json
{
    "id": 1003,
    "timestamp": "2024-01-15T16:45:12Z",
    "source_ip": "10.0.0.45",
    "source_port": 3389,
    "destination_ip": "192.168.1.200",
    "destination_port": 3389,
    "protocol": "TCP",
    "signature": "RDP Multiple Failed Login Attempts",
    "signature_id": 3001,
    "severity": 2,
    "raw_log": "[01:40001:3001] RDP Multiple Failed Login Attempts [Classification: Authentication Failure] [Priority: 2] 01/15-16:45:12.789123 10.0.0.45:3389 -> 192.168.1.200:3389"
}
```

### ML Prediction Output:
```json
{
    "is_threat": true,
    "threat_probability": 0.73,
    "confidence": 0.81,
    "threat_level": "MEDIUM",
    "model_prediction": 1,
    "algorithm_used": "RandomForestClassifier",
    "timestamp": "2024-01-15T16:45:13.123Z"
}
```

---

## Example 4: Batch Processing Results

### Command Execution:
```bash
python manage.py process_ml_threats --batch-size 50 --max-batches 5
```

### Console Output:
```
🤖 ML Threat Classification Command
==================================================

📊 CURRENT ML STATISTICS:
   Total alerts: 2,547
   Processed: 1,923
   Unprocessed: 624
   Processing rate: 75.5%
   Threats detected: 312
   - High severity: 45
   - Medium severity: 89
   Threat detection rate: 16.2%
   Model: ✅ RandomForestClassifier

📊 Found 624 alerts to process

🔄 Processing batch 1 (up to 50 alerts)...
✅ Batch 1: 50/50 processed, 8 threats detected
📈 Total: 50 processed, 8 threats, 25.0 alerts/sec

🔄 Processing batch 2 (up to 50 alerts)...
✅ Batch 2: 50/50 processed, 6 threats detected
📈 Total: 100 processed, 14 threats, 28.5 alerts/sec

[... continues for all batches ...]

==================================================
🏁 PROCESSING COMPLETE
📊 Total processed: 250 alerts
🚨 Threats detected: 34 alerts
⏱️ Total time: 8.7 seconds
🏃 Average rate: 28.7 alerts/second
⚠️ Threat detection rate: 13.6%

📈 UPDATED STATISTICS:
   Total alerts: 2,547
   Processed: 2,173
   Unprocessed: 374
   Processing rate: 85.3%
   Threats detected: 346
   - High severity: 53
   - Medium severity: 101
   Threat detection rate: 15.9%
   Model: ✅ RandomForestClassifier
```

---

## Example 5: Model Training Results

### Command Execution:
```bash
python manage.py train_ml_models --dataset-path kdd_test.csv --retrain
```

### Training Output Summary:
```
🤖 ML Model Training Command
==================================================

1. Preprocessing dataset...
Dataset loaded: 311,029 samples, 42 features
After cleaning: 311,029 samples
Binary label distribution - Normal: 97,277, Attack: 213,752
Preprocessing completed successfully!
Training set: (248,823, 41)
Test set: (62,206, 41)

2. Training 3 models...

==================================================
Training Random Forest Classifier (random_forest)
==================================================

📊 Results for random_forest:
   Accuracy: 0.9941
   Precision: 0.9941
   Recall: 0.9941
   F1-Score: 0.9941
   ROC AUC: 0.9978
   CV Accuracy: 0.9938 (+/- 0.0012)
   Training Time: 28.45s
   Prediction Time: 0.3456s

   Confusion Matrix:
   [[19234    52]]  <- Normal
   [[  313 42607]]  <- Attack
     Normal Attack

==================================================
Training Logistic Regression (logistic_regression)
==================================================

📊 Results for logistic_regression:
   Accuracy: 0.9156
   Precision: 0.9201
   Recall: 0.9156
   F1-Score: 0.9145
   ROC AUC: 0.9623
   CV Accuracy: 0.9142 (+/- 0.0034)
   Training Time: 12.78s
   Prediction Time: 0.0123s

==================================================
MODEL COMPARISON SUMMARY
==================================================
Model                Accuracy   F1-Score   ROC AUC    Time(s)   
------------------------------------------------------------
random_forest        0.9941     0.9941     0.9978     28.45     
logistic_regression  0.9156     0.9145     0.9623     12.78     
gradient_boosting    0.9887     0.9887     0.9956     67.23     

🏆 Best model (random_forest) saved as default classifier
📁 All models and preprocessor saved to: /path/to/ml_models

🎉 TRAINING COMPLETE!
```

---

## Example 6: Real-time Alert Processing Integration

### Snort Log Parsing with ML:
```bash
python manage.py parse_snort_logs --file ../snort_logs/alerts.csv
```

### Console Output:
```
Parsing CSV file: ../snort_logs/alerts.csv
Imported alert: HTTP GET Request to Web Server from 192.168.1.100 to 172.16.0.10
✅ Created ML threat notifications for 2 users
Imported alert: SCAN nmap TCP SYN scan from 203.0.113.25 to 192.168.1.50
Successfully imported 125 alerts
```

### Email Notification Example (High Threat):
```
Subject: 🚨 HIGH THREAT DETECTED - SCAN nmap TCP SYN scan...

Machine Learning Analysis
Algorithm: RandomForestClassifier
Threat Probability: 94.2%
Confidence Level: 89.0%

Alert Details
Source IP:Port: 203.0.113.25:0
Destination IP:Port: 192.168.1.50:22
Protocol: TCP
Signature: SCAN nmap TCP SYN scan
Severity: High

Immediate Action Required
This alert has been classified as a HIGH threat by our ML system with 89.0% confidence.

Recommended Actions:
🔍 Investigate the source IP immediately
🛡️ Consider blocking the source if confirmed malicious
📊 Review related network traffic patterns
📋 Document findings for security analysis
```

---

## Model Performance Metrics

### Classification Report:
```
                 precision    recall  f1-score   support
    Normal           0.997     0.973     0.985     19286
    Attack           0.993     0.999     0.996     42920
    
    accuracy                           0.994     62206
   macro avg         0.995     0.986     0.990     62206
weighted avg         0.994     0.994     0.994     62206
```

### Feature Importance (Top 10):
```
1. dst_host_srv_count          0.089
2. count                       0.087
3. srv_count                   0.074
4. dst_host_count              0.062
5. same_srv_rate               0.051
6. dst_host_same_srv_rate      0.048
7. serror_rate                 0.041
8. srv_serror_rate             0.039
9. dst_host_srv_diff_host_rate 0.037
10. hot                        0.034
```

This comprehensive ML integration provides robust threat detection capabilities while maintaining high performance and providing clear, actionable results for security analysts.
