# Model Sentinel IDS

## Overview
ModelSentinel is a **network-based Intrusion Detection System** built for my final year project using:
- **Backend:** Django REST API (SQLite database)
- **Frontend:** Next.js + Tailwind CSS
- **IDS Engine:** Snort
- **Machine Learning:** Random Forest (for threat classification)
- **Real-Time Monitoring:** Auto-parsing of Snort alerts
- **Report Generation:** Email reports based on timeframes

It captures and analyzes network packets, classifies threats, and displays them in a **real-time dashboard** with filtering and reporting features.

---

## System Architecture
1. **Data Collection:**  
   - Snort captures packets and logs suspicious activity.
   - Logs are saved in `alerts.csv` (shared folder).

2. **Backend Processing (Django):**  
   - Parses CSV logs continuously.
   - Saves alerts to SQLite database.
   - Runs ML classification to assign threat levels and attack types.
   - Provides REST API endpoints for frontend.

3. **Frontend Dashboard (Next.js):**  
   - Displays real-time alerts with filtering options.
   - Uses charts and tables for visualization.
   - Supports alert notifications.

4. **Reporting:**  
   - User selects a timeframe.
   - Backend generates a PDF/CSV report and sends it via email.

---

## Features
- Real-time packet capture via Snort
- ML-based threat classification (High / Medium / Low severity)
- Attack type identification (XSS, DDoS, SQL Injection, etc.)
- Time-based filtering (1h, 24h, 7d, 30d, All)
- Dashboard with charts and tables
- Automatic CSV log parsing
- Email-based reporting
- Custom Snort rules for common attacks + ICMP ping detection

---






