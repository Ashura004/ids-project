from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.core.paginator import Paginator
from django.db.models import Q
from .models import SnortAlert
import json
from datetime import datetime, timedelta
from django.utils import timezone
import io
import os
from django.core.mail import EmailMessage
from django.conf import settings
from django.template.loader import render_to_string
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart

def dashboard_view(request):
    """Main dashboard view - serves the HTML page"""
    return render(request, 'dashboard.html')

@csrf_exempt
@require_http_methods(["GET"])
def dashboard_api(request):
    """API endpoint for dashboard data"""
    try:
        print("Dashboard API called")
        
        # Get time range parameter
        time_range = request.GET.get('time_range', '24h')
        print(f"Time range: {time_range}")
        
        # Calculate date filter based on time range
        now = timezone.now()
        if time_range == '1h':
            start_time = now - timedelta(hours=1)
        elif time_range == '24h':
            start_time = now - timedelta(days=1)
        elif time_range == '7d':
            start_time = now - timedelta(days=7)
        elif time_range == '30d':
            start_time = now - timedelta(days=30)
        else:  # 'all' or any other value
            start_time = None
        
        # Filter alerts by time range
        if start_time:
            alerts_queryset = SnortAlert.objects.filter(timestamp__gte=start_time)
            latest_alerts = alerts_queryset.order_by('-timestamp')[:20]
        else:
            alerts_queryset = SnortAlert.objects.all()
            latest_alerts = alerts_queryset.order_by('-timestamp')[:20]
        
        alerts_data = []
        for alert in latest_alerts:
            alerts_data.append({
                'id': alert.id,
                'timestamp': alert.timestamp.strftime('%Y-%m-%d %H:%M:%S') if alert.timestamp else 'Unknown',
                'source_ip': alert.source_ip or 'Unknown',
                'destination_ip': alert.destination_ip or 'Unknown',
                'signature': alert.signature or 'Unknown',
                'severity': alert.severity,
                'severity_text': get_severity_display(alert.severity),
                'protocol': alert.protocol.upper() if alert.protocol else 'UNKNOWN',
                'is_anomalous': bool(alert.is_anomalous),
                'anomaly_score': round(float(alert.anomaly_score), 3) if alert.anomaly_score else 0.000,
                'status': 'ANOMALY' if alert.is_anomalous else 'NORMAL'
            })

        
        if start_time:
            total_alerts = SnortAlert.objects.filter(timestamp__gte=start_time).count()
            total_anomalies = SnortAlert.objects.filter(timestamp__gte=start_time, is_anomalous=True).count()
            high_severity_alerts = SnortAlert.objects.filter(timestamp__gte=start_time, severity=1).count()
        else:
            total_alerts = SnortAlert.objects.count()
            total_anomalies = SnortAlert.objects.filter(is_anomalous=True).count()
            high_severity_alerts = SnortAlert.objects.filter(severity=1).count()

        print(f"Returning {len(alerts_data)} recent alerts, {total_alerts} total for {time_range}")

        return JsonResponse({
            'status': 'success',
            'total_alerts': total_alerts,
            'recent_alerts': alerts_data,
            'summary': {
                'total_alerts': total_alerts,
                'total_anomalies': total_anomalies,
                'high_severity_alerts': high_severity_alerts,
                'anomaly_rate': round((total_anomalies / total_alerts * 100), 1) if total_alerts > 0 else 0
            }
        })

    except Exception as e:
        import traceback
        print(f"Dashboard API Error: {e}")
        print(traceback.format_exc())
        return JsonResponse({
            'status': 'error',
            'error': str(e)
        }, status=500)

@csrf_exempt
@require_http_methods(["GET"])
def alerts_api(request):
    """API endpoint for paginated and filtered alerts"""
    try:
        
        page = int(request.GET.get('page', 1))
        page_size = 20
        severity_filter = request.GET.get('severity', '')
        protocol_filter = request.GET.get('protocol', '')
        is_anomalous_filter = request.GET.get('is_anomalous', '')
        
        print(f"Alerts API called with: page={page}, severity={severity_filter}, protocol={protocol_filter}, anomaly={is_anomalous_filter}")
        
        
        alerts_queryset = SnortAlert.objects.all().order_by('-timestamp')
        
        
        if severity_filter:
            alerts_queryset = alerts_queryset.filter(severity=int(severity_filter))
        
        if protocol_filter:
            alerts_queryset = alerts_queryset.filter(protocol__icontains=protocol_filter)
        
        if is_anomalous_filter:
            is_anomalous_bool = is_anomalous_filter.lower() == 'true'
            alerts_queryset = alerts_queryset.filter(is_anomalous=is_anomalous_bool)
        
        
        paginator = Paginator(alerts_queryset, page_size)
        total_pages = paginator.num_pages
        page_obj = paginator.get_page(page)
        
        
        alerts_data = []
        for alert in page_obj:
            alerts_data.append({
                'id': alert.id,
                'timestamp': alert.timestamp.isoformat() if alert.timestamp else None,
                'source_ip': alert.source_ip,
                'source_port': alert.source_port,
                'destination_ip': alert.destination_ip,
                'destination_port': alert.destination_port,
                'signature': alert.signature,
                'protocol': alert.protocol.upper(),
                'severity': alert.severity,
                'severity_display': get_severity_display(alert.severity),
                'is_anomalous': alert.is_anomalous,
                'anomaly_score': float(alert.anomaly_score) if alert.anomaly_score else 0.0,
                'signature_id': alert.signature_id,
            })
        
        print(f"Returning {len(alerts_data)} alerts out of {paginator.count} total")
        
        return JsonResponse({
            'status': 'success',
            'results': alerts_data,
            'count': paginator.count,
            'total_pages': total_pages,
            'current_page': page,
            'has_next': page_obj.has_next(),
            'has_previous': page_obj.has_previous(),
            'next': page + 1 if page_obj.has_next() else None,
            'previous': page - 1 if page_obj.has_previous() else None
        })

    except Exception as e:
        import traceback
        print(f"Alerts API Error: {e}")
        print(traceback.format_exc())
        return JsonResponse({
            'status': 'error',
            'error': str(e)
        }, status=500)

@csrf_exempt
@require_http_methods(["GET"])
def live_alerts(request):
    """API endpoint for live alerts (WebSocket alternative)"""
    try:
        
        latest_alerts = SnortAlert.objects.order_by('-timestamp')[:10]
        alerts_data = []
        
        for alert in latest_alerts:
            alerts_data.append({
                'id': alert.id,
                'timestamp': alert.timestamp.isoformat() if alert.timestamp else None,
                'source_ip': alert.source_ip,
                'destination_ip': alert.destination_ip,
                'signature': alert.signature,
                'severity': alert.severity,
                'is_anomalous': alert.is_anomalous,
                'anomaly_score': float(alert.anomaly_score) if alert.anomaly_score else 0.0,
            })
        
        return JsonResponse({
            'status': 'success',
            'alerts': alerts_data
        })
    
    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'error': str(e)
        }, status=500)

@csrf_exempt
@require_http_methods(["GET"])
def notifications_api(request):
    """API endpoint for notifications (placeholder)"""
    try:
        # For now, return empty notifications
        # You can implement a Notification model later
        return JsonResponse({
            'status': 'success',
            'notifications': []
        })
    
    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'error': str(e)
        }, status=500)

@csrf_exempt
@require_http_methods(["POST"])
def mark_notification_read(request, notification_id):
    """API endpoint to mark notification as read (placeholder)"""
    try:
        # Placeholder - implement when you have Notification model
        return JsonResponse({
            'status': 'success',
            'message': 'Notification marked as read'
        })
    
    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'error': str(e)
        }, status=500)

@csrf_exempt
@require_http_methods(["GET"])
def alert_detail_api(request, alert_id):
    """API endpoint for individual alert details"""
    try:
        print(f"Alert detail API called for ID: {alert_id}")
        
        # Get the specific alert
        try:
            alert = SnortAlert.objects.get(id=alert_id)
        except SnortAlert.DoesNotExist:
            return JsonResponse({
                'status': 'error',
                'error': 'Alert not found'
            }, status=404)
        
        # Serialize detailed alert data
        alert_data = {
            'id': alert.id,
            'timestamp': alert.timestamp.isoformat() if alert.timestamp else None,
            'source_ip': alert.source_ip,
            'source_port': alert.source_port,
            'destination_ip': alert.destination_ip,
            'destination_port': alert.destination_port,
            'signature': alert.signature,
            'protocol': alert.protocol.upper() if alert.protocol else 'UNKNOWN',
            'severity': alert.severity,
            'severity_display': get_severity_display(alert.severity),
            'is_anomalous': alert.is_anomalous,
            'anomaly_score': float(alert.anomaly_score) if alert.anomaly_score else 0.0,
            'signature_id': alert.signature_id,
            'raw_log': alert.raw_log,
            
        }
        
        print(f"Returning alert detail for ID: {alert_id}")
        
        return JsonResponse({
            'status': 'success',
            'alert': alert_data
        })

    except Exception as e:
        import traceback
        print(f"Alert Detail API Error: {e}")
        print(traceback.format_exc())
        return JsonResponse({
            'status': 'error',
            'error': str(e)
        }, status=500)

def get_severity_display(severity):
    """Convert severity number to display text"""
    severity_map = {1: 'High', 2: 'Medium', 3: 'Low'}
    return severity_map.get(severity, 'Unknown')

@csrf_exempt
@require_http_methods(["POST", "OPTIONS"])  
def generate_report(request):
    """Generate and send security report via email"""
    
    
    if request.method == 'OPTIONS':
        response = JsonResponse({'status': 'ok'})
        response['Access-Control-Allow-Origin'] = 'http://localhost:3000'
        response['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
        response['Access-Control-Allow-Headers'] = 'Content-Type'
        return response
    
    try:
        print("Generate report endpoint called")
        print(f"Request method: {request.method}")
        print(f"Request path: {request.path}")
        
        data = json.loads(request.body)
        email = data.get('email')
        report_type = data.get('report_type', 'weekly')
        
        print(f"Request data: email={email}, report_type={report_type}")
        
        if not email:
            return JsonResponse({
                'status': 'error',
                'error': 'Email address is required'
            }, status=400)
        
        # Generate report data
        print("Generating report data...")
        report_data = generate_report_data(report_type)
        
        if not report_data:
            return JsonResponse({
                'status': 'error',
                'error': 'Failed to generate report data'
            }, status=500)
        
        print(f"Report data generated: {report_data.get('total_alerts', 0)} total alerts")
        
        # Generate PDF
        print("Generating PDF...")
        pdf_buffer = generate_enhanced_pdf_report(report_data, report_type)
        
        if not pdf_buffer:
            return JsonResponse({
                'status': 'error',
                'error': 'Failed to generate PDF report'
            }, status=500)
        
        print(f"PDF generated successfully, size: {len(pdf_buffer.getvalue())} bytes")
        
        # Send email with PDF attachment
        print(f"Sending email to {email}...")
        success = send_report_email(email, pdf_buffer, report_data, report_type)
        
        if success:
            print(f"Email sent successfully to {email}")
            return JsonResponse({
                'status': 'success',
                'message': f'Report sent successfully to {email}! Check your inbox for the detailed PDF report.'
            })
        else:
            print(f"Failed to send email to {email}")
            return JsonResponse({
                'status': 'error',
                'error': 'Failed to send email. Please check email configuration.'
            }, status=500)
        
    except json.JSONDecodeError:
        print("Invalid JSON data received")
        return JsonResponse({
            'status': 'error',
            'error': 'Invalid JSON data'
        }, status=400)
        
    except Exception as e:
        import traceback
        print(f"Generate report error: {e}")
        print(traceback.format_exc())
        return JsonResponse({
            'status': 'error',
            'error': str(e)
        }, status=500)

def generate_report_data(report_type):
    """Generate comprehensive report data"""
    try:
        # Calculate date range based on report type
        end_date = datetime.now()
        if report_type == 'daily':
            start_date = end_date - timedelta(days=1)
            period_name = "Daily"
        elif report_type == 'weekly':
            start_date = end_date - timedelta(days=7)
            period_name = "Weekly"
        elif report_type == 'monthly':
            start_date = end_date - timedelta(days=30)
            period_name = "Monthly"
        else:
            start_date = end_date - timedelta(days=7)
            period_name = "Weekly"
        
        # Filter alerts by date range
        alerts = SnortAlert.objects.filter(
            timestamp__gte=start_date,
            timestamp__lte=end_date
        )
        
        # Calculate statistics
        total_alerts = alerts.count()
        anomalies = alerts.filter(is_anomalous=True).count()
        high_severity = alerts.filter(severity=1).count()
        medium_severity = alerts.filter(severity=2).count()
        low_severity = alerts.filter(severity=3).count()
        
        # Protocol distribution
        protocol_stats = {}
        for alert in alerts:
            protocol = alert.protocol or 'Unknown'
            protocol_stats[protocol] = protocol_stats.get(protocol, 0) + 1
        
        # Top source IPs
        source_ip_stats = {}
        for alert in alerts:
            ip = alert.source_ip
            if ip:
                source_ip_stats[ip] = source_ip_stats.get(ip, 0) + 1
        
        top_source_ips = sorted(source_ip_stats.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Top signatures
        signature_stats = {}
        for alert in alerts:
            sig = alert.signature or 'Unknown'
            signature_stats[sig] = signature_stats.get(sig, 0) + 1
        
        top_signatures = sorted(signature_stats.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Recent critical alerts
        critical_alerts = alerts.filter(severity=1, is_anomalous=True).order_by('-timestamp')[:10]
        
        return {
            'period': period_name,
            'start_date': start_date.strftime('%Y-%m-%d %H:%M:%S'),
            'end_date': end_date.strftime('%Y-%m-%d %H:%M:%S'),
            'total_alerts': total_alerts,
            'anomalies': anomalies,
            'anomaly_rate': round((anomalies / total_alerts * 100), 2) if total_alerts > 0 else 0,
            'high_severity': high_severity,
            'medium_severity': medium_severity,
            'low_severity': low_severity,
            'protocol_stats': protocol_stats,
            'top_source_ips': top_source_ips,
            'top_signatures': top_signatures,
            'critical_alerts': [
                {
                    'timestamp': alert.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                    'source_ip': alert.source_ip,
                    'destination_ip': alert.destination_ip,
                    'signature': alert.signature,
                    'anomaly_score': float(alert.anomaly_score) if alert.anomaly_score else 0
                }
                for alert in critical_alerts
            ]
        }
        
    except Exception as e:
        print(f"Error generating report data: {e}")
        return {}

def generate_enhanced_pdf_report(data, report_type):
    """Generate enhanced PDF report with charts and styling"""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=18)
    
    # Get styles
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30,
        alignment=1,  
        textColor=colors.HexColor('#1f2937')
    )
    
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=16,
        spaceAfter=12,
        textColor=colors.HexColor('#374151')
    )
    
    normal_style = ParagraphStyle(
        'CustomNormal',
        parent=styles['Normal'],
        fontSize=11,
        spaceAfter=6
    )
    
    
    story = []
    
    
    story.append(Paragraph(f"Network Security Report - {data.get('period', 'Weekly')}", title_style))
    story.append(Spacer(1, 12))
    
    
    story.append(Paragraph(f"<b>Report Period:</b> {data.get('start_date')} to {data.get('end_date')}", normal_style))
    story.append(Paragraph(f"<b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
    story.append(Spacer(1, 20))
    
    # Executive Summary
    story.append(Paragraph("Executive Summary", heading_style))
    
    summary_data = [
        ['Metric', 'Value', 'Status'],
        ['Total Alerts', f"{data.get('total_alerts', 0):,}", ],
        ['Anomalies Detected', f"{data.get('anomalies', 0):,}", '🚨' if data.get('anomalies', 0) > 0 else '✅'],
        ['Anomaly Rate', f"{data.get('anomaly_rate', 0)}%", '⚠️' if data.get('anomaly_rate', 0) > 10 else '✅'],
        ['High Severity', f"{data.get('high_severity', 0):,}", '🔴' if data.get('high_severity', 0) > 0 else '✅'],
        ['Medium Severity', f"{data.get('medium_severity', 0):,}", '🟡'],
        ['Low Severity', f"{data.get('low_severity', 0):,}", '🟢'],
    ]
    
    summary_table = Table(summary_data, colWidths=[2*inch, 1.5*inch, 1*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3b82f6')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    
    story.append(summary_table)
    story.append(Spacer(1, 20))
    
    # Protocol Distribution
    if data.get('protocol_stats'):
        story.append(Paragraph("Protocol Distribution", heading_style))
        
        protocol_data = [['Protocol', 'Count', 'Percentage']]
        total = sum(data['protocol_stats'].values())
        
        for protocol, count in sorted(data['protocol_stats'].items(), key=lambda x: x[1], reverse=True):
            percentage = round((count / total * 100), 1) if total > 0 else 0
            protocol_data.append([protocol, str(count), f"{percentage}%"])
        
        protocol_table = Table(protocol_data, colWidths=[1.5*inch, 1*inch, 1*inch])
        protocol_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#10b981')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(protocol_table)
        story.append(Spacer(1, 20))
    
    # Top Source IPs
    if data.get('top_source_ips'):
        story.append(Paragraph("Top Source IPs", heading_style))
        
        ip_data = [['Rank', 'Source IP', 'Alert Count', 'Risk Level']]
        
        for i, (ip, count) in enumerate(data['top_source_ips'], 1):
            risk = 'High' if count > 50 else 'Medium' if count > 10 else 'Low'
            ip_data.append([str(i), ip, str(count), risk])
        
        ip_table = Table(ip_data, colWidths=[0.5*inch, 2*inch, 1*inch, 1*inch])
        ip_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#ef4444')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(ip_table)
        story.append(Spacer(1, 20))
    
    # Critical Alerts
    if data.get('critical_alerts'):
        story.append(Paragraph("Recent Critical Alerts", heading_style))
        
        critical_data = [['Timestamp', 'Source IP', 'Destination IP', 'Signature', 'Score']]
        
        for alert in data['critical_alerts'][:10]:  # Limit to 10 most recent
            signature = alert['signature'][:40] + '...' if len(alert['signature']) > 40 else alert['signature']
            critical_data.append([
                alert['timestamp'],
                alert['source_ip'],
                alert['destination_ip'],
                signature,
                f"{alert['anomaly_score']:.3f}"
            ])
        
        critical_table = Table(critical_data, colWidths=[1.2*inch, 1.2*inch, 1.2*inch, 2*inch, 0.7*inch])
        critical_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#dc2626')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(critical_table)
        story.append(Spacer(1, 20))
    
    # Recommendations
    story.append(Paragraph("Security Recommendations", heading_style))
    
    recommendations = []
    
    if data.get('anomaly_rate', 0) > 20:
        recommendations.append("• High anomaly rate detected - Consider reviewing ML model thresholds")
    
    if data.get('high_severity', 0) > 100:
        recommendations.append("• Significant high-severity alerts - Implement additional security controls")
    
    for ip, count in data.get('top_source_ips', [])[:3]:
        if count > 50:
            recommendations.append(f"• Source IP {ip} shows suspicious activity ({count} alerts) - Consider blocking")
    
    if not recommendations:
        recommendations = [
            "• Continue monitoring current security posture",
            "• Regular review of alert patterns recommended",
            "• Maintain current security policies"
        ]
    
    for rec in recommendations:
        story.append(Paragraph(rec, normal_style))
    
    story.append(Spacer(1, 20))
    
    # Footer
    story.append(Paragraph("---", normal_style))
    story.append(Paragraph("This report was automatically generated by the Network Security Monitoring System.", normal_style))
    story.append(Paragraph(f"For questions, contact your security team.", normal_style))
    
    # Build PDF
    doc.build(story)
    buffer.seek(0)
    return buffer

def send_report_email(email, pdf_buffer, data, report_type):
    """Send email with PDF attachment"""
    try:
        subject = f" {data.get('period', 'Weekly')} Security Report - {datetime.now().strftime('%Y-%m-%d')}"
        
        
        body = f"""
        Dear Security Team,

        Please find attached your {data.get('period', 'weekly').lower()} network security report.

        Key Highlights:
        • Total Alerts: {data.get('total_alerts', 0):,}
        • Anomalies Detected: {data.get('anomalies', 0):,}
        • Anomaly Rate: {data.get('anomaly_rate', 0)}%
        • High Severity Alerts: {data.get('high_severity', 0):,}

        {
        "Action Required: High anomaly rate detected!" if data.get('anomaly_rate', 0) > 20 
        else "Security status appears normal."
        }

        Report Period: {data.get('start_date')} to {data.get('end_date')}

        Please review the attached detailed report and take appropriate action for any critical alerts.

        Best regards,
        Network Security Monitoring System
        """
        
        # Create email
        email_msg = EmailMessage(
            subject=subject,
            body=body,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[email],
        )
        
        # Attach PDF
        filename = f"security_report_{report_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        email_msg.attach(filename, pdf_buffer.getvalue(), 'application/pdf')
        
        # Send email
        result = email_msg.send()
        
        print(f"Email sent successfully to {email}: {result}")
        return True
        
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False
