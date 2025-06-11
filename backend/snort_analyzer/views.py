from django.shortcuts import render
from rest_framework import viewsets, filters, status
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from django.db.models import Count, F, Q
from django.utils import timezone
from datetime import timedelta, datetime
from django_filters.rest_framework import DjangoFilterBackend
from django.http import JsonResponse, FileResponse, HttpResponse
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken

from snort_analyzer.notification_serializers import AttackNotificationSerializer
from ids_project import settings
from .auth_serializers import UserSerializer, RegisterSerializer, LoginSerializer
from django.contrib.auth.models import User

from .models import SnortAlert, IPStats, DailyStats, AttackNotification
from .serializers import (
    SnortAlertSerializer, IPStatsSerializer, DailyStatsSerializer,
    AlertCountByProtocolSerializer, TopSourceIPsSerializer,
    TopDestinationIPsSerializer, AlertTrendSerializer
)
from django.template.loader import render_to_string
from django.core.mail import EmailMessage
from io import BytesIO
from reportlab.lib.pagesizes import letter, landscape
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.linecharts import HorizontalLineChart
from reportlab.lib.units import inch
import logging

logger = logging.getLogger(__name__)

class SnortAlertViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = SnortAlert.objects.all()
    serializer_class = SnortAlertSerializer
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['severity', 'protocol', 'is_anomalous']
    ordering_fields = ['timestamp', 'source_ip', 'destination_ip', 'anomaly_score']
    ordering = ['-timestamp']
    
    @action(detail=False, methods=['get'])
    def dashboard_data(self, request):
        """
        Get aggregated data for the dashboard
        """
        
        days = int(request.query_params.get('days', 7))
        start_date = timezone.now() - timedelta(days=days)
        
        
        queryset = SnortAlert.objects.filter(timestamp__gte=start_date)
        
        
        severity_counts = queryset.values('severity').annotate(
            count=Count('id')
        ).order_by('severity')
        
        
        protocol_counts = queryset.values('protocol').annotate(
            count=Count('id')
        ).order_by('-count')[:10]
        
        
        top_source_ips = IPStats.objects.filter(
            is_source=True, 
            last_seen__gte=start_date
        ).order_by('-alert_count')[:10]
        
        
        top_dest_ips = IPStats.objects.filter(
            is_source=False,
            last_seen__gte=start_date
        ).order_by('-alert_count')[:10]
        
        
        trends = DailyStats.objects.filter(
            date__gte=start_date.date()
        ).values('date', 'total_alerts', 'anomaly_count')
        
        
        anomaly_counts = {
            'normal': queryset.filter(is_anomalous=False).count(),
            'anomalous': queryset.filter(is_anomalous=True).count()
        }
        
        
        return Response({
            'severity_counts': severity_counts,
            'protocol_counts': protocol_counts,
            'top_source_ips': IPStatsSerializer(top_source_ips, many=True).data,
            'top_destination_ips': IPStatsSerializer(top_dest_ips, many=True).data,
            'trends': trends,
            'anomaly_distribution': anomaly_counts,
            'total_alerts': queryset.count()
        })

@api_view(['GET'])
def dashboard_data(request):
    """API endpoint for dashboard summary data"""
    
    last_24h = datetime.now() - timedelta(days=1)
    
    
    total_alerts = SnortAlert.objects.count()
    recent_alerts = SnortAlert.objects.filter(timestamp__gte=last_24h).count()
    
   
    severity_counts = list(
        SnortAlert.objects.values('severity')
                          .annotate(count=Count('id'))
                          .order_by('severity')
    )
    
    
    protocol_counts = list(
        SnortAlert.objects.values('protocol')
                          .annotate(count=Count('id'))
                          .order_by('-count')[:5]
    )
    
    
    anomalies = SnortAlert.objects.filter(is_anomalous=True).count()
    
    return Response({
        'total_alerts': total_alerts,
        'recent_alerts': recent_alerts,
        'severity_distribution': severity_counts,
        'protocol_distribution': protocol_counts,
        'anomalies': anomalies,
    })

def dashboard_api(request):
    """API endpoint for dashboard data"""
    time_range = request.GET.get('time_range', '24h')
    

    if time_range == 'all':
        alerts = SnortAlert.objects.all()
    else:
        now = timezone.now()
        if time_range == '24h':
            start_time = now - timedelta(hours=24)
        elif time_range == '7d':
            start_time = now - timedelta(days=7)
        elif time_range == '30d':
            start_time = now - timedelta(days=30)
        else:
            start_time = now - timedelta(days=365)
    
        alerts = SnortAlert.objects.filter(timestamp__gte=start_time)
    
    
    high_severity = alerts.filter(severity=1).count()
    medium_severity = alerts.filter(severity=2).count()
    low_severity = alerts.filter(severity__gt=2).count()
    
    
    severity_distribution = [
        {'severity': 1, 'count': high_severity, 'name': 'High'},
        {'severity': 2, 'count': medium_severity, 'name': 'Medium'},
        {'severity': 3, 'count': low_severity, 'name': 'Low'}
    ]
    
    
    anomalies = alerts.filter(is_anomalous=True).count()
    
    
    protocol_distribution = list(
        alerts.values('protocol')
        .annotate(count=Count('protocol'))
        .order_by('-count')[:5]  
    )
    
    
    protocol_data = []
    for item in protocol_distribution:
        if item['protocol']:  
            protocol_data.append({
                'protocol': item['protocol'],
                'count': item['count']
            })
    
    
    top_source_ips = list(IPStats.objects.filter(is_source=True)
        .order_by('-alert_count')[:5]
        .values('ip_address', 'alert_count'))

    
    top_destination_ips = list(IPStats.objects.filter(is_source=False)
        .order_by('-alert_count')[:5]
        .values('ip_address', 'alert_count'))
    

    return JsonResponse({
        'total_alerts': alerts.count(),
        'anomalies': anomalies,
        'severity_distribution': severity_distribution,
        'protocol_distribution': protocol_data,
        'top_source_ips': top_source_ips,
        'top_destination_ips': top_destination_ips,
    })

@api_view(['POST'])
def register_user(request):
    serializer = RegisterSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        refresh = RefreshToken.for_user(user)
        return Response({
            'user': UserSerializer(user).data,
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
def login_user(request):
    serializer = LoginSerializer(data=request.data)
    if serializer.is_valid():
        username = serializer.validated_data['username']
        password = serializer.validated_data['password']
        
        user = authenticate(username=username, password=password)
        
        if user is not None:
            
            user.profile.login_count += 1
            if 'HTTP_X_FORWARDED_FOR' in request.META:
                user.profile.last_login_ip = request.META['HTTP_X_FORWARDED_FOR']
            else:
                user.profile.last_login_ip = request.META['REMOTE_ADDR']
            user.profile.save()
            
            refresh = RefreshToken.for_user(user)
            return Response({
                'user': UserSerializer(user).data,
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            })
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
def user_profile(request):
    return Response(UserSerializer(request.user).data)

@api_view(['POST'])
def logout_user(request):
    return Response({'detail': 'Successfully logged out.'})

@api_view(['GET'])
def get_attack_notifications(request):
    """Get user's attack notifications"""
    
   
    if request.user.is_authenticated:
        user = request.user
    else:
        
        user = User.objects.first()
        if not user:
           
            return Response([])
    
    
    notifications = AttackNotification.objects.filter(user=user).order_by('-timestamp')
    data = AttackNotificationSerializer(notifications, many=True).data
    return Response(data)

@api_view(['POST'])
def mark_notification_read(request, notification_id):
    """Mark a notification as read"""
    try:
        
        user = request.user if request.user.is_authenticated else User.objects.first()
        if not user:
            return Response({'status': 'error', 'message': 'No users available'}, status=404)
            
        notification = AttackNotification.objects.get(id=notification_id, user=user)
        notification.is_read = True
        notification.save()
        return Response({'status': 'success'})
    except AttackNotification.DoesNotExist:
        return Response({'status': 'error', 'message': 'Notification not found'}, status=404)

@api_view(['POST'])
def generate_attack_report(request, notification_id):
    """Generate a PDF report for an attack notification and email it"""
    try:
        notification = AttackNotification.objects.get(id=notification_id, user=request.user)
        
        
        pdf_file = generate_pdf_report(notification)
        
        
        send_attack_report_email(request.user.email, notification, pdf_file)
        
        return Response({'status': 'success', 'message': 'Report sent to your email'})
    except AttackNotification.DoesNotExist:
        return Response({'status': 'error', 'message': 'Notification not found'}, status=404)

def generate_pdf_report(notification):
    """Generate a PDF report for an attack notification using ReportLab"""
    buffer = BytesIO()
    
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    
    title_style = styles["Heading1"]
    title_style.alignment = 1  
    
    subtitle_style = styles["Heading2"]
    subtitle_style.alignment = 1
    
    header_style = styles["Heading3"]
    
    
    elements = []
    
    
    elements.append(Paragraph("ModelSentinel IDS", title_style))
    elements.append(Paragraph("Network Intrusion Detection System", subtitle_style))
    elements.append(Spacer(1, 0.3*inch))
    
    
    elements.append(Paragraph("Attack Detection Report", header_style))
    elements.append(Paragraph(f"Generated: {notification.timestamp.strftime('%B %d, %Y, %I:%M %p')}", styles["Normal"]))
    elements.append(Spacer(1, 0.2*inch))
    
   
    elements.append(Paragraph("Attack Details", header_style))
    
    data = [
        ["Attack Type:", notification.attack_type],
        ["Severity:", notification.severity.upper()],
        ["Timestamp:", notification.timestamp.strftime("%B %d, %Y, %I:%M:%S %p")]
    ]
    
    
    table = Table(data, colWidths=[2*inch, 4*inch])
    table.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.5, colors.gray),
        ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('PADDING', (0, 0), (-1, -1), 6),
    ]))
    
    elements.append(table)
    elements.append(Spacer(1, 0.2*inch))
    
  
    elements.append(Paragraph("Description", header_style))
    elements.append(Paragraph(notification.description, styles["Normal"]))
    elements.append(Spacer(1, 0.2*inch))
    
    
    elements.append(Paragraph("Recommendations", header_style))
    recommendations = [
        "Update your firewall rules to block suspicious traffic",
        "Scan affected systems for malware",
        "Check system logs for additional suspicious activity",
        "Consider implementing additional security measures"
    ]
    
    for rec in recommendations:
        elements.append(Paragraph(f"• {rec}", styles["Normal"]))
    
    elements.append(Spacer(1, 0.3*inch))
    
    
    footer_text = "This is an automated report generated by ModelSentinel IDS. Please contact your security team for further assistance."
    elements.append(Paragraph(footer_text, styles["Italic"]))
    
    
    doc.build(elements)
    buffer.seek(0)
    
    return buffer

def send_attack_report_email(email, notification, pdf_file):
    """Send an email with the PDF report attached"""
    subject = f"Attack Report: {notification.attack_type}"
    message = f"Please find attached a report for the {notification.attack_type} attack detected on {notification.timestamp}."
    from_email = settings.DEFAULT_FROM_EMAIL
    
    email_message = EmailMessage(subject, message, from_email, [email])
    email_message.attach(f'attack_report_{notification.id}.pdf', pdf_file.read(), 'application/pdf')
    email_message.send()

@api_view(['POST'])

def generate_alert_report(request):
    """Generate a PDF report of recent alerts and email it"""
    try:
        
        days = int(request.data.get('days', 1))
        email = request.data.get('email')
        
        logger.info(f"🔍 Report request - days: {days}, email: {email}")
        print(f"🔍 Generating report for {days} days to {email}")
        
        
        end_date = timezone.now()
        start_date = end_date - timedelta(days=days)
        
        print(f"📅 Date range: {start_date.strftime('%Y-%m-%d %H:%M:%S')} to {end_date.strftime('%Y-%m-%d %H:%M:%S')}")
        
        
        all_alerts = SnortAlert.objects.filter(
            timestamp__gte=start_date,
            timestamp__lte=end_date
        )
        
        
        total_alert_count = all_alerts.count()
        print(f"📊 Total alerts in {days}-day period: {total_alert_count}")
        
        
        high_severity = all_alerts.filter(severity=1).count()
        medium_severity = all_alerts.filter(severity=2).count()
        low_severity = all_alerts.filter(severity=3).count()
        print(f"📊 Severity counts - High: {high_severity}, Medium: {medium_severity}, Low: {low_severity}")
        
       
        table_alerts = all_alerts.order_by('-timestamp')[:100]
        
        
        buffer = BytesIO()
        
        
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        
        elements = []
        
        
        title_style = styles["Heading1"]
        title_style.alignment = 1 
        elements.append(Paragraph("ModelSentinel IDS - Alert Report", title_style))
        elements.append(Paragraph(f"Report Period: {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')} ({days} days)", styles["Normal"]))
        elements.append(Spacer(1, 0.25*inch))
        
        
        stats_data = [
            ['Total Alerts', f"{total_alert_count}"],
            ['High Severity', f"{high_severity} ({high_severity/total_alert_count*100:.1f}% of total)" if total_alert_count else "0"],
            ['Medium Severity', f"{medium_severity} ({medium_severity/total_alert_count*100:.1f}% of total)" if total_alert_count else "0"],
            ['Low Severity', f"{low_severity} ({low_severity/total_alert_count*100:.1f}% of total)" if total_alert_count else "0"],
        ]
        
        stats_table = Table(stats_data, colWidths=[2*inch, 1*inch])
        stats_table.setStyle(TableStyle([
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
        ]))
        
        elements.append(Paragraph("Alert Statistics", styles["Heading2"]))
        elements.append(stats_table)
        elements.append(Spacer(1, 0.25*inch))
        
        
        if table_alerts:
            if total_alert_count > 100:
                elements.append(Paragraph(f"Recent Alerts (Showing 100 most recent of {total_alert_count} total alerts)", styles["Heading2"]))
            else:
                elements.append(Paragraph("Recent Alerts", styles["Heading2"]))
            
            
            alerts_data = [['Timestamp', 'Source IP', 'Destination IP', 'Protocol', 'Signature', 'Severity']]
            
           
            for alert in table_alerts:
                severity = {1: 'High', 2: 'Medium', 3: 'Low'}.get(alert.severity, 'Unknown')
                signature = alert.signature
                if signature and len(signature) > 50:
                    signature = signature[:47] + '...'
                
                alerts_data.append([
                    alert.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                    alert.source_ip,
                    alert.destination_ip,
                    alert.protocol,
                    signature,
                    severity,
                ])
            
            
            alerts_table = Table(alerts_data, repeatRows=1)
            alerts_table.setStyle(TableStyle([
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ]))
            elements.append(alerts_table)
        else:
            elements.append(Paragraph("No alerts found in the selected time period", styles["Normal"]))
        
        
        doc.build(elements)
        
        logger.info("PDF generation completed successfully")
    except Exception as pdf_error:
        logger.error(f"Error generating PDF: {str(pdf_error)}")
        return HttpResponse(f"Error generating PDF: {str(pdf_error)}", status=500)
    
    
    buffer.seek(0)
    filename = f"modelsentinel_report_{timezone.now().strftime('%Y%m%d_%H%M')}.pdf"
    
    
    response = FileResponse(buffer, content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    response['Access-Control-Allow-Origin'] = '*'  
    
    logger.info(f"Returning PDF with filename {filename}")
    
    try:
        from_email = settings.DEFAULT_FROM_EMAIL
        
        subject = "ModelSentinel IDS - Security Alert Report"
        body = f"""
        Hello,

        Please find attached your requested security alert report from ModelSentinel IDS.

        Report period: {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}
        Report timespan: {days} days

        Alert Statistics:
        - Total alerts: {total_alert_count} 
        - High severity alerts: {high_severity} ({high_severity/total_alert_count*100:.1f}% of total) 
        - Medium severity alerts: {medium_severity} ({medium_severity/total_alert_count*100:.1f}% of total)
        - Low severity alerts: {low_severity} ({low_severity/total_alert_count*100:.1f}% of total)

        Note: The attached PDF contains up to 100 most recent alerts for readability.

        This is an automated email. Please do not reply.

        Regards,
        ModelSentinel IDS Team
        """
        email_message = EmailMessage(subject, body, from_email, [email])
        email_message.attach(filename, buffer.getvalue(), 'application/pdf')
        
        
        print(f"Sending email to: {email}")
        print(f"From: {from_email}")
        print(f"Subject: {subject}")
        print(f"Using EMAIL_HOST: {settings.EMAIL_HOST}")
        
        
        import smtplib
        try:
            email_message.send(fail_silently=False)
            print("Email sent successfully!")
        except smtplib.SMTPException as e:
            print(f"SMTP Error: {e}")
            return JsonResponse({'error': f'SMTP Error: {str(e)}'}, status=500)
            
        return JsonResponse({
            'success': True,
            'message': f'Report has been sent to {email}',
        })
    except Exception as email_error:
        print(f"Exception during email sending: {email_error}")
        return JsonResponse({'error': f'Error sending email: {str(email_error)}'}, status=500)

@api_view(['POST'])
def mark_all_notifications_read(request):
    """Mark all notifications as read"""
    try:
        
        from .models import AttackNotification
        count_attack = AttackNotification.objects.filter(is_read=False).count()
        AttackNotification.objects.filter(is_read=False).update(is_read=True)
        
       
        count_alerts = 0
        try:
            from .models import SnortAlert
            if hasattr(SnortAlert, 'is_read'):
                count_alerts = SnortAlert.objects.filter(is_read=False).count()
                SnortAlert.objects.filter(is_read=False).update(is_read=True)
        except Exception as alert_error:
            print(f"Error updating SnortAlerts (this is fine if model doesn't have is_read): {alert_error}")
        
        return JsonResponse({
            'success': True, 
            'message': f'All notifications marked as read ({count_attack + count_alerts} total)'
        })
    except Exception as e:
        import traceback
        print(f"Error marking notifications as read: {e}")
        print(traceback.format_exc())
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


def simulate_attack_detection(user, attack_type, description, severity='medium'):
    """Simulate attack detection and create a notification"""
    notification = AttackNotification.objects.create(
        user=user,
        attack_type=attack_type,
        description=description,
        severity=severity
    )
    return notification


@api_view(['GET'])
def get_notifications(request):
    
    alerts = SnortAlert.objects.order_by('-timestamp')[:20]
    
    response_data = []
    for alert in alerts:
        response_data.append({
            'id': alert.id,
            'message': f"{alert.signature} from {alert.source_ip}",
            'timestamp': alert.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            'read': getattr(alert, 'is_read', False),
            'severity': alert.severity
        })
    
    return JsonResponse(response_data, safe=False)
