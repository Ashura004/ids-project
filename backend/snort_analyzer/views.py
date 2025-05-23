from django.shortcuts import render
from rest_framework import viewsets, filters, status
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from django.db.models import Count, F, Q
from django.utils import timezone
from datetime import timedelta, datetime
from django_filters.rest_framework import DjangoFilterBackend
from django.http import JsonResponse
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from .auth_serializers import UserSerializer, RegisterSerializer, LoginSerializer
from django.contrib.auth.models import User

from .models import SnortAlert, IPStats, DailyStats
from .serializers import (
    SnortAlertSerializer, IPStatsSerializer, DailyStatsSerializer,
    AlertCountByProtocolSerializer, TopSourceIPsSerializer,
    TopDestinationIPsSerializer, AlertTrendSerializer
)

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
        # Time range filter (default: last 7 days)
        days = int(request.query_params.get('days', 7))
        start_date = timezone.now() - timedelta(days=days)
        
        # Filter queryset by date range
        queryset = SnortAlert.objects.filter(timestamp__gte=start_date)
        
        # Alert counts by severity
        severity_counts = queryset.values('severity').annotate(
            count=Count('id')
        ).order_by('severity')
        
        # Alert counts by protocol
        protocol_counts = queryset.values('protocol').annotate(
            count=Count('id')
        ).order_by('-count')[:10]
        
        # Top source IPs
        top_source_ips = IPStats.objects.filter(
            is_source=True, 
            last_seen__gte=start_date
        ).order_by('-alert_count')[:10]
        
        # Top destination IPs
        top_dest_ips = IPStats.objects.filter(
            is_source=False,
            last_seen__gte=start_date
        ).order_by('-alert_count')[:10]
        
        # Alert trends by day
        trends = DailyStats.objects.filter(
            date__gte=start_date.date()
        ).values('date', 'total_alerts', 'anomaly_count')
        
        # Anomaly vs. normal distribution
        anomaly_counts = {
            'normal': queryset.filter(is_anomalous=False).count(),
            'anomalous': queryset.filter(is_anomalous=True).count()
        }
        
        # Return all data
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
    # Get alerts from the last 24 hours
    last_24h = datetime.now() - timedelta(days=1)
    
    # Count total alerts
    total_alerts = SnortAlert.objects.count()
    recent_alerts = SnortAlert.objects.filter(timestamp__gte=last_24h).count()
    
    # Get severity distribution
    severity_counts = list(
        SnortAlert.objects.values('severity')
                          .annotate(count=Count('id'))
                          .order_by('severity')
    )
    
    # Get protocol distribution
    protocol_counts = list(
        SnortAlert.objects.values('protocol')
                          .annotate(count=Count('id'))
                          .order_by('-count')[:5]
    )
    
    # Get anomaly statistics
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
    
    # Count anomalies
    anomalies = alerts.filter(is_anomalous=True).count()
    
    # Return the JSON response with the actual data
    return JsonResponse({
        'total_alerts': alerts.count(),
        'anomalies': anomalies,
        'severity_distribution': severity_distribution,
        
    })

@api_view(['POST'])
@permission_classes([AllowAny])
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
@permission_classes([AllowAny])
def login_user(request):
    serializer = LoginSerializer(data=request.data)
    if serializer.is_valid():
        username = serializer.validated_data['username']
        password = serializer.validated_data['password']
        
        user = authenticate(username=username, password=password)
        
        if user is not None:
            # Update login stats
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
@permission_classes([IsAuthenticated])
def user_profile(request):
    return Response(UserSerializer(request.user).data)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_user(request):
    # Client-side handling is usually sufficient for JWT tokens
    # Just return success as the token will be removed from client storage
    return Response({'detail': 'Successfully logged out.'})
