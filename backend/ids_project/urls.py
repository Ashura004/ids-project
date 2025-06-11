from django.contrib import admin
from django.urls import path, include
from snort_analyzer import views as snort_views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('dashboard/', include('snort_analyzer.urls')),
    
    
    path('api/', snort_views.dashboard_api, name='dashboard_api'),
    
    
    path('api/notifications/', snort_views.get_attack_notifications, name='get-attack-notifications'),
    path('api/notifications/<int:notification_id>/read/', snort_views.mark_notification_read, name='mark-notification-read'),
    path('api/notifications/<int:notification_id>/report/', snort_views.generate_attack_report, name='generate-attack-report'),
    
    
    path('api/reports/email/', snort_views.generate_alert_report, name='email-alert-report'),
]
