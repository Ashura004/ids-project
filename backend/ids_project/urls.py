from django.contrib import admin
from django.urls import path
from snort_analyzer import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.dashboard_view, name='dashboard'),
    path('api/', views.dashboard_api, name='dashboard_api'),
    path('api/alerts/', views.alerts_api, name='alerts_api'),
    path('api/alerts/<int:alert_id>/', views.alert_detail_api, name='alert_detail_api'),
    path('api/generate-report/', views.generate_report, name='generate_report'),
    path('api/live-alerts/', views.live_alerts, name='live_alerts'),
    path('api/notifications/', views.notifications_api, name='notifications_api'),
    path('api/notifications/<int:notification_id>/read/', views.mark_notification_read, name='mark_notification_read'),
]
