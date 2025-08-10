from django.urls import path
from . import views

urlpatterns = [

    path('', views.dashboard, name='dashboard'),
    path('api/', views.dashboard_api, name='dashboard_api'),
    path('api/alerts/', views.alerts_api, name='alerts_api'),
    path('api/alerts/<int:alert_id>/', views.alert_detail_api, name='alert_detail_api'),  # Add this line
    path('api/live-alerts/', views.live_alerts, name='live_alerts'),
    path('api/notifications/', views.notifications_api, name='notifications_api'),
    path('api/notifications/<int:notification_id>/read/', views.mark_notification_read, name='mark_notification_read'),
]