from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    SnortAlertViewSet, dashboard_data,
    register_user, login_user, user_profile, logout_user,
    get_attack_notifications, mark_notification_read, mark_all_notifications_read
)

router = DefaultRouter()
router.register(r'snort_alerts', SnortAlertViewSet)

urlpatterns = [
    path('', include(router.urls)),
    path('api/dashboard/', dashboard_data, name='dashboard-data'),
    
    
    path('auth/register/', register_user, name='register'),
    path('auth/login/', login_user, name='login'),
    path('auth/profile/', user_profile, name='profile'),
    path('auth/logout/', logout_user, name='logout'),

    
    path('api/attack-notifications/<int:notification_id>/read/', mark_notification_read, name='mark-notification-read'),
    path('api/attack-notifications/mark-all-read', mark_all_notifications_read, name='mark-all-notifications-read'),
    path('api/attack-notifications/', get_attack_notifications, name='get-notifications'),
]