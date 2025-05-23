# snort_analyzer/urls.py

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    SnortAlertViewSet, dashboard_data,
    register_user, login_user, user_profile, logout_user
)

router = DefaultRouter()
router.register(r'snort_alerts', SnortAlertViewSet)

urlpatterns = [
    path('', include(router.urls)),
    path('api/dashboard/', dashboard_data, name='dashboard-data'),
    
    # Auth endpoints
    path('auth/register/', register_user, name='register'),
    path('auth/login/', login_user, name='login'),
    path('auth/profile/', user_profile, name='profile'),
    path('auth/logout/', logout_user, name='logout'),
]