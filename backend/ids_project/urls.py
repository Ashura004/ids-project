from django.contrib import admin
from django.urls import path, include
from snort_analyzer import views as snort_views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('dashboard/', include('snort_analyzer.urls')),
    path('api/', snort_views.dashboard_api, name='dashboard_api'),
]
