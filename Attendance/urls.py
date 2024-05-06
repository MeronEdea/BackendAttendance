from django.urls import path
from . import views

urlpatterns = [
    path("", views.home, name="home"),
    path('api/register/', views.register_user, name='register_user'),
    path('api/login/', views.login_user, name='login_user'),
    path('api/activity-logs/', views.get_activity_logs, name='get_activity_logs'),
    path('api/profile/', views.user_profile, name='user_profile'),
]