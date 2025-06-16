from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

urlpatterns = [
    # Authentication URLs
    path('register/', views.register, name='register'),
    path('login/', auth_views.LoginView.as_view(template_name='file_sharing/login.html'), name='login'),
    path('logout/', auth_views.LogoutView.as_view(), name='logout'),
    
    # Dashboard and file management
    path('', views.dashboard, name='dashboard'),
    path('upload/', views.upload_file, name='upload_file'),
    path('create-link/<uuid:file_id>/', views.create_secure_link, name='create_link'),
    
    # Download process
    path('download/<uuid:link_id>/', views.download_request, name='download_request'),
    path('verify-otp/<uuid:otp_id>/', views.verify_otp_view, name='verify_otp'),
    
    # Admin dashboard
    path('admin-dashboard/', views.admin_dashboard, name='admin_dashboard'),
]
