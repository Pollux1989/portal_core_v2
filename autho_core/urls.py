from django.urls import path
from django.views.generic import TemplateView
from . import views

app_name = 'autho_core'

urlpatterns = [
    # Authentication URLs
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),

    # Registration URLs
    path('register/', views.register_view, name='register'),
    path('register/success/', TemplateView.as_view(template_name='autho_core/register_success.html'), name='register_success'),

    # Password Management URLs
    path('password/change/', views.password_change_view, name='password_change'),
    path('password/change/done/', TemplateView.as_view(template_name='autho_core/password_change_done.html'), name='password_change_done'),

    # Password Reset URLs
    path('password/reset/', views.password_reset_view, name='password_reset'),
    path('password/reset/done/', TemplateView.as_view(template_name='autho_core/password_reset_done.html'), name='password_reset_done'),
    path('password/reset/confirm/<uidb64>/<token>/', views.password_reset_confirm_view, name='password_reset_confirm'),
    path('password/reset/complete/', TemplateView.as_view(template_name='autho_core/password_reset_complete.html'), name='password_reset_complete'),

    # User Profile URLs
    path('profile/', views.profile_view, name='profile'),
    path('profile/edit/', views.profile_edit_view, name='profile_edit'),

    # Security URLs
    path('lockout/', views.lockout_view, name='lockout'),
    path('verify-email/<uidb64>/<token>/', views.verify_email_view, name='verify_email'),
    path('verify-email/sent/', TemplateView.as_view(template_name='autho_core/verify_email_sent.html'), name='verify_email_sent'),

    # Additional Security URLs
    path('mfa/setup/', views.mfa_setup_view, name='mfa_setup'),
    path('mfa/verify/', views.mfa_verify_view, name='mfa_verify'),
    path('mfa/disable/', views.mfa_disable_view, name='mfa_disable'),
]