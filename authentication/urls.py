from django.urls import path, reverse_lazy
from django.views.decorators.csrf import csrf_exempt
from .views import register, login_view, logout_view, default, UsernameValidationView, EmailValidationView, VerificationView
from django.contrib.auth import views as auth_views  # For password reset views
from . import views
app_name = 'authentication'

urlpatterns = [
    path("", default, name='default'),
    path('signup/', register, name="signup"),
    path('login/', login_view, name="login"),
    path('logout/', logout_view, name="logout"),
    path('validate-username', csrf_exempt(UsernameValidationView.as_view()), name="validate-username"),
    path('validate-email', csrf_exempt(EmailValidationView.as_view()), name='validate_email'),
    path('activate/<uidb64>/<token>', VerificationView.as_view(), name='activate'),

    # Password reset URLs
    path('password_reset/', views.password_recovery, name='password_reset'),
    path('password_reset_done/', auth_views.PasswordResetDoneView.as_view(template_name='password_reset_done.html'), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(template_name='password_reset_confirm.html'), name='password_reset_confirm'),
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(template_name='password_reset_complete.html'), name='password_reset_complete'),
]
