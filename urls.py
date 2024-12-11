from .views import (
    ClinicStatus,
    ExportCSVView,
    UserRegistrationView,
    ClinicRegistrationView,
    UserLoginView,
    OTPVerificationView,
    ResendOTP,
    UpdatePasswordView,
    ResetPasswordView,
    ConfirmResetPasswordView,
    UserStaffView,
    OfficeSettingsView,
    BlackListedUsersView,
    AuditLogView,
    UserUpdateView,
    CaptchaView
    
)
from django.urls import path


from django.contrib.auth import views as auth_views
urlpatterns = [
    path('verify-captcha/', CaptchaView.as_view(),
         name="captcha-verify"),
    path('register/', UserRegistrationView.as_view(),
         name="register user"),
    path('register/clinic/', ClinicRegistrationView.as_view(),
        name="register user"),
    path('update/', UserUpdateView.as_view(),
         name="update user"),
    path('login/', UserLoginView.as_view(),
        name="login user"),
    path('verify-OTP/', OTPVerificationView.as_view(), name="OTP verification"),
    path('get-staff/', UserStaffView.as_view(), name="get-associated-staff"),
    path('get-audit-logs/', AuditLogView.as_view(), name="get-audit-logs"),
    path('get-deleted-staff/', BlackListedUsersView.as_view(), name="get-deleted-staff"),
    path('delete-staff/<int:pk>/', UserStaffView.as_view(), name="delete-associated-staff"),
    path('office-settings/', OfficeSettingsView.as_view(), name="post-office-settings"),
    path('office-settings/', OfficeSettingsView.as_view(), name="get-office-settings"),
    path('office-settings/update/', OfficeSettingsView.as_view(), name="update-office--settings"),
    path('office-settings/delete/', OfficeSettingsView.as_view(), name="delete-office--settings"),
    path("resend-OTP/<int:pk>/", ResendOTP.as_view(), name="resend-OTP"),
    path("change-password/", UpdatePasswordView.as_view(),
         name="update password"),
    path('reset-password/', ResetPasswordView.as_view(), name='password_reset'),
    path('reset-password/done/', auth_views.PasswordResetDoneView.as_view(), name='password_reset_done'),
    path('reset-password/confirm/<username>/<token>/', ConfirmResetPasswordView.as_view(), name='password_reset_confirm'),
    path('reset-password/complete/', auth_views.PasswordResetCompleteView.as_view(), name='password_reset_complete'),
    path('list/status/', ClinicStatus.as_view(), name='get_specific_status'),
    path('list/status/<int:clinic>/', ClinicStatus.as_view(), name='get_specific_status_using_clinic'),
    path('add/payment-method/', ClinicStatus.as_view(), name='add-payment-method'),
    path('export-csv/', ExportCSVView.as_view(), name='export_csv'),

]
