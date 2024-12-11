from django.urls import path

from project_emr_auth.views import UpdatePasswordView, UserRegistrationView

from .views import (
AccountOwnerCreditCardInfoRetrieveView,
AccountOwnerCreditCardInfoView,
AccoutOwnerEmailForInvoiceRetrieveView,
AccoutOwnerEmailForInvoiceView,
RetrieveApplicationImages,
RetrieveSuperAdminNote,
SuperAdminLoginView,
SuperAdminNoteView,
UpdateClinicView,
VerifyOTPView,
SuperAdminView,
SuperAdminAccessView,
ClinicDataUsageView,
ManageShowStatusView,
DeleteUpdateClinic,
RegisteredClinic,
UpdateSuperAdminPasswordView,
SuperAdminManageView,
RetrieveSuperAdminManager,
AccountOwnerPyamentInfoRetrieveView,
SuperAdminDetailManageView,
SuperAdminAuditLogView
)


urlpatterns = [
    path('get-super-admin-audit-logs/', SuperAdminAuditLogView.as_view(), name="get-super-admin-audit-logs"),
    path('superadmin-login/', SuperAdminLoginView.as_view(), name='superadmin-login'),
    path('super-admin-otp-verify/', VerifyOTPView.as_view(), name='verify-otp'),
    path('super-admin-detail/', SuperAdminDetailManageView.as_view(), name='get super admin detail'),
    path('super-admin-manager-register/', SuperAdminManageView.as_view(), name='register-super-admin'),
    path('super-admin-manager-update/<int:user_id>/', SuperAdminManageView.as_view(), name='register-super-update'),
    path('super-admin-manager-delete/<int:user_id>/', SuperAdminManageView.as_view(), name='register-super-delete'),
    path("dashboard/", SuperAdminView.as_view()),
    path("retrieve/superadmin-managers/", RetrieveSuperAdminManager.as_view()),
    path("set-clinic/inactive/", SuperAdminAccessView.as_view()),
    path("user/count/", SuperAdminAccessView.as_view(), name="get active users count, user count and patient count"),
    path("office/count/", RegisteredClinic.as_view(), name="clinic count"),
    path("data/usage/", ClinicDataUsageView.as_view(), name="data usage"),
    path('update/', ManageShowStatusView.as_view(), name='update_all_status'),
    path('update/<str:clinic_id>/', ManageShowStatusView.as_view(), name='update_specific_status_or_note_or_extension'),
    path('delete/<str:username>/', DeleteUpdateClinic.as_view(), name='delete_a_user'),
    path('admin-update-email/<str:username>/', UpdateClinicView.as_view(), name='update_email_of_user'),
    path('update-superadmin/request-otp/', UpdateSuperAdminPasswordView.as_view(), name='request-otp'),
    path('update-superadmin/', UpdateSuperAdminPasswordView.as_view(), name='verify-otp'),
    path('add-application-images/', RetrieveApplicationImages.as_view(), name='manage-application-images'),
    path('update-application-images/', RetrieveApplicationImages.as_view(), name='update-application-images'),
    path('retrieve-application-images/', RetrieveApplicationImages.as_view(), name='retrieve-application-images'),
    path('retrieve-super-admin-note/', RetrieveSuperAdminNote.as_view(), name='retrieve-super-admin-note'),
    path('retrieve-super-admin-note/<int:user_id>/', RetrieveSuperAdminNote.as_view(), name='retrieve-super-admin-note'),
    path('super-admin-note/', SuperAdminNoteView.as_view(), name='create-super-admin-note'),
    path('super-admin-note/update/', SuperAdminNoteView.as_view(), name='update-super-admin-note'),
    path('super-admin-note/delete/', SuperAdminNoteView.as_view(), name='delete-super-admin-note'),

    path('account_owner_credit_card_info/add/', AccountOwnerCreditCardInfoView.as_view(), name='account_owner_credit_card_info_add'),
    path('account_owner_credit_card_info/get/', AccountOwnerCreditCardInfoRetrieveView.as_view(), name='account_owner_credit_card_info_get_office'),
    path('account_owner_credit_card_info/get/<int:account>/', AccountOwnerCreditCardInfoRetrieveView.as_view(), name='account_owner_credit_card_info_get'),
    path('account_owner_credit_card_info/update/<record_id>/', AccountOwnerCreditCardInfoView.as_view(), name='account_owner_credit_card_info_update_specific'),
    path('account_owner_credit_card_info/delete/<record_id>/', AccountOwnerCreditCardInfoView.as_view(), name='account_owner_credit_card_info_delete'),

    # for both credit card and invoice
    path('account_owner_payment_info/get/<int:account>/', AccountOwnerPyamentInfoRetrieveView.as_view(), name='account_owner_payment_info'),
    
    path('account_owner_email_for_invoice/add/', AccoutOwnerEmailForInvoiceView.as_view(), name='account_owner_email_for_invoice_add'),
    path('account_owner_email_for_invoice/get/', AccoutOwnerEmailForInvoiceRetrieveView.as_view(), name='account_owner_email_for_invoice_get_office'),
    path('account_owner_email_for_invoice/get/<int:account>/', AccoutOwnerEmailForInvoiceRetrieveView.as_view(), name='account_owner_email_for_invoice_get'),
    path('account_owner_email_for_invoice/update/<record_id>/', AccoutOwnerEmailForInvoiceView.as_view(), name='account_owner_email_for_invoice_update_specific'),
    path('account_owner_email_for_invoice/delete/<record_id>/', AccoutOwnerEmailForInvoiceView.as_view(), name='account_owner_email_for_invoice_delete'),
]