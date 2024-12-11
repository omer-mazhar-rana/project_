from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView, SpectacularRedocView

urlpatterns = [
    path('user/', include("project_emr_auth.urls")),
    path('patient/', include("EMR_patients.urls")),
    path('services/', include("EMR_services.urls")),
    path('settings/', include("EMR_user_settings.urls")),
    path('prescriptions/',include("EMR_prescriptions.urls")),
    path('icd/', include("ICD10_codes.urls")),
    path('inventory/', include("EMR_inventory.urls")),
    path('waiting-room/', include("EMR_waiting_room.urls")),
    path('appointments/', include("EMR_appointments.urls")),
    path('notes/', include("EMR_notes.urls")),
    path('dashboard/', include("EMR_dashboard.urls")),
    path('tasks/', include("EMR_tasks.urls")),
    path('membership/', include("EMR_membership.urls")),
    path('bill/', include("EMR_credit_memo.urls")),
    path('patient/message/', include("EMR_patient_messaging.urls")),
    path('reports/', include("reports.urls")),
    path('visits/', include("EMR_visits.urls")),
    path('templates/', include("EMR_templates.urls")),
    path('administration/', include("EMR_SuperAdmin.urls")),
    path('upload/', include("upload_to_GCP.urls")),
    path("invoice/", include("EMR_invoice_billings.urls")),
    path('labs/images/', include("EMR_labs_images.urls")),
    path('referral/', include("EMR_referrals.urls")),
    path('insurance-claims/', include("EMR_insurance_claims.urls")),
    path('superbill/', include("EMR_superBill.urls")),
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('api/schema/swagger-ui/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    path('api/schema/redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),
    
]
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
