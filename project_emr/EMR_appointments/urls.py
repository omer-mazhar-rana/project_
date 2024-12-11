from django.urls import path
from .views import (
    AppointmentsView,
    UpcomingAppointmentsView,
    SearchPatientView,
    ChooseServiceView,
    OfficeTimingsView,
    GetAppointmentDate

)
urlpatterns = [
    path("make/",AppointmentsView.as_view(), name="make appointment"),
    path("get/",AppointmentsView.as_view(), name="get appointment"),
    path("update/<int:pk>/",AppointmentsView.as_view(), name="update appointment"),
    path("delete/<int:pk>/",AppointmentsView.as_view(), name="delete appointment"),
    path("search-patients/",SearchPatientView.as_view(), name="search patients"),
    path("choose-service/",ChooseServiceView.as_view(), name="choose service"),
    path("get-office-hrs/",OfficeTimingsView.as_view(), name="get office hrs"),
    # get today's appoitment for duplicate 
    path("get-appointments/",GetAppointmentDate.as_view(), name="get today's appointments for duplicate"),
    # get upcoming appointments - greater then current time
    path('up-coming-appointments/', UpcomingAppointmentsView.as_view(), name='upcomimg-appointments-list'),
]