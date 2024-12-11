import datetime
from django.db import models
from project_emr_auth.models import (
    Clinic,
)

class Appointments(models.Model):
    clinic = models.ForeignKey(Clinic, on_delete=models.CASCADE, related_name='patient''s_appointments')
    time = models.CharField(max_length=100,default=None, null=True)
    ending_time = models.CharField(max_length=100, null=True, default="")
    current_status = models.CharField(max_length=100,default="Scheduled")
    first_name = models.CharField(max_length=200,blank=False,null=False,default="")
    middle_name = models.CharField(max_length=200,blank=True,null=True, default="")
    last_name = models.CharField(max_length=200,blank=False,null=False, default="")
    dob = models.CharField(max_length=50,blank=True,null=True,default="")
    gender = models.CharField(max_length=50, default="")
    contact = models.CharField(max_length=100,blank=True,null=True, default="")
    visit_reason = models.CharField(max_length=300, default="")
    appointment_with = models.CharField(max_length=300, default="")
    appointment_date = models.DateTimeField(max_length=300, default="")
    time_zone_value = models.CharField(max_length=100,default="", null=True, blank=True)
    duration = models.CharField(max_length=50, default="")
    service = models.CharField(max_length=50, default="")
    patient_id = models.IntegerField(blank=True, null=True)
    patient_MRN = models.CharField(max_length=50, default="")
    provider_id = models.IntegerField(default=0)
    registered_date = models.DateField(default=datetime.date.today)
    