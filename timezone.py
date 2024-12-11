import pytz
from project_emr_auth.models import Clinic, Doctor, Manager, Nurse, User
from rest_framework.response import Response
from django.utils import timezone

class TimeZoneMixin:
    def set_timezone(self, request):
        user = request.user.id
        try:
            username = User.objects.get(id=user)
            
            Model = username.role.capitalize()
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=404)
        try:
            clinic = Clinic.objects.get(user_id=user)
            clinic_id = clinic.id
        except:
            try:
                model_mapping = {
                    "Nurse":Nurse,
                    "Doctor":Doctor,
                    "Manager":Manager
                }
                if Model in model_mapping:
                    clinic = model_mapping.get(Model,None).objects.get(user_id=user)
                    clinic_id = clinic.clinic_id
              
            except:
                return Response({'error': 'Not found'}, status=404)
        
        clinic_instance = Clinic.objects.get(id=clinic_id)
        office_settings = clinic_instance.office_settings_Basic.first()
        facility_time_zone = office_settings.facility_time_zone
        if facility_time_zone.startswith("UTC"):
            try:
                offset = int(facility_time_zone[4:])
            except:
                offset = 0
            if "-" in facility_time_zone:
                sign = "+"
            elif "+" in facility_time_zone:
                sign = "-"
            else:
                sign = "+"
            facility_time_zone = f'Etc/GMT{sign}{abs(offset)}'
        facility_time_zone = pytz.timezone(facility_time_zone)
        now_utc = timezone.localtime(timezone.now(), timezone=facility_time_zone)
        now_utc = now_utc.astimezone(pytz.utc)
        utc_date = now_utc.date()
        now = timezone.localtime(timezone.now(), timezone=facility_time_zone).date()
        time = timezone.localtime(timezone.now(), timezone=facility_time_zone)
        return [now, time, utc_date]


