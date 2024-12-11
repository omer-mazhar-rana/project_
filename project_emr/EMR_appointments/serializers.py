from rest_framework import serializers
from .models import Appointments
from EMR_patients.models import Patient

class AppointmentsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Appointments
        fields = "__all__"

class SearchPatientSerializer(serializers.ModelSerializer):
    class Meta:
        model = Patient
        fields = "__all__"

class ChooseServicesSerializer(serializers.Serializer):
    service_names = serializers.CharField()

class OfficeTimingsSerializer(serializers.Serializer):
    operating_hrs = serializers.JSONField()