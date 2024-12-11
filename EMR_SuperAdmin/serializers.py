from rest_framework import serializers

from EMR_SuperAdmin.models import AccoutOwnerCreditCardInfo, AccoutOwnerEmailForInvoice, SuperAdminModel
from project_emr_auth.models import AdministrationLogs, BasicOfficeSettings, ShowStatus, User

class BasicOfficeSettingsSerializer(serializers.ModelSerializer):
    class Meta:
        model = BasicOfficeSettings
        fields = '__all__'

class SuperAdminSerializer(serializers.Serializer):
    user__id = serializers.IntegerField()
    user__username = serializers.CharField()
    user__email = serializers.EmailField()
    user__first_name = serializers.CharField()
    user__last_name = serializers.CharField()
    user__registration_date = serializers.DateField()
    user__is_active = serializers.BooleanField()
    user__role = serializers.CharField()
    mobile_number = serializers.CharField()
    work_number = serializers.CharField()
    speciality = serializers.CharField()
    website = serializers.CharField()
    country = serializers.CharField()
    city = serializers.CharField()
    extension = serializers.IntegerField()
    clinic_code = serializers.CharField()
    office_settings_Basic__facility_name = serializers.ListField(child=serializers.CharField())
    office_settings_Basic__speciality_type = serializers.ListField(child=serializers.CharField())
    office_settings_Basic__facility_address = serializers.ListField(child=serializers.CharField())
    office_settings_Basic__city = serializers.ListField(child=serializers.CharField())
    office_settings_Basic__country = serializers.ListField(child=serializers.CharField())
    office_settings_Basic__zipcode = serializers.ListField(child=serializers.CharField())
    office_settings_Basic__office_phone = serializers.ListField(child=serializers.CharField())
    office_settings_Basic__office_fax = serializers.ListField(child=serializers.CharField())
    office_settings_Basic__website = serializers.CharField()
    office_settings_Basic__state = serializers.ListField(child=serializers.CharField())
    showstatus__status = serializers.CharField()
    showstatus__date_time = serializers.DateTimeField()


class ShowStatusSerialzier(serializers.ModelSerializer):
    class Meta:
        model = ShowStatus
        fields = "__all__"

class UserPostSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = "__all__"

class UserRetrieveSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = "__all__"

class AccoutOwnerCreditCardInfoSerializer(serializers.ModelSerializer):
    class Meta:
        model = AccoutOwnerCreditCardInfo
        fields = "__all__"

class AccoutOwnerEmailForInvoiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = AccoutOwnerEmailForInvoice
        fields = "__all__"

class SuperAdminSerializer(serializers.ModelSerializer):
    class Meta:
        model = SuperAdminModel
        fields = "__all__"

class SuperAdminDetailManageViewSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("first_name", "last_name", "email")


class AdministrationLogsSerializer(serializers.ModelSerializer):
    class Meta:
        model = AdministrationLogs
        fields = "__all__"
