from django.conf import settings
from rest_framework import serializers
from django.core.mail import send_mail
from django.core.cache import cache
import random
from dotenv import dotenv_values
from .models import(
    AuditLog,
    ShowStatus,
    User,
    Clinic,
    Doctor,
    Nurse,
    Manager,
    BasicOfficeSettings,
    OfficeBillingSettings,
)
class UserRegistrationSerializer(serializers.ModelSerializer):
    otp = serializers.CharField(required=False)
    class Meta:
        model = User
        fields = "__all__"
    def create(self, validated_data):
        env = dotenv_values()
        user = User.objects.create_user(**validated_data)
        otp = str(random.randint(100000, 999999))
        cache.set(f'otp-{user.id}', otp, timeout=180)
        
        url = env.get('otp_page_url')
        otp_page_url = f'{url}{user.id}'

        username = user.username
        
        message = f'''Hello,

        Thanks for signing up.

        You will only need to visit the link once to verify and activate your account.

        To complete your account verification, please click the link given below and enter the one time secure number OTP.

        {otp_page_url}
        Username: {username}
        OTP: {otp}
        Will expire in 3 minutes

        If the above link does not work, please copy and paste the link into your web browser.

        If you are still having problems signing up then please get in touch with our support team.

        Thank you,
        Team American EMR.'''

        email_subject = 'Email Verfication'

        email_from = settings.MAILERSEND_SMTP_USERNAME
        email_to = [validated_data['email']]
     
        send_mail(
            subject=email_subject,
            message=message,
            from_email=email_from,
            recipient_list=email_to,
            fail_silently=False,
        )
        return user
class ClinicRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Clinic
        fields = "__all__"
class ManagerRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Manager
        fields = "__all__"
class DoctorRegistrationSerializer(serializers.ModelSerializer):
    clinic_id = serializers.IntegerField()
    class Meta:
        model = Doctor
        fields = "__all__"
class NurseRegistrationSerializer(serializers.ModelSerializer):
    clinic_id = serializers.IntegerField()
    class Meta:
        model = Nurse
        fields = "__all__"

# OTP verification
class OTPVerificationSerializer(serializers.Serializer):
    user_id = serializers.IntegerField()
    otp = serializers.CharField()
    def validate(self, data):
        user_id = data.get('user_id')
        otp = data.get('otp')
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            raise serializers.ValidationError("User does not exist")
        cached_otp = cache.get(f'otp-{user_id}')
        if not cached_otp or cached_otp != otp:
            raise serializers.ValidationError("Invalid OTP code")
        cache.delete(f'otp-{user_id}')
        data['user'] = user
        return data

class UpdatePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(max_length=500, required=True)
    new_password = serializers.CharField(max_length=500, required=True)

class DoctorSerializer(serializers.ModelSerializer):
    class Meta:
        model = Doctor
        fields = '__all__'

class NurseSerializer(serializers.ModelSerializer):
    class Meta:
        model = Nurse
        fields = '__all__'

class ManagerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Manager
        fields = '__all__'


class OfficeBasicSettingsSerializer(serializers.ModelSerializer):
    class Meta:
        model = BasicOfficeSettings
        fields = "__all__"

class OfficeBillingSettingsSerializer(serializers.ModelSerializer):
    class Meta:
        model = OfficeBillingSettings
        fields = "__all__"

class UserSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    username = serializers.CharField()
    email = serializers.EmailField()
    first_name = serializers.CharField()
    last_name = serializers.CharField()
    role = serializers.CharField()

class AuditLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = AuditLog
        fields = "__all__"

class ShowStatusSerializer(serializers.ModelSerializer):
    payment_due = serializers.SerializerMethodField()

    class Meta:
        model = ShowStatus
        fields = "__all__"
    
    def get_payment_due(self, instance):
        clinic = instance.clinic
        count = Doctor.objects.filter(clinic=clinic, user__is_active=True).count() + Nurse.objects.filter(clinic=clinic, user__is_active=True).count() + Manager.objects.filter(clinic=clinic, user__is_active=True).count()
        payment_due = (count*5)+45
        payment_due = {
            "payment_due":payment_due,
            "active_count":count
        }
        return payment_due

class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = "__all__"
