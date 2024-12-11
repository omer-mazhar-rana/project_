import requests
from rest_framework import generics
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from django.contrib.auth import get_user_model
from django.utils import timezone
from EMR_SuperAdmin.permissions import OnlySuperAdmin
import csv
import json
from django.http import HttpResponse

from EMR_patients.views import PateintSummaryPostMixin
from project_emr_auth.timezone import TimeZoneMixin
from .serializers import (
    AuditLogSerializer,
    ShowStatusSerializer,
    UserRegistrationSerializer,
    OTPVerificationSerializer,
    UpdatePasswordSerializer,
    ClinicRegistrationSerializer,
    DoctorRegistrationSerializer,
    NurseRegistrationSerializer,
    ManagerRegistrationSerializer,
    OfficeBasicSettingsSerializer,
    OfficeBillingSettingsSerializer,
    UserSerializer,
    UserUpdateSerializer,
)
from .models import (
    AuditLog,
    Clinic,
    Doctor,
    Nurse,
    Manager,
    BasicOfficeSettings,
    OfficeBillingSettings,
    ShowStatus
)
from .permissions import (
    BlacklistPermission,
    AllowAdmin
)
from django.conf import settings
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.permissions import IsAuthenticated, AllowAny
import jwt
from rest_framework_simplejwt.exceptions import InvalidToken
from django.core.cache import cache
import random
from django.core.mail import send_mail
from django.contrib.auth import authenticate, update_session_auth_hash
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import EmailMessage, get_connection
from django.urls import reverse
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
User = get_user_model()



class UserRegistrationView(TimeZoneMixin,APIView):
    serializer_class = UserRegistrationSerializer
    def get_permissions(self):
        if self.request.method == "POST" and "role" in self.request.data:
            return [IsAuthenticated()]
        return [AllowAny()]
    def post(self, request):
        request.data["password_change_date"] = timezone.now().date()
        request.data["registration_date"] = timezone.now().date()
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        if request.user.id:
            try:
                staff = User.objects.get(id=request.user.id)
                clinic = Clinic.objects.get(user_id=staff.id)
                clinic_id = clinic.id
            except Clinic.DoesNotExist:
                try:
                    clinic = Manager.objects.get(user_id=staff.id)
                    clinic_id = clinic.clinic_id
                except Manager.DoesNotExist:
                    return Response({'error': 'not found'}, status=404)
        if user.role == 'clinic' or user.role == 'Clinic':
            total_clinics_1 = User.objects.filter(role="clinic").count()
            total_clinics_2 = User.objects.filter(role="Clinic").count()

            total_clinics = total_clinics_1 + total_clinics_2
            clinic_initial = str(list(user.first_name)[0])+str(list(user.last_name)[0])
            data = {
                'user': user.id,
                'clinic_code': clinic_initial.upper()+str(total_clinics+1),
            }
            
            clinic_serializer = ClinicRegistrationSerializer(data=data, partial=True)
            clinic_serializer.is_valid(raise_exception=True)
            clinic_instance = clinic_serializer.save()
            status_data = {
                "status":"unpaid",
                "date_time":self.set_timezone(request)[1],
                "clinic":clinic_instance.id
            }
            status_serialzier = ShowStatusSerializer(data=status_data)
            if status_serialzier.is_valid():
                status_serialzier.save()
        elif user.role == 'doctor' or user.role == "Doctor":
            data = {
                "user" : user.id,
                "clinic" : clinic_id
            }
            doctor_serializer = DoctorRegistrationSerializer(data=data, partial=True)
            doctor_serializer.is_valid(raise_exception=True)
            doctor_serializer.save()
        elif user.role == 'nurse' or user.role == 'Nurse':
            data = {
                "user" : user.id,
                "clinic": clinic_id
            }
            nurse_serializer = NurseRegistrationSerializer(data=data, partial=True)
            nurse_serializer.is_valid(raise_exception=True)
            nurse_serializer.save()
        elif user.role == 'manager' or user.role == 'Manager':
            data = {
                "user" : user.id,
                "clinic" : clinic_id
            }
            manager_serializer = ManagerRegistrationSerializer(data=data, partial=True)
            manager_serializer.is_valid(raise_exception=True)
            manager_serializer.save()
        return Response({
            "user" : user.id,
            'message': 'Please check your email for an OTP code.'},
            status=status.HTTP_201_CREATED
        )
class ClinicRegistrationView(TimeZoneMixin,APIView):
    permission_classes = (OnlySuperAdmin,)
    serializer_class = UserRegistrationSerializer
    def post(self, request):
        request.data["password_change_date"] = timezone.now().date()
        request.data["registration_date"] = timezone.now().date()
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        if user.role == 'clinic' or user.role == 'Clinic':
            total_clinics_1 = User.objects.filter(role="clinic").count()
            total_clinics_2 = User.objects.filter(role="Clinic").count()

            total_clinics = total_clinics_1 + total_clinics_2
            clinic_initial = str(list(user.first_name)[0])+str(list(user.last_name)[0])
            data = {
                'user': user.id,
                'clinic_code': clinic_initial.upper()+str(total_clinics+1),
            }
            
            clinic_serializer = ClinicRegistrationSerializer(data=data, partial=True)
            clinic_serializer.is_valid(raise_exception=True)
            clinic_instance = clinic_serializer.save()
            status_data = {
                "status":"unpaid",
                "date_time":timezone.now(),
                "clinic":clinic_instance.id
            }
            status_serialzier = ShowStatusSerializer(data=status_data)
            if status_serialzier.is_valid():
                status_serialzier.save()
        return Response({
            "user" : user.id,
            'message': 'OTP Code Sent'},
            status=status.HTTP_201_CREATED
        )

# update user data
class UserUpdateView(PateintSummaryPostMixin,TimeZoneMixin,APIView):
    def patch(self, request):
        username = self.helper(request)[1]
        try:
            instance = User.objects.get(username=username)
        except User.DoesNotExist:
            return Response("No such user", status=status.HTTP_404_NOT_FOUND)
        request.data["password"] = instance.password
        request.data["username"] = username
        serializer = UserUpdateSerializer(instance, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserLoginView(TokenObtainPairView):
    permission_classes = (AllowAny,)
    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        refresh_token = response.data.get('refresh', None)
        access_token = response.data.get('access', None)
        change_password = False
        if access_token is not None:
            try:
                user_id = self.get_user_id_from_token(access_token)
            except InvalidToken:
                return response
        user = self.get_user_by_id(user_id)
        if not user.is_active:
            response.data = {
                "detail": "No active account found with the given credentials"
            }
            return Response(response.data, status=status.HTTP_401_UNAUTHORIZED)
        current_date = timezone.now().date()
        if not user.is_superuser and not user.is_admin:
            months_difference = (current_date - user.password_change_date).days
            if months_difference >= 90:
                change_password = True
        role = user.role
        try:
            associated_clinic = Clinic.objects.get(user_id=user.id)
        except Clinic.DoesNotExist:
            pass
        try:
            is_doctor = Doctor.objects.get(user_id=user.id)
            associated_clinic = Clinic.objects.get(id=is_doctor.clinic_id)
            associated_user = User.objects.get(id=associated_clinic.user_id)
            if not associated_user.is_active:
                response.data = {
                "detail": "No active account found with the given credentials"
                }
                return Response(response.data, status=status.HTTP_401_UNAUTHORIZED)
        except:
            try:
                is_nurse = Nurse.objects.get(user_id=user.id)
                associated_clinic = Clinic.objects.get(id=is_nurse.clinic_id)
                associated_user = User.objects.get(id=associated_clinic.user_id)
                if not associated_user.is_active:
                    response.data = {
                    "detail": "No active account found with the given credentials"
                    }
                    return Response(response.data, status=status.HTTP_401_UNAUTHORIZED)
            except:
                try:
                    is_manager = Manager.objects.get(user_id=user.id)
                    associated_clinic = Clinic.objects.get(id=is_manager.clinic_id)
                    associated_user = User.objects.get(id=associated_clinic.user_id)
                    if not associated_user.is_active:
                        response.data = {
                        "detail": "No active account found with the given credentials"
                        }
                        return Response(response.data, status=status.HTTP_401_UNAUTHORIZED)
                except:
                    pass
        response.data = {
            'refresh': refresh_token,
            'access': access_token,
            'role': role,
            'change_password':change_password
        }
        try:
            AuditLog.objects.create(
            user=user,
            clinic=associated_clinic,
            username=user.username,
            name = user.first_name+" "+user.last_name,
            roles = user.role,
            action=f"{request.method} response",
            object_type='API Request',
            object_id=None, 
            details=f"Request: {request.method} : Details: Login",
            created_at = timezone.now()
        )
        except Exception as e:
            pass
        return response
    @staticmethod
    def get_user_id_from_token(token):
        try:
            decoded_token = jwt.decode(
                token, settings.SECRET_KEY, algorithms=['HS256'])
            user_id = decoded_token.get('user_id', None)
        except jwt.exceptions.InvalidTokenError as e:
            print(e)
            user_id = None
        return user_id
    @staticmethod
    def get_user_by_id(user_id):
        return User.objects.get(pk=user_id)
# OTP verification view
class OTPVerificationView(APIView):
    permission_classes = (AllowAny,)
    serializer_class = OTPVerificationSerializer
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        user.is_active = True
        user.save()
        data = {
            "user_id" : user.id,
            'message': 'verification successful. Your account is now active.'
            }
        return Response(
            data,
            status=status.HTTP_200_OK
        )
# Resend OTP View
class ResendOTP(APIView):
    permission_classes = (AllowAny,)
    def post(self, request, pk, *args, **kwargs):
        try:
            user = User.objects.get(id=pk)
        except Exception:
            return Response({
                "details": "user not found"},
                status=status.HTTP_404_NOT_FOUND
            )
        otp = str(random.randint(100000, 999999))
        cache.set(f'otp-{user.id}', otp, timeout=180)

        message = 'Your OTP code for account activation ' f'Your OTP code is {otp}\nThis OTP will expire in 3 minutes'
        email_subject = 'Resend OTP'

        email_from = settings.MAILERSEND_SMTP_USERNAME
        email_to = [user.email]

        try:
            send_mail(
            subject=email_subject,
            message=message,
            from_email=email_from,
            recipient_list=email_to,
            fail_silently=False,
        )
        except Exception as e:
            return Response({'message': e})
        return Response({
            'message': 'Please check your email for an OTP code.'},
            status=status.HTTP_200_OK
        )
# change password view
class UpdatePasswordView(generics.GenericAPIView):
    serializer_class = UpdatePasswordSerializer
    permission_classes = (IsAuthenticated, BlacklistPermission)
    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = authenticate(
            username=request.user.username,
            password=serializer.data.get("old_password")
        )
        if not user:
            return Response("Current Password is incorrect", status=status.HTTP_400_BAD_REQUEST)
        user.password_change_date = timezone.now().date()
        if user.check_password(serializer.data.get("new_password")):
            return Response("New password cannot be the same as old password", status=status.HTTP_400_BAD_REQUEST)
        user.set_password(serializer.data.get("new_password"))
        user.save()
        update_session_auth_hash(request, user)
        return Response({"success": "Password changed successfully."})
# Reset password API
class ResetPasswordView(APIView):
    permission_classes = (AllowAny,)

    @method_decorator(csrf_exempt)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def post(self, request, *args, **kwargs):
        try:
            user = User.objects.get(username=request.data.get('username'))
            if user.blacklist:
                raise User.DoesNotExist
        except User.DoesNotExist:
            return Response({'message': 'User does not exist.'}, status=status.HTTP_404_NOT_FOUND)

        email = user.email
        if not email:
            return Response({'message': 'User does not have any associated email.'}, status=status.HTTP_400_BAD_REQUEST)

        token = default_token_generator.make_token(user)
        reset_password_link = request.build_absolute_uri(
            reverse('password_reset_confirm', kwargs={'username': user.username, 'token': token})
        )

        reset_password_link = reset_password_link.replace('stagingbackend', 'stagingapp')

        message = f'Click the link below to reset your password:\n\n{reset_password_link}\n This OTP will expire in 3 minutes'
        email_subject = 'Reset Your Password'
        email_from = settings.MAILERSEND_SMTP_USERNAME
        email_to = [email]
        try:
            send_mail(
                subject=email_subject,
                message=message,
                from_email=email_from,
                recipient_list=email_to
            )
        except Exception as e:
            return Response({"error ":e}, status=status.HTTP_400_BAD_REQUEST)

        return Response({'message': 'Password reset link has been sent.'}, status=status.HTTP_200_OK)

# Confirm reset password
class ConfirmResetPasswordView(APIView):
    permission_classes = (AllowAny,)
    @method_decorator(csrf_exempt)
    def post(self, request, username, token):
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return Response({'error': 'Invalid user'}, status=400)
        if default_token_generator.check_token(user, token):
            new_password = request.data.get('new_password')
            confirm_password = request.data.get('confirm_password')
            if new_password == confirm_password:
                user.set_password(new_password)
                user.save()
                return Response({'success': 'Password reset successfully'})
            else:
                return Response({'error': 'Password dont match'})

        
        return Response({'error': 'Invalid token'}, status=400)
    
class UserStaffView(APIView):
    permission_classes = (IsAuthenticated,BlacklistPermission)
    def get(self, request):
        clinic_id = request.user.id
        try:
            clinic = Clinic.objects.get(user_id=clinic_id)
            clinic_id = clinic.id
        except Clinic.DoesNotExist:
            try:
                clinic = Manager.objects.get(user_id=clinic_id)
                clinic_id = clinic.clinic_id
            except Manager.DoesNotExist:
                return Response({'error': 'not found'}, status=404)

        
        register_doctors = Doctor.objects.filter(clinic_id=clinic_id, user__is_active=True, user__blacklist=False).values_list('user_id', flat=True)
        register_nurses = Nurse.objects.filter(clinic_id=clinic_id, user__is_active=True, user__blacklist=False).values_list('user_id', flat=True)
        register_managers = Manager.objects.filter(clinic_id=clinic_id, user__is_active=True, user__blacklist=False).values_list('user_id', flat=True)

        doctors_data = User.objects.filter(id__in=register_doctors)
        nurses_data = User.objects.filter(id__in=register_nurses)
        managers_data = User.objects.filter(id__in=register_managers)

        doctor_serializer = UserSerializer(doctors_data, many=True)
        nurse_serializer = UserSerializer(nurses_data, many=True)
        manager_serializer = UserSerializer(managers_data, many=True)

        inactive_doctors = Doctor.objects.filter(clinic=clinic_id, user__is_active=False, user__blacklist=False).values(
            'user__id', 'user__first_name', 'user__email', 'user__role', 'user__username'
        )

        inactive_nurses = Nurse.objects.filter(clinic=clinic_id, user__is_active=False, user__blacklist=False).values(
            'user__id', 'user__first_name', 'user__email', 'user__role', 'user__username'
        )

        inactive_managers = Manager.objects.filter(clinic=clinic_id, user__is_active=False, user__blacklist=False).values(
            'user__id', 'user__first_name', 'user__email', 'user__role','user__username'
        )
       
        data = {
            "register_doctors":doctor_serializer.data,
            "register_nurses":nurse_serializer.data,
            "register_managers":manager_serializer.data,
            'pending_doctors': list(inactive_doctors),
            'pending_nurses': list(inactive_nurses),
            'pending_managers': list(inactive_managers),
        }
        return Response({'data': data}, status=200)
    
    def delete(self, request, pk):
        clinic_id = request.user.id
        delete = False
        try:
            clinic = Clinic.objects.get(user_id=clinic_id)
            clinic_id = clinic.id
        except Clinic.DoesNotExist:
            try:
                clinic = Manager.objects.get(user_id=clinic_id)
                clinic_id = clinic.clinic_id
            except Manager.DoesNotExist:
                return Response({'error': 'not found'}, status=404)
        try:
            try:
                doctor = Doctor.objects.get(user_id=pk)
                if doctor and doctor.clinic_id == clinic_id:
                    delete = True
            except:
                pass
            try:
                nurse = Nurse.objects.get(user_id=pk)
                if nurse and nurse.clinic_id == clinic_id:
                    delete = True
            except:
                pass
            try:
                manager = Manager.objects.get(user_id=pk)
                if manager and manager.clinic_id == clinic_id:
                    delete=True

            except:
                pass
        except Exception as e:
            return Response({'error': e}, status=status.HTTP_400_BAD_REQUEST)
        if delete:
            try:
                user = User.objects.get(id=pk)
                if not user.is_active or user.blacklist:
                    user.delete()
                    return Response("user deleted", status=status.HTTP_200_OK)

            except:
                return Response("user does not exists", status=status.HTTP_404_NOT_FOUND)

            user.is_active = False
            user.blacklist = True
            user.save()

            return Response("User Deleted", status=status.HTTP_200_OK)
        return Response("Something went wrong", status=status.HTTP_400_BAD_REQUEST)

class OfficeSettingsView(PateintSummaryPostMixin,APIView):
    permission_classes = (IsAuthenticated,)
    def post(self, request):
        clinic_id = self.helper(request)[0]
        try:
            clinic = Clinic.objects.get(id=clinic_id)
        except Clinic.DoesNotExist:
            try:
                clinic = Manager.objects.get(clinic_id=clinic_id)
            except Manager.DoesNotExist:
                return Response({'error': 'No such found'}, status=404)
            return Response({'error': 'No such found'}, status=404)

        request.data["clinic"] = clinic.id

        setting = request.GET.get('q',None)
        if setting.lower() == "billing/":
                
            serializer = OfficeBillingSettingsSerializer(data=request.data)
        
        elif setting.lower() == "basic/":
            
            serializer = OfficeBasicSettingsSerializer(data=request.data)
        
        serializer.is_valid(raise_exception=True)
        if "clinic" in serializer.validated_data.keys() and len(set(serializer.validated_data.keys())) == 1:
            return Response(status=status.HTTP_406_NOT_ACCEPTABLE)

        serializer.save()

        return Response(serializer.data,status=status.HTTP_201_CREATED)

    def get(self, request):
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

        setting = request.GET.get('q', None)

        if setting is None:
            return Response({'error': 'Invalid setting parameter'}, status=status.HTTP_400_BAD_REQUEST)

        if setting.lower() == "billing/":
            try:
                office_settings = OfficeBillingSettings.objects.get(clinic_id=clinic_id)
                serializer = OfficeBillingSettingsSerializer(office_settings)
            except OfficeBillingSettings.DoesNotExist as e:
                return Response({'error': str(e)}, status=status.HTTP_404_NOT_FOUND)
    
        elif setting.lower() == "basic/":
            try:
                office_settings = BasicOfficeSettings.objects.get(clinic_id=clinic_id)
                serializer = OfficeBasicSettingsSerializer(office_settings)
            except BasicOfficeSettings.DoesNotExist as e:
                return Response({'error': str(e)}, status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'error': 'Invalid setting parameter'}, status=status.HTTP_400_BAD_REQUEST)

        return Response(serializer.data, status=status.HTTP_200_OK)

    def patch(self, request):
        clinic_id = self.helper(request)[0]
        try:
            clinic = Clinic.objects.get(id=clinic_id)
        except Clinic.DoesNotExist:
            try:
                clinic = Manager.objects.get(clinic_id=clinic_id)
            except Manager.DoesNotExist:
                return Response({'error': 'No such found'}, status=404)
            return Response({'error': 'No such found'}, status=404)

        setting = request.GET.get('q', None)

        if setting.lower() == "basic/":
            try:
                office_settings = BasicOfficeSettings.objects.get(clinic_id=clinic.id)
            except BasicOfficeSettings.DoesNotExist:
                return Response({'error': 'Basic office settings not found'}, status=status.HTTP_404_NOT_FOUND)

            update_whole = request.query_params.get('update', None)

            if update_whole:
                serializer = OfficeBasicSettingsSerializer(office_settings, data=request.data, partial=True)
                if serializer.is_valid():
                    serializer.save()
                    return Response(serializer.data, status=status.HTTP_200_OK)
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
            else:
                for key, value in request.data.items():
                    if key in office_settings.__dict__ and isinstance(office_settings.__dict__[key], list):
                        office_settings.update_json_field(key, value)
                    else:
                        setattr(office_settings, key, value)

                office_settings.save()

                serializer = OfficeBasicSettingsSerializer(office_settings)
                return Response(serializer.data, status=status.HTTP_200_OK)

        elif setting.lower() == "billing/":
            try:
                office_billing_settings = OfficeBillingSettings.objects.get(clinic_id=clinic.id)
            except OfficeBillingSettings.DoesNotExist:
                return Response({'error': 'Office billing settings not found'}, status=status.HTTP_404_NOT_FOUND)

            update_whole = request.query_params.get('update', None)

            if update_whole:
                serializer = OfficeBillingSettingsSerializer(office_billing_settings, data=request.data, partial=True)
                if serializer.is_valid():
                    serializer.save()
                    return Response(serializer.data, status=status.HTTP_200_OK)
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
            else:
                for key, value in request.data.items():
                    if key in office_billing_settings.__dict__ and isinstance(office_billing_settings.__dict__[key], list):
                        office_billing_settings.update_json_field(key, value)
                    else:
                        setattr(office_billing_settings, key, value)

                office_billing_settings.save()

                serializer = OfficeBillingSettingsSerializer(office_billing_settings)
                return Response(serializer.data, status=status.HTTP_200_OK)

        return Response({'error': 'Invalid setting provided'}, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request):
        clinic_id = self.helper(request)[0]
        try:
            clinic = Clinic.objects.get(id=clinic_id)
        except Clinic.DoesNotExist:
            try:
                clinic = Manager.objects.get(clinic_id=clinic_id)
            except Manager.DoesNotExist:
                return Response({'error': 'No such found'}, status=404)
            return Response({'error': 'No such found'}, status=404)

        setting = request.GET.get('q', None)

        if setting.lower() == "basic/":
            try:
                office_settings = BasicOfficeSettings.objects.get(clinic_id=clinic.id)
            except BasicOfficeSettings.DoesNotExist as e:
                return Response({'error': str(e)}, status=status.HTTP_404_NOT_FOUND)

            for field_name in BasicOfficeSettings._meta.get_fields():
                if field_name.field.__class__.__name__ == 'JSONField' and isinstance(getattr(office_settings, field_name.name), list):
                    setattr(office_settings, field_name.name, [])
            
            office_settings.save()
            return Response({'message': 'All JSON fields deleted'}, status=status.HTTP_204_NO_CONTENT)

        return Response({'error': 'Invalid setting provided'}, status=status.HTTP_400_BAD_REQUEST)

class BlackListedUsersView(PateintSummaryPostMixin, APIView):
    permission_classes = [IsAuthenticated, AllowAdmin]
    serializer_class = UserSerializer
    def get(self, request):
        clinic = self.helper(request)[0]
        try:
            clinic = Clinic.objects.get(id=clinic)
        except Clinic.DoesNotExist:
            clinic= Manager.objects.get(clinic=clinic)

        model_mapping = {
            "Doctor":Doctor,
            "Nurse":Nurse,
            "Manager":Manager
        }
        data = {
            "Doctor":[],
            "Nurse":[],
            "Manager":[]
        }
        for model in model_mapping:
            instance = model_mapping[model].objects.filter(clinic_id=clinic)
            for ids in instance:
                instance_id = User.objects.filter(id=ids.user_id, blacklist=True)
                if instance_id:
                    serializer = self.serializer_class(instance_id, many=True)
                    data[model].append(serializer.data)

        return Response(data, status=status.HTTP_200_OK)


class AuditLogView(PateintSummaryPostMixin, APIView):
    def get(self, request):
        clinic = self.helper(request)[0]
        instance = AuditLog.objects.filter(clinic_id=clinic)
        serializer = AuditLogSerializer(instance)
        return Response(serializer.data, status=status.HTTP_200_OK)

class ClinicStatus(PateintSummaryPostMixin, APIView):
    def get(self, request,clinic=None):
        if not clinic:
            clinic = self.helper(request)[0]
        try:
            instance = ShowStatus.objects.get(clinic=clinic)
        except ShowStatus.DoesNotExist:
            return Response("no such office", status=status.HTTP_404_NOT_FOUND)
        serializer = ShowStatusSerializer(instance)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def patch(self, request):
        clinic = self.helper(request)[0]
        try:
            instance = ShowStatus.objects.get(clinic=clinic)
        except ShowStatus.DoesNotExist:
            return Response("no such office", status=status.HTTP_404_NOT_FOUND)
        request.data["clinic"] = clinic
        serializer = ShowStatusSerializer(instance, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# To download data into CSV
class ExportCSVView(APIView):
    permission_classes = []
    authentication_classes = []
    def post(self, request, *args, **kwargs):
        if not request.body:
            return Response({'error': 'No data provided'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return Response({'error': 'Invalid JSON data'}, status=status.HTTP_400_BAD_REQUEST)
        
        if not isinstance(data, list) or not all(isinstance(item, dict) for item in data):
            return Response({'error': 'Data should be a list of dictionaries'}, status=status.HTTP_400_BAD_REQUEST)

        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="exported_data.csv"'

        writer = csv.writer(response)

        if len(data) > 0:
            header = data[0].keys()
            writer.writerow(header)

            for row in data:
                writer.writerow(row.values())
        
        return response

class CaptchaView(APIView):
    permission_classes = []
    authentication_classes = []

    def post(self, request, *args, **kwargs):
        token = request.data["token"]

        verification_url = "https://www.google.com/recaptcha/api/siteverify"
        payload = {
            "secret": "6Ldpt44qAAAAABtnTIixFvtX3DSXbXJ5WdE7s7Jl",
            "response": token
        }
        response = requests.post(verification_url, data=payload)
        result = response.json()

        if result.get("success"):
            return Response({
            'message': 'CAPTCHA verified!'},
            status=status.HTTP_200_OK
        )
        else:
            return Response({
            'message': 'CAPTCHA verification failed!'},
            status=status.HTTP_400_BAD_REQUEST
        )