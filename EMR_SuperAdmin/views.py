from django.utils import timezone
from django.shortcuts import get_object_or_404
import sys
from django.apps import apps
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
import random
from datetime import datetime, timedelta
import pytz
from rest_framework.pagination import PageNumberPagination
from django.core.mail import send_mail
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from django.conf import settings
from django.core.cache import cache
from rest_framework.exceptions import NotFound
from EMR_SuperAdmin.models import AccoutOwnerCreditCardInfo, AccoutOwnerEmailForInvoice, SuperAdminModel
from EMR_SuperAdmin.permissions import OnlySuperAdmin, SuperAdminAccess
from EMR_appointments.models import Appointments
from EMR_credit_memo.models import CreditMemo, OutStandingBill
from EMR_insurance_claims.models import InsuranceClaims
from EMR_inventory.models import CurrentMonth, GuestCheckout, Inventory, ProductInvoice, Revenue
from EMR_invoice_billings.models import AccountDetails, Insurance, PatientInvoice, PaymentMethod, TotalInvoiceGrandRevenue, TotalInvoiceRevenue
from EMR_labs_images.models import ExternalLabs, InHouseLabs, InvoiceInhouseLabs, Orderedlabs
from EMR_membership.models import Memberships, PatientMembership
from EMR_notes.models import Notes
from EMR_patient_messaging.models import PatientMessages
from EMR_patients.models import Patient
from EMR_patients.views import PateintSummaryPostMixin
from EMR_referrals.models import Referral, ReferralDoctor
from EMR_services.models import CptCodes, DeletedCodes, Labs, ServiceGroup, ServiceType, Services
from EMR_superBill.models import SuperBill
from EMR_tasks.models import Tasks
from EMR_templates.models import Templates
from EMR_user_settings.models import MedicalIdentifier, PersonelSettings, WorkSchedule
from EMR_visits.models import Visits
from EMR_waiting_room.models import TrackingWaitingRoom, WaitingRoom
from project_emr_auth.serializers import OTPVerificationSerializer, UpdatePasswordSerializer, UserUpdateSerializer
from project_emr_auth.timezone import TimeZoneMixin
from project_emr_auth.views import UserLoginView

from .serializers import AccoutOwnerCreditCardInfoSerializer, AccoutOwnerEmailForInvoiceSerializer, AdministrationLogsSerializer, ShowStatusSerialzier, SuperAdminDetailManageViewSerializer, SuperAdminSerializer, UserPostSerializer, UserRetrieveSerializer
from project_emr_auth.models import AdministrationLogs, BasicOfficeSettings, Clinic, Doctor, Manager, Nurse, OfficeBillingSettings, ShowStatus, User
from django_rest_passwordreset.models import ResetPasswordToken
from django.utils.crypto import get_random_string
from django.core.cache import cache
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.hashers import make_password
from dotenv import dotenv_values


class SuperAdminLoginView(UserLoginView):
    permission_classes = () 
    
    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
    
        user_id = self.get_user_id_from_token(response.data.get('access'))
        
        user = self.get_user_by_id(user_id)
        
        if not user.is_superuser and user.role!="super admin manager":
            response.data = {
                "detail": "Super admin credentials required"
            }
            return Response(response.data, status=status.HTTP_401_UNAUTHORIZED)
        
        otp = str(random.randint(100000, 999999))
        cache.set(f'otp-{user.id}', otp, timeout=180)
        env = dotenv_values()
        url = env.get('super_admin_otp_page_url')
        otp_page_url = f'{url}{user.id}'

        message = f'''Your OTP code for account login: {otp}\n This OTP will expire in 3 minutes\n. 
                     To enter OTP, visit: {otp_page_url}'''
        email_subject = 'Super Admin Login Attempt'
        email_from = settings.MAILERSEND_SMTP_USERNAME
        email_to = [user.email]
     
        send_mail(
            subject=email_subject,
            message=message,
            from_email=email_from,
            recipient_list=email_to,
            fail_silently=False,
        )
        
        return Response({
            'message': "check email for OTP",
            "user_id":user.id,
            "status":status.HTTP_200_OK
        })
class SuperAdminDetailManageView(APIView):
    permission_classes = (OnlySuperAdmin,)
    def get(self, request):
        if request.user.is_superuser:
            instance = User.objects.filter(is_superuser=True)
        else:
            instance = User.objects.filter(id=request.user.id, role="super admin manager")
        serializer = SuperAdminDetailManageViewSerializer(instance, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class SuperAdminManageView(TimeZoneMixin,APIView):
    permission_classes = (SuperAdminAccess,)

    def post(self, request):
        request.data["role"] = "super admin manager"
        request.data["is_active"] = True
        request.data["password_change_date"] = timezone.now().date()
        request.data["registration_date"] = timezone.now().date()
        request.data["password"] = make_password(request.data["password"])
        serializer = UserPostSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, user_id):
        try:
            instance = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response("User not found", status=status.HTTP_404_NOT_FOUND)
        try:
            password = request.data["password"]
            if password:
                request.data["password"] = make_password(password)
        except:
            request.data["password"] = instance.password
        request.data["username"] = request.data.get("username", instance.username)
        request.data["email"] = request.data.get("email", instance.email)
        serializer = UserUpdateSerializer(instance, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, user_id):
        try:
            instance = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response("User not found", status=status.HTTP_404_NOT_FOUND)
        instance.delete()
        return Response("deleted", status=status.HTTP_200_OK)

class VerifyOTPView(APIView):
    permission_classes = () 

    def post(self, request, *args, **kwargs):

        user_id = request.data.get('user_id')
        otp_entered = request.data.get('otp')

        cached_otp = cache.get(f'otp-{user_id}')

        if not cached_otp:
            return Response({'error': 'OTP expired or invalid'}, status=status.HTTP_400_BAD_REQUEST)

        if otp_entered == int(cached_otp):
            user = get_user_model().objects.get(id=user_id)
            refresh = RefreshToken.for_user(user)
            if refresh and refresh.access_token:
                try:
                    AdministrationLogs.objects.create(
                    user=user,
                    username=user.username,
                    name = user.first_name+" "+user.last_name,
                    roles = user.role,
                    action=f"{request.method} response",
                    object_type='API Request',
                    object_id=None, 
                    details=f"Request: {request.method} : Details: Login",
                    created_at=timezone.now().astimezone(pytz.timezone('America/Chicago'))
                )
                except Exception as e:
                    pass
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                "role" : user.role
            })
        
        return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)

class SuperAdminView(APIView):
    permission_classes = (OnlySuperAdmin,)
    def get(self, request):
        clinic_data = Clinic.objects.select_related('basicofficesettings',"showstatus").values(
            'id',
            'user__id',
            'user__username',
            'user__email',
            'user__first_name',
            'user__last_name',
            'user__is_active',
            'user__last_login',
            'user__registration_date',
            'user__role',
            'clinic_code',
            'office_settings_Basic__facility_name',
            'office_settings_Basic__speciality_type',
            'office_settings_Basic__facility_address',
            'office_settings_Basic__city',
            'office_settings_Basic__country',
            'office_settings_Basic__zipcode',
            'office_settings_Basic__office_phone',
            'office_settings_Basic__office_fax',
            'office_settings_Basic__website',
            'office_settings_Basic__state',
            'showstatus__status',
            "showstatus__date_time",
            "showstatus__notes",
            "showstatus__payment_method",
            "showstatus__extension"

        ).filter(
            user__role="clinic"
        )
        return Response(clinic_data, status=status.HTTP_200_OK)
    
class SuperAdminAccessView(APIView):
    permission_classes = (OnlySuperAdmin,)

    def patch(self, request, *args, **kwargs):
        clinic = get_object_or_404(User, id=request.data["clinic_id"])
        try:
            make_active = request.data["status"]
        except:
            pass
        if not make_active:
            clinic.is_active = False
        else:
            clinic.is_active = True
        clinic.save()
        return Response({"status":clinic.is_active},status=status.HTTP_200_OK)
    
    def get(self, request):
        clinic_id = request.GET.get("clinic_id", None)

        if clinic_id is None:
            return Response({"detail": "clinic_id is required"}, status=status.HTTP_400_BAD_REQUEST)

        clinic = get_object_or_404(Clinic, id=clinic_id)

        active_doctor_count = Doctor.objects.filter(clinic=clinic, user__is_active=True).count()
        active_nurse_count = Nurse.objects.filter(clinic=clinic, user__is_active=True).count()
        active_manager_count = Manager.objects.filter(clinic=clinic, user__is_active=True).count()
        patient_count = Patient.objects.filter(clinic=clinic).count()



        doctor_count = Doctor.objects.filter(clinic=clinic).count()
        nurse_count = Nurse.objects.filter(clinic=clinic).count()
        manager_count = Manager.objects.filter(clinic=clinic).count()

        total_staff_count = {
            "payment_due":((active_doctor_count+active_nurse_count+active_manager_count)*5)+45,
            "Active staff count":active_doctor_count + active_nurse_count + active_manager_count,
            "Total staff count":doctor_count + nurse_count + manager_count,
            "Total_patient_clinic":patient_count
        }

        return Response({"total_staff_count": total_staff_count}, status=status.HTTP_200_OK)

class ClinicDataUsageView(APIView):
    permission_classes = (OnlySuperAdmin,)
    def get(self, request):
        clinic_id = request.GET.get("clinic", None)
        if not clinic_id:
            return Response("Clinic required", status=status.HTTP_400_BAD_REQUEST)
        
        clinic = get_object_or_404(Clinic, id=clinic_id)
        total_data_usage = 0
        storages = [Patient, Appointments, InsuranceClaims, Inventory, GuestCheckout, Revenue, CurrentMonth, ProductInvoice, InHouseLabs, InvoiceInhouseLabs, ExternalLabs, Orderedlabs, Memberships, PatientMembership, PatientMessages, ReferralDoctor, Referral, ServiceType,
                    Insurance, AccountDetails, PaymentMethod,TotalInvoiceRevenue,TotalInvoiceGrandRevenue,OutStandingBill, CreditMemo, Notes,MedicalIdentifier, WorkSchedule, PersonelSettings, ServiceGroup, Services, Labs, DeletedCodes, CptCodes, SuperBill, Tasks, Templates, Visits, WaitingRoom, TrackingWaitingRoom, OfficeBillingSettings, BasicOfficeSettings, ShowStatus]

        for model in storages:
            try:
                data_size_estimate = self.estimate_model_size(model, clinic)
                total_data_usage += data_size_estimate
            except Exception as e:
                return Response({"error": str(e)})

        return Response({"clinic_id": clinic_id, "total_data_usage_in_MegaBytes": total_data_usage}, status=status.HTTP_200_OK)

    def estimate_model_size(self, model, clinic):
        total_size = 0
        try:
            instances = model.objects.filter(clinic=clinic)
        except Exception as e:
            try:
                instances = model.objects.filter(user_id=clinic.user_id)
            except:
                try:
                    patient_ids = Patient.objects.filter(clinic=clinic).values_list('id', flat=True)
                    instances = model.objects.filter(patient_id__in=patient_ids)
                except:
                    instances = model.objects.filter(clinic=clinic.id)
        for instance in instances:
            instance_size = 0
            for field in instance._meta.fields:
                field_value = getattr(instance, field.attname)
                if isinstance(field_value, str):
                    instance_size += sys.getsizeof(field_value)
                elif isinstance(field_value, int):
                    instance_size += sys.getsizeof(field_value)
            total_size += instance_size
        
        return total_size/ (1024 * 1024)

class ManageShowStatusView(APIView):
    permission_classes = (OnlySuperAdmin,)
    def patch(self, request, clinic_id=None):
        if clinic_id:
            instances = ShowStatus.objects.get(clinic_id=clinic_id)
        else:
            instances = ShowStatus.objects.all()
        try:
            note = request.data["notes"]
        except:
            note = None
        try:
            extension = request.data["extension"]
        except:
            extension = None
        try:
            paid_date = request.data["paid_date"]
        except:
            paid_date = None
        if note!=None or extension!=None or paid_date!=None:
            serialzier = ShowStatusSerialzier(instances, data=request.data)
            request.data["clinic"] = instances.clinic.id
            if serialzier.is_valid():
                serialzier.save()
                return Response("Success", status=status.HTTP_200_OK)
            else:
                print(serialzier.errors)
            return Response("Failed", status=status.HTTP_400_BAD_REQUEST)
        
        else:
            
            try:
                new_status = request.data["status"]
            except:
                new_status = "unpaid"
            try:
                for instance in instances:
                    if not instance.extension:
                        instance.status = new_status
                        instance.save()
            except:
                instances.status = new_status
                instances.save()
            return Response("Success", status=status.HTTP_200_OK)       
        
class DeleteUpdateClinic(APIView):
    permission_classes = (SuperAdminAccess,)
    def delete(self, request, username):
        try:
            instance = User.objects.get(username=username)
        except:
            return Response("No such user", status=status.HTTP_400_BAD_REQUEST)
        if instance:
            reset_pass_instance = ResetPasswordToken.objects.filter(user_id=instance.id)
            for ins in reset_pass_instance:
                ins.delete()
            instance.delete()
            return Response("Deleted", status=status.HTTP_200_OK)
        return Response("Something went wrong", status=status.HTTP_400_BAD_REQUEST)
class UpdateClinicView(APIView):
    def patch(self, request, username):
        try:
            instance = User.objects.get(username=username)
        except:
            return Response("No such user", status=status.HTTP_400_BAD_REQUEST)
        if instance:
            instance.email = request.data["email"]
            instance.save()
            return Response("Success", status=status.HTTP_200_OK)
        return Response("Something went wrong", status=status.HTTP_400_BAD_REQUEST)

class RegisteredClinic(APIView):
    permission_classes = (OnlySuperAdmin,)
    def get(self, request):
        clinic_count = Clinic.objects.all().count()
        active_clinic_count = Clinic.objects.filter(user__is_active=True).count()
        pending_payment = ShowStatus.objects.filter(clinic__user__is_active=True,status="unpaid").count()
        return Response({"total_clinics":clinic_count, "active_clinic_count":active_clinic_count,"pending_payment":pending_payment}, status=status.HTTP_200_OK)
    
class UpdateSuperAdminPasswordView(APIView):
    permission_classes = (OnlySuperAdmin,)

    def send_otp(self, user):
        otp = get_random_string(length=6, allowed_chars='0123456789')
        cache.set(f'otp-{user.id}', otp, timeout=180)  #3 minutes expiration
        email_from = settings.MAILERSEND_SMTP_USERNAME

        send_mail(
            subject='Password Change OTP',
            message=f'Your OTP for password change: {otp}\nThis OTP will expire in 3 minutes',
            from_email=email_from,
            recipient_list=[user.email],
            fail_silently=False,
        )
        return otp

    def post(self, request):
        if 'otp' in request.data:
            serializer = OTPVerificationSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            user = serializer.validated_data['user']
            new_password = request.data.get('new_password')
            new_email = request.data.get('email')
            
            if new_password:
                user.set_password(new_password)
            if new_email:
                user.email = new_email
            user.save()
            update_session_auth_hash(request, user)
            return Response("success", status=status.HTTP_200_OK)

        else:
            user = request.user
            otp = self.send_otp(user)
            return Response({"user":user.id,"message": "OTP sent to your email."})
        
class RetrieveApplicationImages(APIView):
    permission_classes = []
    authentication_classes = []

    def post(self, request):
        super_instance = None
        try:
            super_instance, _ = SuperAdminModel.objects.get_or_create(id=1)
        except:
            pass
        data = request.data

        if 'icon' in data:
            super_instance.icon = data['icon']
        if 'front_page_image' in data:
            super_instance.front_page_image = data['front_page_image']
        if 'login_image' in data:
            super_instance.login_image = data['login_image']

        super_instance.save()

        return Response({"message": "Images updated successfully"}, status=status.HTTP_200_OK)
    def get(self, request):
        try:
            super_instance = SuperAdminModel.objects.get(id=1)
        except SuperAdminModel.DoesNotExist:
            return Response("not found", status=status.HTTP_404_NOT_FOUND)
        data = {
            "icon":super_instance.icon,
            "sign_up_image":super_instance.front_page_image,
            "login_image":super_instance.login_image
        }
        data = {}

        if super_instance.icon:
            data["icon"] = super_instance.icon
        else:
            data["icon"] = None

        if super_instance.front_page_image:
            data["sign_up_image"] = super_instance.front_page_image
        else:
            data["sign_up_image"] = None

        if super_instance.login_image:
            data["login_image"] = super_instance.login_image
        else:
            data["login_image"] = None

        if not data["icon"] and not data["sign_up_image"] and not data["login_image"]:
            raise NotFound("No image associated with either icon or front_page_image")
            
        return Response({"data": data}, status=status.HTTP_200_OK)
    
    def patch(self, request):
        super_instance = SuperAdminModel.objects.get(id=1)
        data = request.data

        if 'icon' in data:
            super_instance.icon = data['icon']
        if 'front_page_image' in data:
            super_instance.front_page_image = data['front_page_image']
        if 'login_image' in data:
            super_instance.login_image = data['login_image']

        super_instance.save()

        return Response({"message": "Images updated successfully"}, status=status.HTTP_200_OK)

    def delete(self, request):
        super_instance = SuperAdminModel.objects.get(id=1)

        super_instance.icon = None
        super_instance.front_page_image = None
        super_instance.login_image = None

        super_instance.save()

        return Response({"message": "Images deleted successfully"}, status=status.HTTP_200_OK)
    
class RetrieveSuperAdminNote(APIView):
    def get(self, request, user_id=None):
        if user_id:
            try:
                instance = User.objects.get(id=user_id)
            except User.DoesNotExist:
                return Response("No such user", status=status.HTTP_404_NOT_FOUND)
        
        instance = SuperAdminModel.objects.get(id=1)
        data = {
            "super_admin_payment_bank_info":instance.super_admin_payment_bank_info,
        }
        return Response({"data":data}, status=status.HTTP_200_OK)

class SuperAdminNoteView(APIView):
    permission_classes = (OnlySuperAdmin,) 
    def post(self, request):
        serializer = SuperAdminSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def patch(self, request):
        instance = SuperAdminModel.objects.get(id=1)
        serializer = SuperAdminSerializer(instance, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, user_id):
        try:
            instance = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response("No such user", status=status.HTTP_404_NOT_FOUND)
        
        try:
            instance = SuperAdminModel.objects.get(id=1)
        except SuperAdminModel.DoesNotExist:
            return Response("No such user", status=status.HTTP_404_NOT_FOUND)
        instance.delete()
        return Response("Deleted", status=status.HTTP_200_OK)

    
class RetrieveSuperAdminManager(APIView):
    permission_classes = (OnlySuperAdmin,)
    def get(self, request):
        qs = User.objects.filter(role="super admin manager")
        serializer = UserRetrieveSerializer(qs, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class AccountOwnerCreditCardInfoView(PateintSummaryPostMixin, APIView):
    serializer_class = AccoutOwnerCreditCardInfoSerializer
    def post(self, request):
        account = self.helper(request)[0]
        request.data["account"] =account
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def patch(self, request, record_id):
        account = self.helper(request)[0]
        try:
            instance = AccoutOwnerCreditCardInfo.objects.get(account_id=account, id=record_id)
        except:
            return Response("no such record", status=status.HTTP_404_NOT_FOUND)
        request.data["account"] = account
        serializer = self.serializer_class(instance, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, record_id):
        account = self.helper(request)[0]
        try:
            instance = AccoutOwnerCreditCardInfo.objects.get(account_id=account, id=record_id)
        except:
            return Response("no such record", status=status.HTTP_404_NOT_FOUND)
        instance.delete()
        return Response("Deleted", status=status.HTTP_200_OK)

class AccountOwnerCreditCardInfoRetrieveView(PateintSummaryPostMixin, APIView):
    def get(self, request, account=None):
        try:
            account = self.helper(request)[0]
        except:
            pass
        instance = AccoutOwnerCreditCardInfo.objects.filter(account_id=account)
        serializer = AccoutOwnerCreditCardInfoSerializer(instance, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


# Retrieve both, credit card and invoice email
class AccountOwnerPyamentInfoRetrieveView(PateintSummaryPostMixin, APIView):
    permission_classes = (OnlySuperAdmin,)

    def get(self, request, account=None):
        try:
            account = self.helper(request)[0]
        except:
            pass
        instance = AccoutOwnerCreditCardInfo.objects.filter(account_id=account)
        credit_card_serializer = AccoutOwnerCreditCardInfoSerializer(instance, many=True)
        try:
            account = self.helper(request)[0]
        except:
            pass
        instance = AccoutOwnerEmailForInvoice.objects.filter(account_id=account)
        email_info_serializer = AccoutOwnerEmailForInvoiceSerializer(instance, many=True)

        data = {
            "credit_card_info":credit_card_serializer.data,
            "email_info_serializer":email_info_serializer.data
        }
        return Response(data, status=status.HTTP_200_OK)
class AccoutOwnerEmailForInvoiceView(PateintSummaryPostMixin, APIView):
    serializer_class = AccoutOwnerEmailForInvoiceSerializer
    def post(self, request):
        account = self.helper(request)[0]
        request.data["account"] =account
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def patch(self, request, record_id=None):
        account = self.helper(request)[0]
        try:
            instance = AccoutOwnerEmailForInvoice.objects.get(account_id=account, id=record_id)
        except:
            return Response("no such record", status=status.HTTP_404_NOT_FOUND)
        serializer = self.serializer_class(instance, data=request.data)
        request.data["account"] = account
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, record_id):
        account = self.helper(request)[0]
        try:
            instance = AccoutOwnerEmailForInvoice.objects.get(account_id=account, id=record_id)
        except:
            return Response("no such record", status=status.HTTP_404_NOT_FOUND)
        instance.delete()
        return Response("Deleted", status=status.HTTP_200_OK)

class AccoutOwnerEmailForInvoiceRetrieveView(PateintSummaryPostMixin, APIView):
    def get(self, request, account=None):
        try:
            account = self.helper(request)[0]
        except:
            pass
        instance = AccoutOwnerEmailForInvoice.objects.filter(account_id=account)
        serializer = AccoutOwnerEmailForInvoiceSerializer(instance, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class SuperAdminAuditLogView(APIView):
    permission_classes = (OnlySuperAdmin,)
    def get(self, request):
        from_date_str = request.GET.get('from_date')
        to_date_str = request.GET.get('to_date')

        facility_time_zone = pytz.timezone('America/Chicago')

        try:
            if not from_date_str or not to_date_str:
                return Response({"error": "from_date and to_date are required"}, status=status.HTTP_400_BAD_REQUEST)

            from_date_utc = self.parse_date_to_utc(from_date_str, facility_time_zone)
            to_date_utc = self.parse_date_to_utc(to_date_str, facility_time_zone)

            to_date_utc += timedelta(days=1)

            query_set = AdministrationLogs.objects.filter(
                created_at__range=(from_date_utc, to_date_utc)
            )
            paginator = PageNumberPagination()
            paginated_queryset = paginator.paginate_queryset(query_set, request)

            serializer = AdministrationLogsSerializer(paginated_queryset, many=True)

            return paginator.get_paginated_response(serializer.data)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def parse_date_to_utc(self, date_str, facility_time_zone):
        date_obj = datetime.strptime(date_str, '%Y-%m-%d').date()
        date_facility_time_zone = facility_time_zone.localize(datetime.combine(date_obj, datetime.min.time()))
        date_utc = date_facility_time_zone.astimezone(pytz.utc)
        return date_utc