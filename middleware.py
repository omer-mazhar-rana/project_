from django.contrib.auth.signals import user_logged_in
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.dispatch import receiver
from django.utils import timezone
from pytz import timezone as pytz_timezone
import json
import time
from django.contrib.auth import logout
from django.utils.deprecation import MiddlewareMixin
import logging
import pytz
from dotenv import load_dotenv
from django.core.mail import send_mail
import os
import re

from .models import (
    AuditLog,
    AdministrationLogs,
    BasicOfficeSettings,
    Clinic,
    Doctor,
    Manager,
    Nurse
)
from django.http import JsonResponse
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings

logger = logging.getLogger(__name__)

load_dotenv()

ADMIN_EMAIL = os.getenv('ADMIN_EMAIL')
BLOCKED_IP_FILE = 'blocked_ips.json'

BOT_KEYWORDS = os.getenv('BOT_KEYWORDS').split('|')
USER_AGENT_BLACKLIST = os.getenv('USER_AGENT_BLACKLIST').split('|')


class APIGatewayMiddleware(MiddlewareMixin):
    def __init__(self, get_response):
        self.get_response = get_response
        self.api_error_counts = {}  # Stores counts of 404, 500, 401 errors per IP address

    def process_request(self, request):
        ip_address = self.get_client_ip(request)

        # Check if IP is blocked
        if self.is_ip_blocked(ip_address):
            return JsonResponse({'error': 'Your IP is temporarily blocked due to suspicious activity.'}, status=403)

        # Check for bot keywords and suspicious user agents
        if self.is_suspicious_request(request):
            return JsonResponse({'error': 'Suspicious request detected.'}, status=403)

    def process_response(self, request, response):
        ip_address = self.get_client_ip(request)

        # Monitor API responses (404, 500, 401) for blocking the IP
        if response.status_code in [404, 500, 401]:
            self.increment_error_count(ip_address)
        else:
            # Reset error count for successful responses
            self.reset_error_count(ip_address)

        # Block the IP if it exceeds the threshold of 3 consecutive errors
        if self.api_error_counts.get(ip_address, 0) >= 3:
            self.block_ip(ip_address)
            self.send_alert_email(ip_address)

        return response

    def get_client_ip(self, request):
        """
        Get the client's IP address from the request.
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

    def is_ip_blocked(self, ip):
        """
        Check if the IP address is currently blocked.
        """
        try:
            with open(BLOCKED_IP_FILE, 'r') as f:
                blocked_ips = json.load(f)
            if ip in blocked_ips:
                blocked_time = blocked_ips[ip]
                if time.time() - blocked_time < 3600:
                    return True
        except FileNotFoundError:
            pass 
        return False

    def block_ip(self, ip):
        """
        Block the IP address by adding it to a block list file.
        """
        try:
            with open(BLOCKED_IP_FILE, 'r') as f:
                blocked_ips = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            blocked_ips = {}

        blocked_ips[ip] = time.time()

        with open(BLOCKED_IP_FILE, 'w') as f:
            json.dump(blocked_ips, f)

    def increment_error_count(self, ip):
        """
        Increment the error count for the given IP address.
        """
        if ip not in self.api_error_counts:
            self.api_error_counts[ip] = 0
        self.api_error_counts[ip] += 1

    def reset_error_count(self, ip):
        """
        Reset the error count for the given IP address when a successful request is made.
        """
        if ip in self.api_error_counts:
            del self.api_error_counts[ip]

    def send_alert_email(self, ip):
        """
        Send an email alert to the admin when an IP is blocked.
        """
        subject = f"Blocked IP Alert: {ip}"
        message = f"The IP address {ip} has been blocked due to multiple errors (404, 500, 401)."

        send_mail(
            subject=subject,
            message=message,
            from_email=settings.MAILERSEND_SMTP_USERNAME,
            recipient_list=[ADMIN_EMAIL],
            fail_silently=False,
        )
        send_mail(subject, message, 'no-reply@yourdomain.com', [ADMIN_EMAIL])

    def is_suspicious_request(self, request):
        """
        Check for suspicious bot-like requests based on user-agent and URL patterns.
        """
        user_agent = request.META.get('HTTP_USER_AGENT', '').lower()
        if any(re.search(keyword, user_agent) for keyword in USER_AGENT_BLACKLIST):
            logger.warning(f"Blocked suspicious user-agent: {user_agent}")
            return True

        if any(re.search(keyword, request.path.lower()) for keyword in BOT_KEYWORDS):
            logger.warning(f"Blocked suspicious path: {request.path}")
            return True

        return False

# dormant
class FacilityTimezoneMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            try:
                clinic = Clinic.objects.get(user_id=request.user.id)
                facility_timezone_str = BasicOfficeSettings.objects.get(clinic_id=clinic-id)
                facility_time_zone = facility_timezone_str.facility_time_zone
                facility_timezone = pytz_timezone(facility_time_zone)
                timezone.activate(facility_timezone)
            except Clinic.DoesNotExist:
                default_timezone = pytz_timezone('UTC')
                timezone.activate(default_timezone)

        response = self.get_response(request)
        return response

class AuditLogMiddleware(MiddlewareMixin):
    def process_view(self, request, view_func, view_args, view_kwargs):
        try:
            user_auth_tuple = JWTAuthentication().authenticate(request)
            if user_auth_tuple is not None:
                request.user, request.auth = user_auth_tuple
        except Exception as e:
            logger.error(f"Authentication failed: {str(e)}")
        
        if request.user.is_authenticated:
            path = str(request.path).split("/")
            path = str(request.path).split("/")[-1] + str(request.path).split("/")[-2]
            if request.method == "PATCH" or request.method == "DELETE":
                method = "Updated" if request.method == "PATCH" else "Deleted"
                details = f"Request: {request.method} : Details: {path} {method}"
                action = f"{request.method} request"
                self.create_audit_log(request.user, action, details)
        else:
            action = f"{request.method} request"
            details = f"{request.method} request to {request.path} by an anonymous user"

    def create_audit_log(self, user, action, details):
        clinic = None
        

        if user.role in ["super admin", "super admin manager"]:
            try:
                time = timezone.localtime(timezone.now(), timezone=timezone.utc)
                AdministrationLogs.objects.create(
                    user=user,
                    username=user.username,
                    name=f"{user.first_name} {user.last_name}",
                    roles=user.role,
                    action=action,
                    object_type='API Request',
                    object_id=None,
                    details=details,
                    created_at=time
                )
            except Exception as e:
                logger.error(f"Audit log creation failed: {str(e)}")
        else:
            try:
                clinic = Clinic.objects.get(user_id=user.id)
            except Clinic.DoesNotExist:
                try:
                    staff = Doctor.objects.get(user_id=user.id)
                    clinic = staff.clinic
                except Doctor.DoesNotExist:
                    try:
                        staff = Nurse.objects.get(user_id=user.id)
                        clinic = staff.clinic
                    except Nurse.DoesNotExist:
                        try:
                            staff = Manager.objects.get(user_id=user.id)
                            clinic = staff.clinic
                        except Manager.DoesNotExist:
                            logger.error("No clinic found for user: %s", user.id)
                            return Response("No clinic found", status.HTTP_400_BAD_REQUEST)

            if clinic:
                try:
                    clinic_instance = Clinic.objects.get(id=clinic.id)
                    office_settings = clinic_instance.office_settings_Basic.first()
                    facility_time_zone = office_settings.facility_time_zone
                    if facility_time_zone.startswith("UTC"):
                        offset = int(facility_time_zone[4:]) if facility_time_zone[4:].isdigit() else 0
                        sign = "+" if "-" in facility_time_zone else "-"
                        facility_time_zone = f'Etc/GMT{sign}{abs(offset)}'
                    facility_time_zone = pytz.timezone(facility_time_zone)
                    time = timezone.localtime(timezone.now(), timezone=facility_time_zone)
                except Exception as e:
                    logger.error(f"Time zone conversion error: {str(e)}")
                    time = None
            else:
                time = None

            try:
                AuditLog.objects.create(
                    user=user,
                    clinic=clinic,
                    username=user.username,
                    name=f"{user.first_name} {user.last_name}",
                    roles=user.role,
                    action=action,
                    object_type='API Request',
                    object_id=None,
                    details=details,
                    created_at=time
                )
            except Exception as e:
                logger.error(f"Audit log creation failed: {str(e)}")

# dormant
@receiver(user_logged_in)
def log_user_login(sender, request, user, **kwargs):
    action = "Login"
    
    details = f"User logged in: {user.username}"
    middleware_instance = AuditLogMiddleware()
    middleware_instance.create_audit_log(user, action, details)

# dormant
# Auto logout middleware
class AutoLogoutMiddleware(MiddlewareMixin):
    def process_request(self, request):
        if request.user.is_authenticated:
            last_activity_time = request.user.last_activity_time
            if last_activity_time:
                inactive_duration = timezone.now() - last_activity_time
                if inactive_duration.total_seconds() > 1800:
                    logout(request)
            
class TimeZoneMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        default_time_zone = 'UTC+11'

        response = self.get_response(request)
        if hasattr(request, 'user') and request.user.is_authenticated:
            try:
                clinic = Clinic.objects.get(user_id=request.user.id)
                office_settings = clinic.office_settings_Basic.first()
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
            except Exception as e:
                print(str(e))
        else:
            pass
        print(pytz.timezone(facility_time_zone), "date and time according to BasicOfficeSettings")
        timezone.activate(pytz.timezone(facility_time_zone))
        print(timezone.now(), "timezone now")
        return response