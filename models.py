import datetime
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from datetime import date
from django.utils import timezone

class UserManager(BaseUserManager):
    def create_user(self, username, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Users must have an email address')

        user = self.model(
            username=username,
            email=self.normalize_email(email),
            **extra_fields
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        return self.create_user(username, email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    ROLES = (
        ('clinic', 'Clinic'),
        ('manager', 'Manager'),
        ('doctor', 'Doctor'),
        ('nurse', 'Nurse'),
        ('super admin manager', 'Super Admin Manager'),
    )
    role = models.CharField(max_length=20,choices=ROLES, default='clinic')
    username = models.CharField(max_length=30, unique=True)
    email = models.EmailField(max_length=255, null=True, blank=True)
    first_name = models.CharField(max_length=30, blank=True)
    last_name = models.CharField(max_length=30, blank=True)
    is_admin = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)
    blacklist = models.BooleanField(default=False)
    registration_date = models.DateField(default=datetime.date.today)
    password_change_date = models.DateField(null=True, blank=True)

    objects = UserManager()
    REQUIRED_FIELDS = ['email']
    USERNAME_FIELD = 'username'

    def __str__(self):
        return str(self.username)

    def get_full_name(self):
        return f'{self.first_name} {self.last_name}'

    def get_short_name(self):
        return self.username

    @property
    def get_email(self):
        return self.email
    
class Clinic(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    clinic_code = models.CharField(max_length=200, default=000)

class Manager(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    clinic = models.ForeignKey(Clinic, on_delete=models.CASCADE, related_name='admin')


class Doctor(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    clinic = models.ForeignKey(Clinic, on_delete=models.CASCADE, related_name='Admin_for_staff_doctor')

class Nurse(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    clinic = models.ForeignKey(Clinic, on_delete=models.CASCADE, related_name='Admin_for_staff_nurse')

class OfficeBillingSettings(models.Model):
    clinic = models.ForeignKey(Clinic, on_delete=models.CASCADE, related_name='office_settings_Billing')
    facilty_code = models.JSONField(default=list, null=False, blank=False)
    facilty_registration_number = models.JSONField(default=list)
    tax_id =models.JSONField(default=list)
    taxonomy = models.JSONField(default=dict)
    clia_number = models.JSONField(default=list, null=False, blank=False)
    additional_billing_data_1 = models.JSONField(default=list)
    additional_billing_data_2 = models.JSONField(default=list)
    additional_billing_data_3 = models.JSONField(default=list)

class BasicOfficeSettings(models.Model):
    clinic = models.ForeignKey(Clinic, on_delete=models.CASCADE, related_name='office_settings_Basic')
    facility_name = models.JSONField(default=list)
    speciality_type = models.JSONField(default=list)
    facility_address = models.JSONField(default=list)
    city = models.JSONField(default=list)
    country = models.JSONField(default=list)
    zipcode = models.JSONField(default=list)
    office_phone = models.JSONField(default=list)
    office_fax = models.JSONField(default=list)
    website = models.CharField(max_length=30,null=True, blank=True)
    website_visible = models.BooleanField(default=False)
    buisness_email = models.JSONField(default=list)
    additional_basic_data_1 = models.JSONField(default=list)
    additional_basic_data_2 = models.JSONField(default=list)
    additional_basic_data_3 = models.JSONField(default=list)
    exam_rooms = models.JSONField(default=list)
    operating_hrs = models.JSONField(default=list)
    facility_time_zone = models.CharField(max_length=150, default="")
    date_format = models.CharField(max_length=150, default="")
    state = models.JSONField(default=list)
    time_format = models.CharField(max_length=150, default="")
    local_currency = models.CharField(max_length=150, default="")
    local_tax_rate = models.CharField(max_length=150, default="")
    apply_tax = models.BooleanField(default=False)
    discounts = models.JSONField(default=list)
    selected_unit = models.CharField(max_length=50, default="")
    user_office_logo = models.TextField(default="", null=True, blank=True)
    
    def update_json_field(self, field_name, data):
        json_data = getattr(self, field_name)

        if isinstance(data, dict):
            for key, value in data.items():
                if key in json_data:
                    json_data[key] = value
        elif isinstance(data, list):
            json_data.extend(data)
        else:
            pass

        setattr(self, field_name, json_data)
        self.save()

class ShowStatus(models.Model):
    clinic = models.ForeignKey(Clinic, on_delete=models.CASCADE)
    status = models.CharField(max_length=50,default="")
    date_time = models.DateTimeField(null=True, blank=True)
    payment_method = models.CharField(max_length=100, default="", null=True, blank=True)
    extension = models.CharField(max_length=50,null=True, default="", blank=True)
    notes = models.CharField(max_length=500, default="", null=True, blank=True)

class AuditLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    clinic = models.ForeignKey(Clinic, on_delete=models.CASCADE)
    username = models.CharField(max_length=100,default="")
    action = models.CharField(max_length=100)
    roles = models.CharField(max_length=20,default="")
    object_type = models.CharField(max_length=100)
    object_id = models.PositiveIntegerField(null=True, blank=True)
    details = models.TextField()
    name = models.CharField(max_length=50, default="")
    created_at = models.DateTimeField(timezone.now())


class AdministrationLogs(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    username = models.CharField(max_length=100,default="")
    action = models.CharField(max_length=100)
    roles = models.CharField(max_length=20,default="")
    object_type = models.CharField(max_length=100)
    object_id = models.PositiveIntegerField(null=True, blank=True)
    details = models.TextField()
    name = models.CharField(max_length=50, default="")
    created_at = models.DateTimeField(timezone.now())
