from django.db import models

from project_emr_auth.models import Clinic

# Create your models here.

class SuperAdminModel(models.Model):
    super_admin_payment_bank_info = models.TextField(default="", null=True, blank=True)
    icon = models.TextField(null=True, blank=True)
    front_page_image = models.TextField(null=True, blank=True)
    login_image = models.TextField(null=True, blank=True)

class AccoutOwnerCreditCardInfo(models.Model):
    account = models.ForeignKey(Clinic, on_delete=models.CASCADE,unique=True)
    card_holder_name = models.CharField(max_length=300, default="", null=True, blank=True)
    credit_card_number = models.CharField(max_length=50, default="", null=True, blank=True)
    expiration_date = models.CharField(max_length=20, default="",null=True, blank=True)
    cvv_security_code = models.CharField(max_length=10,default="", null=True, blank=True)
    billing_address = models.CharField(max_length=300, default="", null=True, blank=True)
    zipcode = models.CharField(max_length=50, default="", null=True, blank=True)

class AccoutOwnerEmailForInvoice(models.Model):
    account = models.ForeignKey(Clinic, on_delete=models.CASCADE,unique=True)
    email = models.EmailField(default="", null=True, blank=True)