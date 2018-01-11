import uuid

from django.contrib.auth.models import AbstractUser
from django.db import models


# NOTE: Changing AUTH_USER_MODEL will cause migration 0001 from otp_totp to
# break once migrations have already been run once.
class CoreUser(AbstractUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email_verified = models.BooleanField(default=False)
    nickname = models.CharField(blank=True, null=True, max_length=30)
    msisd = models.CharField(blank=True, null=True, max_length=16)
    msisdn_verified = models.BooleanField(default=False)
    gender = models.IntegerField(blank=True, null=True)
    birth_date = models.DateTimeField(blank=True, null=True)
    country = models.ForeignKey("Country", blank=True, null=True)
    avatar = models.ImageField(blank=True, null=True)
    is_employee = models.BooleanField(default=False)
    is_system_user = models.BooleanField(default=False)
    updated_at = models.DateTimeField(auto_now=True)


class Country(models.Model):
    code = models.CharField(blank=True, null=True, max_length=2)
    name = models.CharField(blank=True, null=True, max_length=100)

    class Meta:
        verbose_name_plural = "Countries"
