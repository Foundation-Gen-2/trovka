from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone
import random
import string
from datetime import timedelta
from django.conf import settings
import os
import uuid
class UserManager(BaseUserManager):
    def create_user(self, email, username, role=None, password=None):
        if not email:
            raise ValueError("Users must have an email address")
        if not username:
            raise ValueError("Users must have a username")
        
        user = self.model(
            email=self.normalize_email(email),
            username=username,
        )
        user.set_password(password)
        user.is_active = False  # Set user as inactive until they verify email
        user.save(using=self._db)
        
        # Assign role
        if role:
            self.assign_role(user, role)
        else:
            self.assign_default_role(user)
        
        return user

    def create_superuser(self, email, username, password=None):
        user = self.create_user(
            email=email,
            username=username,
            password=password,
        )
        user.is_active = True
        user.is_admin = True
        user.save(using=self._db)
        self.assign_default_role(user, role_name='admin')
        return user

    def assign_default_role(self, user, role_name='user'):
        role = Role.objects.get(role_name=role_name)
        UserRole.objects.create(user=user, role=role)

    def assign_role(self, user, role_name):
        role = Role.objects.get(role_name=role_name)
        UserRole.objects.create(user=user, role=role)


class User(AbstractBaseUser, PermissionsMixin):
    class Gender(models.TextChoices):
        MALE = 'M', 'Male'
        FEMALE = 'F', 'Female'

    id = models.AutoField(primary_key=True)
    first_name = models.CharField(max_length=100, blank=True, null=True)
    last_name = models.CharField(max_length=100, blank=True, null=True)
    username = models.CharField(max_length=100, unique=True)
    gender = models.CharField(max_length=10, choices=Gender.choices, blank=True, null=True)
    phone = models.CharField(max_length=15, unique=True, blank=True, null=True)
    email = models.EmailField(unique=True)
    avatar = models.CharField(max_length=255, blank=True, null=True)
    dob = models.DateField(blank=True, null=True)
    last_login = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    otp_code = models.CharField(max_length=6, blank=True, null=True)
    otp_expires_at = models.DateTimeField(blank=True, null=True)
    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def __str__(self):
        return self.email

    @property
    def is_staff(self):
        return self.is_admin

    def set_otp(self):
        self.otp_code = ''.join(random.choices(string.digits, k=6))
        self.otp_expires_at = timezone.now() + timedelta(minutes=10)
        self.save()

    def verify_otp(self, otp_code):
        if self.otp_code == otp_code and timezone.now() < self.otp_expires_at:
            self.otp_code = None
            self.otp_expires_at = None
            self.is_verified = True
            self.is_active = True
            self.save()
            return True
        return False

class Role(models.Model):
    id = models.AutoField(primary_key=True)
    role_name = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.role_name

class UserRole(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)

class CategoryType(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255)
    category_image = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

class Category(models.Model):
    id = models.AutoField(primary_key=True)
    category_name = models.CharField(max_length=255)
    category_type = models.ForeignKey(CategoryType, on_delete=models.CASCADE)
    parent = models.ForeignKey('self', on_delete=models.CASCADE, blank=True, null=True)
class Location(models.Model):
    id = models.AutoField(primary_key=True)
    province = models.CharField(max_length=255)
    district = models.CharField(max_length=255)
    commune = models.CharField(max_length=255)
    village = models.CharField(max_length=255)
    postal_code = models.IntegerField()
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='locations')

    def __str__(self):
        return f'{self.village}, {self.commune}, {self.district}, {self.province}'

class Service(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    image = models.CharField(max_length=255, blank=True, null=True)
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    status = models.BooleanField(default=True)
    working_days = models.CharField(max_length=255)
    start_time = models.TimeField()
    end_time = models.TimeField()
    category = models.ForeignKey(Category, on_delete=models.CASCADE)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, related_name='created_services', null=True, blank=True)
    location = models.ForeignKey(Location, on_delete=models.CASCADE, related_name='services')

    def __str__(self):
        return self.name
class Review(models.Model):
    id = models.AutoField(primary_key=True)
    comment = models.TextField()
    rate_star = models.IntegerField()
    created_at = models.DateTimeField(auto_now_add=True)
    service = models.ForeignKey('Service', on_delete=models.CASCADE)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, related_name='created_reviews', null=True, blank=True)
    like_count = models.PositiveIntegerField(default=0)
    unlike_count = models.PositiveIntegerField(default=0)
    def __str__(self):
        return self.comment
class Like(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    review = models.ForeignKey('Review', on_delete=models.CASCADE, related_name='likes')
    like_at = models.DateTimeField(auto_now_add=True)

class Unlike(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    review = models.ForeignKey('Review', on_delete=models.CASCADE, related_name='unlikes')
    unlike_at = models.DateTimeField(auto_now_add=True)

class Report(models.Model):
    id = models.AutoField(primary_key=True)
    description = models.TextField()
    reported_at = models.DateTimeField(auto_now_add=True)
    service = models.ForeignKey(Service, on_delete=models.CASCADE)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, related_name='created_reports', null=True, blank=True)

class Mail(models.Model):
    id = models.AutoField(primary_key=True)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_mails')
    recipient = models.ForeignKey(User, on_delete=models.CASCADE, related_name='received_mails', null=True, blank=True)

def upload_to(instance, filename):
    ext = filename.split('.')[-1]
    filename = f"category_{uuid.uuid4()}.{ext}"
    return os.path.join('uploads/', filename)
class UploadedFile(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    file = models.FileField(upload_to=upload_to)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if not self.id:
            self.id = uuid.uuid4()
        if self.file and not self._state.adding:
            original_extension = os.path.splitext(self.file.name)[1]
            self.file.name = f"category_{self.id}{original_extension}"
        super().save(*args, **kwargs)

    @property
    def filename(self):
        return self.file.name

    @property
    def url(self):
        return self.file.url