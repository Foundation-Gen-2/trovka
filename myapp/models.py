from django.db import models

class User(models.Model):
    id = models.AutoField(primary_key=True)
    firstname = models.CharField(max_length=100)
    lastname = models.CharField(max_length=100)
    username = models.CharField(max_length=100, unique=True)
    gender = models.CharField(max_length=10)
    phone = models.IntegerField(unique=True)
    email = models.EmailField(unique=True)
    avatar = models.CharField(max_length=255, blank=True, null=True)
    dob = models.DateField()
    last_login = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)
    verification_code = models.IntegerField(blank=True, null=True)
    is_verified = models.BooleanField(default=False)
    is_enabled = models.BooleanField(default=True)

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
    category = models.ForeignKey('Category', on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)

class Category(models.Model):
    id = models.AutoField(primary_key=True)
    category_name = models.CharField(max_length=255)
    category_type = models.CharField(max_length=255)
    category_image = models.CharField(max_length=255, blank=True, null=True)
    parent = models.ForeignKey('self', on_delete=models.CASCADE, blank=True, null=True)

class Review(models.Model):
    id = models.AutoField(primary_key=True)
    comment = models.TextField()
    rate_star = models.IntegerField()
    created_at = models.DateTimeField(auto_now_add=True)
    service = models.ForeignKey(Service, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)

class Like(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    review = models.ForeignKey(Review, on_delete=models.CASCADE)
    like_at = models.DateTimeField(auto_now_add=True)

class Unlike(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    review = models.ForeignKey(Review, on_delete=models.CASCADE)
    unlike_at = models.DateTimeField(auto_now_add=True)

class Role(models.Model):
    id = models.AutoField(primary_key=True)
    role_name = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

class UserRole(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)

class Report(models.Model):
    id = models.AutoField(primary_key=True)
    description = models.TextField()
    reported_at = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    service = models.ForeignKey(Service, on_delete=models.CASCADE)

class Mail(models.Model):
    id = models.AutoField(primary_key=True)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='received_mails')
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_mails')

class Location(models.Model):
    id = models.AutoField(primary_key=True)
    province = models.CharField(max_length=255)
    district = models.CharField(max_length=255)
    commune = models.CharField(max_length=255)
    village = models.CharField(max_length=255)
    postal_code = models.IntegerField()
    service = models.ForeignKey(Service, on_delete=models.CASCADE)
