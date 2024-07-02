from rest_framework import serializers
from .models import User, Role, UserRole, CategoryType, Category, Service, Review, Like, Unlike, Report, Mail, Location
class UserRegistrationSerializer(serializers.ModelSerializer):
    confirmPassword = serializers.CharField(style={'input_type': 'password'}, write_only=True)

    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'password', 'confirmPassword')
        extra_kwargs = {'password': {'write_only': True}}

    def validate(self, data):
        errors = {}
        if data['password'] != data['confirmPassword']:
            errors['password'] = "Passwords do not match."

        existing_user_by_email = User.objects.filter(email=data['email']).first()
        existing_user_by_username = User.objects.filter(username=data['username']).first()

        if existing_user_by_email:
            if not existing_user_by_email.is_active:
                errors['message'] = "Your account has been created. Please check and verify your email address."
            else:
                errors['email'] = "User with this email already exists."
        if existing_user_by_username:
            if not existing_user_by_username.is_active:
                errors['message'] = "Your account has been created. Please check and verify your email address."
            else:
                errors['username'] = "User with this username already exists."

        if errors:
            raise serializers.ValidationError(errors)
        return data

    def create(self, validated_data):
        validated_data.pop('confirmPassword')
        user = User.objects.create_user(
            email=validated_data['email'],
            username=validated_data['username'],
            password=validated_data['password']
        )
        user.set_otp()
        return user
# class UserRegistrationSerializer(serializers.ModelSerializer):
#     confirmPassword = serializers.CharField(style={'input_type': 'password'}, write_only=True)

#     class Meta:
#         model = User
#         fields = ('id', 'username', 'email', 'password', 'confirmPassword')
#         extra_kwargs = {'password': {'write_only': True}}

#     def validate(self, data):
#         errors = {}
#         if data['password'] != data['confirmPassword']:
#             errors['password'] = "Passwords do not match."

#         existing_user_by_email = User.objects.filter(email=data['email']).first()
#         existing_user_by_username = User.objects.filter(username=data['username']).first()

#         if existing_user_by_email:
#             if not existing_user_by_email.is_active:
#                 errors['message'] = "Your account has been created. Please check and verify your email address."
#             else:
#                 errors['email'] = "User with this email already exists."
#         if existing_user_by_username:
#             if not existing_user_by_username.is_active:
#                 errors['message'] = "Your account has been created. Please check and verify your email address."
#             else:
#                 errors['username'] = "User with this username already exists."

#         if errors:
#             raise serializers.ValidationError(errors)
#         print(data)
#         return data

#     def create(self, validated_data):
#         validated_data.pop('confirmPassword')
#         user = User.objects.create_user(
#             email=validated_data['email'],
#             username=validated_data['username'],
#             password=validated_data['password']
#         )
#         user.set_otp()
#         return user
class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'gender', 'phone', 'email', 'avatar', 'dob', 'created_at', 'updated_at']
        extra_kwargs = {
            'email': {'read_only': True}  # Prevent email from being updated
        }
    def validate_username(self, value):
        if not value.isalnum():
            raise serializers.ValidationError("Username should only contain alphanumeric characters.")
        return value       
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'
class OTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp_code = serializers.CharField(max_length=6)

class RoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Role
        fields = '__all__'

class UserRoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserRole
        fields = '__all__'

class CategoryTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = CategoryType
        fields = '__all__'

class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = '__all__'

class ServiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Service
        fields = '__all__'

    def validate(self, data):
        if not CategoryType.objects.filter(id=data['category'].category_type.id).exists():
            raise serializers.ValidationError("Category Type does not exist.")
        return data

    def create(self, validated_data):
        service = super().create(validated_data)
        service.save()
        return service

    def update(self, instance, validated_data):
        instance = super().update(instance, validated_data)
        instance.save()
        return instance

class ReviewSerializer(serializers.ModelSerializer):
    class Meta:
        model = Review
        fields = '__all__'

class LikeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Like
        fields = '__all__'

class UnlikeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Unlike
        fields = '__all__'

class ReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = Report
        fields = '__all__'

class MailSerializer(serializers.ModelSerializer):
    class Meta:
        model = Mail
        fields = '__all__'

class LocationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Location
        fields = '__all__'
