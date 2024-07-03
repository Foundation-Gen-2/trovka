from rest_framework import serializers
from .models import User, Role, UserRole, CategoryType, Category, Service, Review, Like, Unlike, Report, Mail, Location, UploadedFile
import django_filters

class UserSimpleSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username']
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
class LocationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Location
        fields = '__all__'

class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = '__all__'
class ServiceListSerializer(serializers.ModelSerializer):
    created_by = UserSimpleSerializer(read_only=True)
    created_by = serializers.CharField(source='created_by.username', read_only=True)
    # category = CategorySerializer(read_only=True)
    category = serializers.CharField(source='category.category_name', read_only=True)
    # location = serializers.SlugRelatedField(slug_field='id', queryset=Location.objects.all())
    location = LocationSerializer(read_only=True)
    class Meta:
        model = Service
        fields = '__all__'
        read_only_fields = ['created_by']
class ServiceSerializer(serializers.ModelSerializer):
    created_by = serializers.CharField(source='created_by.username', read_only=True)
    location = serializers.PrimaryKeyRelatedField(queryset=Location.objects.all())

    class Meta:
        model = Service
        fields = '__all__'
        read_only_fields = ['created_by']

    def validate(self, data):
        if 'category' not in data:
            raise serializers.ValidationError("Category field is required.")
        
        if not CategoryType.objects.filter(id=data['category'].category_type.id).exists():
            raise serializers.ValidationError("Category Type does not exist.")
        return data

    def create(self, validated_data):
        validated_data['created_by'] = self.context['request'].user
        return super().create(validated_data)

    def update(self, instance, validated_data):
        instance = super().update(instance, validated_data)
        return instance      
# class ServiceSerializer(serializers.ModelSerializer):
#     created_by = UserSimpleSerializer(read_only=True)
#     created_by = serializers.CharField(source='created_by.username', read_only=True)
#     location = serializers.SlugRelatedField(slug_field='id', queryset=Location.objects.all())

#     class Meta:
#         model = Service
#         fields = '__all__'
#         read_only_fields = ['created_by']

#     def validate(self, data):
#         if not CategoryType.objects.filter(id=data['category'].category_type.id).exists():
#             raise serializers.ValidationError("Category Type does not exist.")
#         return data

#     def create(self, validated_data):
#         request = self.context.get('request', None)
#         if request and request.user:
#             validated_data['created_by'] = request.user
#         service = super().create(validated_data)
#         service.save()
#         return service

#     def update(self, instance, validated_data):
#         instance = super().update(instance, validated_data)
#         instance.save()
#         return instance

class ReviewSerializer(serializers.ModelSerializer):
    created_by = serializers.CharField(source='created_by.username', read_only=True)
    like_count = serializers.ReadOnlyField()
    unlike_count = serializers.ReadOnlyField()

    class Meta:
        model = Review
        fields = '__all__'
        read_only_fields = ['created_by', 'like_count', 'unlike_count']

class LikeSerializer(serializers.ModelSerializer):
    user = serializers.CharField(source='user.username', read_only=True)

    class Meta:
        model = Like
        fields = '__all__'
        read_only_fields = ['user']

class UnlikeSerializer(serializers.ModelSerializer):
    user = serializers.CharField(source='user.username', read_only=True)

    class Meta:
        model = Unlike
        fields = '__all__'
        read_only_fields = ['user']

class ReportSerializer(serializers.ModelSerializer):
    created_by = serializers.CharField(source='created_by.username', read_only=True)

    class Meta:
        model = Report
        fields = '__all__'
        read_only_fields = ['created_by']

class MailSerializer(serializers.ModelSerializer):
    sender = serializers.CharField(source='sender.username', read_only=True)
    recipient = serializers.CharField(source='recipient.username', read_only=True)

    class Meta:
        model = Mail
        fields = '__all__'
        read_only_fields = ['sender', 'recipient']
        
class UploadedFileSerializer(serializers.ModelSerializer):
    url = serializers.SerializerMethodField()

    class Meta:
        model = UploadedFile
        fields = ('id', 'file', 'uploaded_at', 'url')

    def get_url(self, obj):
        request = self.context.get('request')
        return request.build_absolute_uri(obj.file.url)

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation['file'] = instance.file.name.split('/')[-1]  # Keep only the filename
        return representation
class ServiceFilter(django_filters.FilterSet):
    category_type = django_filters.CharFilter(field_name='category__category_type__name', lookup_expr='icontains')
    category = django_filters.CharFilter(field_name='category__name', lookup_expr='icontains')
    name = django_filters.CharFilter(field_name='name', lookup_expr='icontains')
    location = django_filters.CharFilter(field_name='location__name', lookup_expr='icontains')

    class Meta:
        model = Service
        fields = ['category_type', 'category', 'name', 'location']    