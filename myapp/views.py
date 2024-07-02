from rest_framework import viewsets, permissions
from .models import *
from .serializers import *
from rest_framework.permissions import IsAuthenticated, IsAdminUser, AllowAny,IsAuthenticatedOrReadOnly
from rest_framework.views import APIView
from rest_framework.response import Response
from django.conf import settings
from django.core.mail import send_mail,BadHeaderError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed, NotAuthenticated
from django.contrib.auth import authenticate
from .permissions import IsProvider, IsAdmin, IsUser
from .permissions import IsProviderOrAdmin

# class UserRegistrationView(APIView):
#     permission_classes = [AllowAny]

#     def post(self, request):
#         serializer = UserRegistrationSerializer(data=request.data)
#         if serializer.is_valid():
#             user = serializer.save()
#             try:
#                 role = Role.objects.get(name='user')
#                 user.role = role
#                 user.save()
#                 try:
#                     send_mail(
#                         'Your OTP Code',
#                         f'Your OTP code is {user.otp_code}',
#                         settings.DEFAULT_FROM_EMAIL,
#                         [user.email],
#                     )
#                     return Response({"message": "User created. Check your email for the OTP code."}, status=status.HTTP_201_CREATED)
#                 except Exception as e:
#                     return Response({"message": f"User created but failed to send OTP email: {str(e)}"}, status=status.HTTP_201_CREATED)
#             except Role.DoesNotExist:
#                 return Response({"error": "Role 'user' does not exist."}, status=status.HTTP_400_BAD_REQUEST)
#         else:
#             errors = serializer.errors
#             print(errors)
#             conflict_fields = [
#                 {"field": field, "error": error[0]} for field, error in errors.items() if error[0].code == 'unique'
#             ]
#             field_requies = [
#                 {"field": field, "error": error[0]} for field, error in errors.items() if error[0].code == 'required'
#             ]
#             other_errors = [
#                 {"field": field, "error": error[0]} for field, error in errors.items() if error[0].code != 'unique'
#             ]

#             if conflict_fields:
#                 return Response(
#                     {
#                         "message": "Your account already exists. Failed to create a new account.",
#                         "status": 409,
#                         "errors": conflict_fields
#                     },
#                     status=status.HTTP_409_CONFLICT
#                 )

#             return Response(
#                 {
#                     "message": "Validation errors occurred.",
#                     "status": 400,
#                     "errors": field_requies
#                 },
#                 status=status.HTTP_400_BAD_REQUEST
#             )
class UserRegistrationView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            try:
                role = Role.objects.get(role_name='user')
                UserRole.objects.create(user=user, role=role)
                try:
                    send_mail(
                        'Your OTP Code',
                        f'Your OTP code is {user.otp_code}',
                        settings.DEFAULT_FROM_EMAIL,
                        [user.email],
                    )
                    return Response({"message": "User created. Check your email for the OTP code."}, status=status.HTTP_201_CREATED)
                except Exception as e:
                    return Response({"message": f"User created but failed to send OTP email: {str(e)}"}, status=status.HTTP_201_CREATED)
            except Role.DoesNotExist:
                return Response({"error": "Role 'user' does not exist."}, status=status.HTTP_400_BAD_REQUEST)
        else:
            errors = serializer.errors
            conflict_fields = [
                {"field": field, "error": error[0]} for field, error in errors.items() if error[0].code == 'unique'
            ]
            field_requires = [
                {"field": field, "error": error[0]} for field, error in errors.items() if error[0].code == 'required'
            ]
            other_errors = [
                {"field": field, "error": error[0]} for field, error in errors.items() if error[0].code != 'unique'
            ]

            if conflict_fields:
                return Response(
                    {
                        "message": "Your account already exists. Failed to create a new account.",
                        "status": 409,
                        "errors": conflict_fields
                    },
                    status=status.HTTP_409_CONFLICT
                )

            return Response(
                {
                    "message": "Validation errors occurred.",
                    "status": 400,
                    "errors": field_requires
                },
                status=status.HTTP_400_BAD_REQUEST
            )
class LoginView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        user = authenticate(request, email=email, password=password)

        if user is not None:
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            })
        return Response({"message": "Invalid email or password"}, status=status.HTTP_401_UNAUTHORIZED)
class VerifyOTPView(APIView):
    permission_classes = [AllowAny]

    # @swagger_auto_schema(request_body=OTPSerializer, responses={200: 'Email verified successfully.'})
    def post(self, request):
        serializer = OTPSerializer(data=request.data)
        if serializer.is_valid():
            try:
                user = User.objects.get(email=serializer.validated_data['email'])
                if user.verify_otp(serializer.validated_data['otp_code']):
                    refresh = RefreshToken.for_user(user)
                    return Response({
                        'message': 'Email verified successfully.',
                    }, status=status.HTTP_200_OK)
                return Response({"error": "Invalid OTP code."}, status=status.HTTP_400_BAD_REQUEST)
            except User.DoesNotExist:
                return Response({"error": "Invalid email or OTP code."}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]

    # @swagger_auto_schema(responses={200: UserProfileSerializer})
    def get(self, request):
        user = request.user
        serializer = UserProfileSerializer(user)
        return Response(serializer.data)

    # @swagger_auto_schema(request_body=UserProfileSerializer, responses={200: UserProfileSerializer})
    def put(self, request):
        user = request.user
        serializer = UserProfileSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "message": "Profile updated successfully",
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]
class RoleViewSet(viewsets.ModelViewSet):
    queryset = Role.objects.all()
    serializer_class = RoleSerializer
    permission_classes = [IsAuthenticated]

class UserRoleViewSet(viewsets.ModelViewSet):
    queryset = UserRole.objects.all()
    serializer_class = UserRoleSerializer
    permission_classes = [IsAuthenticated]
class CategoryTypeViewSet(viewsets.ModelViewSet):
    queryset = CategoryType.objects.all()
    serializer_class = CategoryTypeSerializer

    def get_permissions(self):
        if self.action in ['create']:
            self.permission_classes = [IsAuthenticated, IsProviderOrAdmin]
        else:
            self.permission_classes = [IsAuthenticated]
        return super(CategoryTypeViewSet, self).get_permissions()

class CategoryViewSet(viewsets.ModelViewSet):
    queryset = Category.objects.all()
    serializer_class = CategorySerializer
    permission_classes = [IsAuthenticated]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response({"message": "Category created successfully", "data": serializer.data}, status=status.HTTP_201_CREATED, headers=headers)

class ServiceViewSet(viewsets.ModelViewSet):
    queryset = Service.objects.all()
    serializer_class = ServiceSerializer

    def get_queryset(self):
        return Service.objects.filter(user=self.request.user)

    def get_permissions(self):
        if self.action in ['create', 'update', 'partial_update']:
            self.permission_classes = [IsAuthenticated, IsProvider]
        elif self.action in ['destroy']:
            self.permission_classes = [IsAuthenticated, IsAdmin]
        elif self.action in ['list', 'retrieve']:
            self.permission_classes = [IsAuthenticated]
        return super(ServiceViewSet, self).get_permissions()

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response({"message": "Service created successfully", "data": serializer.data}, status=status.HTTP_201_CREATED, headers=headers)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response({"message": "Service deleted successfully"}, status=status.HTTP_204_NO_CONTENT)

    def perform_destroy(self, instance):
        instance.delete()

class ReviewViewSet(viewsets.ModelViewSet):
    queryset = Review.objects.all()
    serializer_class = ReviewSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Review.objects.filter(user=self.request.user)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response({"message": "Review created successfully", "data": serializer.data}, status=status.HTTP_201_CREATED, headers=headers)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response({"message": "Review deleted successfully"}, status=status.HTTP_204_NO_CONTENT)

    def perform_destroy(self, instance):
        instance.delete()

class LikeViewSet(viewsets.ModelViewSet):
    queryset = Like.objects.all()
    serializer_class = LikeSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Like.objects.filter(user=self.request.user)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response({"message": "Like created successfully", "data": serializer.data}, status=status.HTTP_201_CREATED, headers=headers)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response({"message": "Like deleted successfully"}, status=status.HTTP_204_NO_CONTENT)

    def perform_destroy(self, instance):
        instance.delete()

class UnlikeViewSet(viewsets.ModelViewSet):
    queryset = Unlike.objects.all()
    serializer_class = UnlikeSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Unlike.objects.filter(user=self.request.user)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response({"message": "Unlike created successfully", "data": serializer.data}, status=status.HTTP_201_CREATED, headers=headers)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response({"message": "Unlike deleted successfully"}, status=status.HTTP_204_NO_CONTENT)

    def perform_destroy(self, instance):
        instance.delete()

class ReportViewSet(viewsets.ModelViewSet):
    queryset = Report.objects.all()
    serializer_class = ReportSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Report.objects.filter(user=self.request.user)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response({"message": "Report created successfully", "data": serializer.data}, status=status.HTTP_201_CREATED, headers=headers)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response({"message": "Report deleted successfully"}, status=status.HTTP_204_NO_CONTENT)

    def perform_destroy(self, instance):
        instance.delete()

class MailViewSet(viewsets.ModelViewSet):
    queryset = Mail.objects.all()
    serializer_class = MailSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Mail.objects.filter(user=self.request.user) | Mail.objects.filter(sender=self.request.user)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response({"message": "Mail created successfully", "data": serializer.data}, status=status.HTTP_201_CREATED, headers=headers)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response({"message": "Mail deleted successfully"}, status=status.HTTP_204_NO_CONTENT)

    def perform_destroy(self, instance):
        instance.delete()

class LocationViewSet(viewsets.ModelViewSet):
    queryset = Location.objects.all()
    serializer_class = LocationSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Location.objects.filter(service__user=self.request.user)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response({"message": "Location created successfully", "data": serializer.data}, status=status.HTTP_201_CREATED, headers=headers)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response({"message": "Location deleted successfully"}, status=status.HTTP_204_NO_CONTENT)

    def perform_destroy(self, instance):
        instance.delete()    
# class CategoryTypeViewSet(viewsets.ModelViewSet):
#     queryset = CategoryType.objects.all()
#     serializer_class = CategoryTypeSerializer

#     def get_permissions(self):
#         if self.action in ['create']:
#             self.permission_classes = [IsAuthenticated, IsProviderOrAdmin]
#         else:
#             self.permission_classes = [IsAuthenticated]
#         return super(CategoryTypeViewSet, self).get_permissions()

# class CategoryViewSet(viewsets.ModelViewSet):
#     queryset = Category.objects.all()
#     serializer_class = CategorySerializer
#     permission_classes = [IsAuthenticated]

#     def create(self, request, *args, **kwargs):
#         serializer = self.get_serializer(data=request.data)
#         serializer.is_valid(raise_exception=True)
#         self.perform_create(serializer)
#         headers = self.get_success_headers(serializer.data)
#         return Response({"message": "Category created successfully", "data": serializer.data}, status=status.HTTP_201_CREATED, headers=headers)

# class ServiceViewSet(viewsets.ModelViewSet):
#     queryset = Service.objects.all()
#     serializer_class = ServiceSerializer

#     def get_permissions(self):
#         if self.action in ['create', 'update', 'partial_update']:
#             self.permission_classes = [IsAuthenticated, IsProvider]
#         elif self.action in ['destroy']:
#             self.permission_classes = [IsAuthenticated, IsAdmin]
#         elif self.action in ['list', 'retrieve']:
#             self.permission_classes = [IsAuthenticated]
#         return super(ServiceViewSet, self).get_permissions()

#     def create(self, request, *args, **kwargs):
#         serializer = self.get_serializer(data=request.data)
#         serializer.is_valid(raise_exception=True)
#         self.perform_create(serializer)
#         headers = self.get_success_headers(serializer.data)
#         return Response({"message": "Service created successfully", "data": serializer.data}, status=status.HTTP_201_CREATED, headers=headers)

#     def perform_create(self, serializer):
#         serializer.save(user=self.request.user)


# class ReviewViewSet(viewsets.ModelViewSet):
#     serializer_class = ReviewSerializer
#     permission_classes = [IsAuthenticated]

#     def get_queryset(self):
#         return Review.objects.filter(user=self.request.user)

#     def create(self, request, *args, **kwargs):
#         serializer = self.get_serializer(data=request.data)
#         serializer.is_valid(raise_exception=True)
#         self.perform_create(serializer)
#         headers = self.get_success_headers(serializer.data)
#         return Response({"message": "Review created successfully", "data": serializer.data}, status=status.HTTP_201_CREATED, headers=headers)

#     def perform_create(self, serializer):
#         serializer.save(user=self.request.user)

#     def destroy(self, request, *args, **kwargs):
#         instance = self.get_object()
#         self.perform_destroy(instance)
#         return Response({"message": "Review deleted successfully"}, status=status.HTTP_204_NO_CONTENT)

#     def perform_destroy(self, instance):
#         instance.delete()

# class LikeViewSet(viewsets.ModelViewSet):
#     serializer_class = LikeSerializer
#     permission_classes = [IsAuthenticated]

#     def get_queryset(self):
#         return Like.objects.filter(user=self.request.user)

#     def create(self, request, *args, **kwargs):
#         serializer = self.get_serializer(data=request.data)
#         serializer.is_valid(raise_exception=True)
#         self.perform_create(serializer)
#         headers = self.get_success_headers(serializer.data)
#         return Response({"message": "Like created successfully", "data": serializer.data}, status=status.HTTP_201_CREATED, headers=headers)

#     def perform_create(self, serializer):
#         serializer.save(user=self.request.user)

#     def destroy(self, request, *args, **kwargs):
#         instance = self.get_object()
#         self.perform_destroy(instance)
#         return Response({"message": "Like deleted successfully"}, status=status.HTTP_204_NO_CONTENT)

#     def perform_destroy(self, instance):
#         instance.delete()

# class UnlikeViewSet(viewsets.ModelViewSet):
#     serializer_class = UnlikeSerializer
#     permission_classes = [IsAuthenticated]

#     def get_queryset(self):
#         return Unlike.objects.filter(user=self.request.user)

#     def create(self, request, *args, **kwargs):
#         serializer = self.get_serializer(data=request.data)
#         serializer.is_valid(raise_exception=True)
#         self.perform_create(serializer)
#         headers = self.get_success_headers(serializer.data)
#         return Response({"message": "Unlike created successfully", "data": serializer.data}, status=status.HTTP_201_CREATED, headers=headers)

#     def perform_create(self, serializer):
#         serializer.save(user=self.request.user)

#     def destroy(self, request, *args, **kwargs):
#         instance = self.get_object()
#         self.perform_destroy(instance)
#         return Response({"message": "Unlike deleted successfully"}, status=status.HTTP_204_NO_CONTENT)

#     def perform_destroy(self, instance):
#         instance.delete()

# class ReportViewSet(viewsets.ModelViewSet):
#     serializer_class = ReportSerializer
#     permission_classes = [IsAuthenticated]

#     def get_queryset(self):
#         return Report.objects.filter(user=self.request.user)

#     def create(self, request, *args, **kwargs):
#         serializer = self.get_serializer(data=request.data)
#         serializer.is_valid(raise_exception=True)
#         self.perform_create(serializer)
#         headers = self.get_success_headers(serializer.data)
#         return Response({"message": "Report created successfully", "data": serializer.data}, status=status.HTTP_201_CREATED, headers=headers)

#     def perform_create(self, serializer):
#         serializer.save(user=self.request.user)

#     def destroy(self, request, *args, **kwargs):
#         instance = self.get_object()
#         self.perform_destroy(instance)
#         return Response({"message": "Report deleted successfully"}, status=status.HTTP_204_NO_CONTENT)

#     def perform_destroy(self, instance):
#         instance.delete()

# class MailViewSet(viewsets.ModelViewSet):
#     serializer_class = MailSerializer
#     permission_classes = [IsAuthenticated]

#     def get_queryset(self):
#         return Mail.objects.filter(user=self.request.user) | Mail.objects.filter(sender=self.request.user)

#     def create(self, request, *args, **kwargs):
#         serializer = self.get_serializer(data=request.data)
#         serializer.is_valid(raise_exception=True)
#         self.perform_create(serializer)
#         headers = self.get_success_headers(serializer.data)
#         return Response({"message": "Mail created successfully", "data": serializer.data}, status=status.HTTP_201_CREATED, headers=headers)

#     def perform_create(self, serializer):
#         serializer.save(user=self.request.user)

#     def destroy(self, request, *args, **kwargs):
#         instance = self.get_object()
#         self.perform_destroy(instance)
#         return Response({"message": "Mail deleted successfully"}, status=status.HTTP_204_NO_CONTENT)

#     def perform_destroy(self, instance):
#         instance.delete()

# class LocationViewSet(viewsets.ModelViewSet):
#     serializer_class = LocationSerializer
#     permission_classes = [IsAuthenticated]

#     def get_queryset(self):
#         return Location.objects.filter(service__user=self.request.user)

#     def create(self, request, *args, **kwargs):
#         serializer = self.get_serializer(data=request.data)
#         serializer.is_valid(raise_exception=True)
#         self.perform_create(serializer)
#         headers = self.get_success_headers(serializer.data)
#         return Response({"message": "Location created successfully", "data": serializer.data}, status=status.HTTP_201_CREATED, headers=headers)

#     def perform_create(self, serializer):
#         serializer.save(user=self.request.user)

#     def destroy(self, request, *args, **kwargs):
#         instance = self.get_object()
#         self.perform_destroy(instance)
#         return Response({"message": "Location deleted successfully"}, status=status.HTTP_204_NO_CONTENT)

#     def perform_destroy(self, instance):
#         instance.delete()