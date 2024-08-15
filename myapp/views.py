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
from rest_framework.decorators import action
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.filters import SearchFilter
from django_filters.rest_framework import DjangoFilterBackend
from .filters import ServiceFilter

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
            role_name = request.data.get('role', 'user')  # Default to 'user' if no role is provided
            user = serializer.save(role=role_name)
            try:
                send_mail(
                    'Your OTP Code',
                    f'Your OTP code is {user.otp_code}',
                    settings.DEFAULT_FROM_EMAIL,
                    [user.email],
                )
                return Response({
                    "message": "User created. Check your email for the OTP code.",
                    "status": status.HTTP_201_CREATED,
                    "user": {
                        "username": user.username,
                    },
                    "role": {
                        "role_name": role_name,
                    }
                }, status=status.HTTP_201_CREATED)
            except Exception as e:
                return Response({"message": f"User created but failed to send OTP email: {str(e)}"}, status=status.HTTP_201_CREATED)
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

class UpdateUserRoleView(APIView):
    permission_classes = [IsAuthenticated, IsProvider]  # Only admin can update roles

    def post(self, request):
        user_id = request.data.get('user_id')
        role_name = request.data.get('role_name')

        try:
            user = User.objects.get(id=user_id)
            role = Role.objects.get(role_name=role_name)
            user_details = UserSerializer(user).data
            # Ensure no duplicate UserRole entries
            user_roles = UserRole.objects.filter(user=user)
            if user_roles.count() > 1:
                user_roles.delete()  # Remove all existing roles for the user
            
            # Update or create the UserRole
            user_role, created = UserRole.objects.update_or_create(user=user, defaults={'role': role})

            return Response({
                "message": "User role updated successfully.",
                "user": {
                    "username": user.username,
                    "email": user.email
                },
                "role": {
                    "role_name": role.role_name,
                }
            }, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"error": "User does not exist."}, status=status.HTTP_404_NOT_FOUND)
        except Role.DoesNotExist:
            return Response({"error": f"Role '{role_name}' does not exist."}, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        user = authenticate(request, email=email, password=password)

        if user is not None:
            refresh = RefreshToken.for_user(user)
            role = UserRole.objects.filter(user=user).first().role
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'status': '200',
                'user': {
                    'username': user.username,
                    'id': user.id,
                },
                'role': {
                    'role_name': role.role_name,
                }
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
                        'status': '200',
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
        if self.action == 'create':
            self.permission_classes = [IsAuthenticated, IsAdmin]
        else:
            self.permission_classes = [IsAuthenticated]
        return super(CategoryTypeViewSet, self).get_permissions()

class CategoryViewSet(viewsets.ModelViewSet):
    queryset = Category.objects.all()
    serializer_class = CategorySerializer
    permission_classes = [IsAuthenticated,IsProvider]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response({
            "message": "Category created successfully", 
            "data": serializer.data,
            "status": "201"
            }, status=status.HTTP_201_CREATED, headers=headers)
class ServiceViewSet(viewsets.ModelViewSet):
    queryset = Service.objects.all()
    filter_backends = [DjangoFilterBackend, SearchFilter]
    filterset_class = ServiceFilter
    search_fields = ['name', 'description', 'category__category_name', 'location__province']

    def get_serializer_class(self):
        if self.action == 'list':
            return ServiceListSerializer
        return ServiceSerializer

    def get_queryset(self):
        if self.action == 'list':
            return Service.objects.all()
        return Service.objects.filter(created_by=self.request.user)

    def get_permissions(self):
        if self.action in ['create', 'update', 'partial_update', 'destroy']:
            self.permission_classes = [IsAuthenticated]
            if self.action == 'create':
                self.permission_classes += [IsProvider]
            elif self.action in ['update', 'partial_update']:
                self.permission_classes += [IsProvider]
            elif self.action == 'destroy':
                self.permission_classes += [IsAdmin]
        elif self.action in ['retrieve']:
            self.permission_classes = [IsAuthenticated]
        elif self.action == 'list':
            self.permission_classes = [IsAuthenticatedOrReadOnly]
        return super(ServiceViewSet, self).get_permissions()

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        serializer = self.get_serializer(queryset, many=True)
        return Response({
            "message": "List of all services.",
            "data": serializer.data
        }, status=status.HTTP_200_OK)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response({
            "message": "Service created successfully", 
            "data": serializer.data,
            "status": "201"
        }, status=status.HTTP_201_CREATED, headers=headers)

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(serializer.data)

    def perform_update(self, serializer):
        serializer.save()

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response({"message": "Service deleted successfully"}, status=status.HTTP_204_NO_CONTENT)

    def perform_destroy(self, instance):
        instance.delete()

    @action(detail=False, methods=['get'], permission_classes=[IsAuthenticated])
    def my_services(self, request):
        user_services = Service.objects.filter(created_by=request.user)
        serializer = self.get_serializer(user_services, many=True)
        if user_services.exists():
            return Response({
                "message": "Here are your services.",
                "data": serializer.data
            })
        else:
            return Response({
                "message": "You have no services.",
                "data": []
            }, status=status.HTTP_200_OK)
    @action(detail=True, methods=['get'], url_path='id', permission_classes=[AllowAny])
    def find_by_uuid(self, request, pk=None):
        try:
            service = Service.objects.get(id=pk)
        except ValueError:
            return Response({"message": "Service not found"}, status=status.HTTP_404_NOT_FOUND)
        except Service.DoesNotExist:
            return Response({"message": "Service not found"}, status=status.HTTP_404_NOT_FOUND)
        serializer = self.get_serializer(service)
        return Response({"message": "Service found.", "data": serializer.data}, status=status.HTTP_200_OK)

class ReviewViewSet(viewsets.ModelViewSet):
    queryset = Review.objects.all()
    serializer_class = ReviewSerializer
    permission_classes = [IsAuthenticated]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response({
            "message": "Review created successfully",
            "data": serializer.data,
            "status": "201"
            }, status=status.HTTP_201_CREATED, headers=headers)

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)

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

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response({"message": "Like created successfully", "data": serializer.data}, status=status.HTTP_201_CREATED, headers=headers)

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

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response({"message": "Unlike created successfully", "data": serializer.data}, status=status.HTTP_201_CREATED, headers=headers)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response({"message": "Unlike deleted successfully"}, status=status.HTTP_204_NO_CONTENT)

    def perform_destroy(self, instance):
        instance.delete()

import logging

logger = logging.getLogger(__name__)

class LocationViewSet(viewsets.ModelViewSet):
    serializer_class = LocationSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        logger.debug(f"Authenticated user: {user}")

        # Fetch locations created by the authenticated user
        locations = Location.objects.filter(created_by=user).distinct()
        
        logger.debug(f"Locations queryset: {locations.query}")
        
        return locations

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        logger.debug(f"Location created: {serializer.data}")
        return Response({
            "message": "Location created successfully", 
            "data": serializer.data,
            "status": "201"
        }, status=status.HTTP_201_CREATED, headers=headers)

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        logger.debug(f"Location updated: {serializer.data}")
        return Response({
            "message": "Location updated successfully",
            "data": serializer.data
        }, status=status.HTTP_200_OK)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        logger.debug(f"Location deleted: {instance}")
        return Response({
            "message": "Location deleted successfully"
        }, status=status.HTTP_204_NO_CONTENT)

    def perform_destroy(self, instance):
        instance.delete()
class ReportViewSet(viewsets.ModelViewSet):
    queryset = Report.objects.all()
    serializer_class = ReportSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Report.objects.filter(created_by=self.request.user)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response({"message": "Report created successfully", 
                         "data": serializer.data,
                            "status": "201"
                         }, status=status.HTTP_201_CREATED, headers=headers)

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)

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
        return Mail.objects.filter(recipient=self.request.user) | Mail.objects.filter(sender=self.request.user)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response({"message": "Mail created successfully", "data": serializer.data}, status=status.HTTP_201_CREATED, headers=headers)

    def perform_create(self, serializer):
        serializer.save(sender=self.request.user)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response({"message": "Mail deleted successfully"}, status=status.HTTP_204_NO_CONTENT)

    def perform_destroy(self, instance):
        instance.delete()

class FileUploadView(viewsets.ModelViewSet):
    queryset = UploadedFile.objects.all()
    serializer_class = UploadedFileSerializer
    parser_classes = [MultiPartParser, FormParser]
    permission_classes = [AllowAny]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            response_data = serializer.data
            return Response(response_data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)    


    def create(self, request, *args, **kwargs):
        data = request.data
        data['user'] = request.user.id
        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        return Response({"message": "Social media link created successfully.", "data": serializer.data}, status=status.HTTP_201_CREATED)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response({"message": "Social media link updated successfully.", "data": serializer.data}, status=status.HTTP_200_OK)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response({"message": "Social media link deleted successfully."}, status=status.HTTP_200_OK) 