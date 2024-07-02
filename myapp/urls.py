from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import *

router = DefaultRouter()
router.register(r'users', UserViewSet)
router.register(r'services', ServiceViewSet)
router.register(r'categories', CategoryViewSet)
router.register(r'category-types', CategoryTypeViewSet)
router.register(r'reviews', ReviewViewSet)
router.register(r'likes', LikeViewSet)
router.register(r'unlikes', UnlikeViewSet)
router.register(r'roles', RoleViewSet)
router.register(r'user-roles', UserRoleViewSet)
router.register(r'reports', ReportViewSet)
router.register(r'mails', MailViewSet)
router.register(r'locations', LocationViewSet)

urlpatterns = [
    path('api/', include(router.urls)),
    path('api/register/', UserRegistrationView.as_view(), name='register'),
    path('api/login/', LoginView.as_view(), name='login'),
    path('api/verify-otp/', VerifyOTPView.as_view(), name='verify-otp'),
    path('api/profile/', UserProfileView.as_view(), name='profile'),
]
