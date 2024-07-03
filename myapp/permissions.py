from rest_framework.permissions import BasePermission
from .models import UserRole

class IsProvider(BasePermission):
    def has_permission(self, request, view):
        return UserRole.objects.filter(user=request.user, role__role_name='provider').exists()

class IsUser(BasePermission):
    def has_permission(self, request, view):
        return UserRole.objects.filter(user=request.user, role__role_name='user').exists()

class IsAdmin(BasePermission):
    def has_permission(self, request, view):
        return UserRole.objects.filter(user=request.user, role__role_name='admin').exists()

class IsProviderOrAdmin(BasePermission):
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        return UserRole.objects.filter(user=request.user, role__role_name__in=['provider', 'admin']).exists()
