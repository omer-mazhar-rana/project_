from rest_framework.permissions import BasePermission

class OnlySuperAdmin(BasePermission):
    def has_permission(self, request, view):
        role = request.user.role.capitalize()
        if request.user.is_authenticated and request.user.is_superuser or role == "Super admin manager":
            return True
        return False

class SuperAdminAccess(BasePermission):
    def has_permission(self, request, view):
        role = request.user.role.capitalize()
        if request.user.is_authenticated and request.user.is_superuser:
            return True
        return False