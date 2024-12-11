from rest_framework.permissions import BasePermission

class BlacklistPermission(BasePermission):
    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False
        if request.user.blacklist:
            return False

        return True
    
class AllowAdmin(BasePermission):
    def has_permission(self, request, view):
        role = request.user.role
        roles = {"clinic", 'manager'}
        if request.user.is_authenticated and role.lower() in roles and not request.user.blacklist:
            return True
        return False