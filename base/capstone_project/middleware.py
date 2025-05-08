from django.shortcuts import redirect
from django.urls import reverse

class EnsureNotAuthenticatedMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        protected_paths = [
            '/dashboard/', '/manage-pending-users/', '/analytics-form/',
            '/analytics-view/', '/approve-user/', '/reject-user/',
            '/promote-user/', '/demote-user/', '/delete-user/'
        ]
        if any(request.path.startswith(path) for path in protected_paths) and not request.user.is_authenticated:
            response = redirect(reverse('sign_in'))
            response['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            response['Pragma'] = 'no-cache'
            response['Expires'] = '0'
            return response
        response = self.get_response(request)
        return response