from functools import wraps
from django.http import JsonResponse
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import AuthenticationFailed

def token_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        auth = JWTAuthentication()
        try:
            user, _ = auth.authenticate(request)
            request.user = user
            return view_func(request, *args, **kwargs)
        except AuthenticationFailed:
            return JsonResponse({'error': 'Unauthorized'}, status=401)
    return wrapper