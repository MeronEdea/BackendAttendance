import socket
from django.utils import timezone
from .models import ActivityLog

def log_activity(name, action, resource, details, ip_address, status_code):
    timestamp = timezone.now()
    ActivityLog.objects.create(
        name=name,
        action=action,
        resource=resource,
        details=details,
        ip_address=ip_address,
        status_code=status_code,
        timestamp=timestamp
    )

def get_client_ip(request):
    # Get client's IP address
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip
