# admin_seeder.py

import os
import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "BackendAttendance.settings")
django.setup()

from Attendance.models import CustomUser

def create_admin():
    # Check if the admin user already exists
    if not CustomUser.objects.filter(email='admin@admin.com').exists():
        # Create admin user
        admin = CustomUser.objects.create_superuser(email='admin@example.com', password='adminpassword', role='admin', name='Admin')
        print('Admin user created successfully.')
    else:
        print('Admin user already exists.')

if __name__ == '__main__':
    create_admin()
