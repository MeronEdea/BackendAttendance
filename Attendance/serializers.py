from rest_framework import serializers
from .models import AttendanceRecord, Attendance, Course, CustomUser, Student, PermissionRequest, Schedule, Notification, Role, Permission, RolePermission

class AttendanceRecordSerializer(serializers.ModelSerializer):
    # id = serializers.CharField(source='_id')  # Map '_id' to 'id' field

    class Meta:
        model = AttendanceRecord
        fields = '__all__'

class AttendanceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Attendance
        fields = ['date', 'status']

class ScheduleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Schedule
        fields = ['day_of_the_week', 'start_time', 'end_time', 'location', 'instructor']

class CourseSerializer(serializers.ModelSerializer):
    schedules = ScheduleSerializer(many=True, read_only=True)

    class Meta:
        model = Course
        fields = ['id', 'name', 'code', 'duration', 'year', 'prerequest', 'joinCode', 'schedules']

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['name', 'role']  # Exclude 'id'

class CustomUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'email', 'name', 'phone_number', 'gender', 'department', 'college', 'role']
        
class PermissionRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = PermissionRequest
        fields = '__all__'

class StudentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Student
        fields = ['id', 'student_id', 'section', 'user', 'year_semester']


class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = ['id', 'title', 'message', 'timestamp', 'status', 'link', 'user']


class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = ['id', 'codename', 'name', 'description']

class RoleSerializer(serializers.ModelSerializer):
    permissions = serializers.SerializerMethodField()

    class Meta:
        model = Role
        fields = ['id', 'name', 'permissions']

    def get_permissions(self, obj):
        role_permissions = RolePermission.objects.filter(role=obj)
        return PermissionSerializer([rp.permission for rp in role_permissions], many=True).data