from django.shortcuts import render, HttpResponse
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import CustomUser, Student, FaceData, ActivityLog, Section, PermissionRequest, Course, Attendance, Notification, AttendanceRecord, Teacher, Schedule, Permission, CourseStudent, TeacherCourseChoice, Role, RolePermission
from django.contrib.auth import authenticate, login
from rest_framework.authtoken.models import Token
from .utils import log_activity, get_client_ip
from django.contrib.auth.decorators import login_required
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from .decorators import token_required
from django.core.serializers.json import DjangoJSONEncoder
from django.forms.models import model_to_dict
from django.core.mail import send_mail
from django.http import JsonResponse
from django.template.loader import render_to_string
from django_otp import devices_for_user
from django_otp.oath import TOTP
from django.contrib.auth.hashers import make_password
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ObjectDoesNotExist
from django.core.cache import cache
from django.http import QueryDict
import json
import base64
import logging
import jwt
from django.views.decorators.http import require_http_methods
from rest_framework import generics
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from .serializers import AttendanceRecordSerializer,AttendanceSerializer, CourseSerializer, UserSerializer ,AttendanceSerializer,CustomUserSerializer, PermissionRequestSerializer, StudentSerializer, NotificationSerializer, PermissionSerializer, RoleSerializer
from dns import resolver
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.core.paginator import Paginator
from django.db import IntegrityError, DatabaseError
from django.utils.crypto import get_random_string
from django.shortcuts import get_object_or_404
import csv
import uuid
from django.utils.dateparse import parse_time
from datetime import datetime
import pandas as pd
from django.db.models import Q, Case, When, CharField, F, Value
from django.db.models.functions import Coalesce
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from jwt.exceptions import InvalidTokenError
from django.db import transaction, IntegrityError


# Create your views here.

def home(request):
    return HttpResponse("hi merry:)")

@csrf_exempt
def register_user(request):
    if request.method == 'POST':
        fullname = request.POST.get('fullname')
        student_id = request.POST.get('student_id')
        email = request.POST.get('email')
        phonenumber = request.POST.get('phonenumber')
        password = request.POST.get('password')
        section = request.POST.get('section') 
        department = request.POST.get('department') 
        college = request.POST.get('college')
        gender = request.POST.get('gender') 
        year_semester = request.POST.get('year_semester') 
        face_image_file = request.FILES.get('face_image')

        if face_image_file:
            # Create a CustomUser instance
            user = CustomUser.objects.create_user(
                email=email,
                name=fullname,
                phone_number=phonenumber,
                department=department,
                college=college,
                gender=gender,
                role='student'
            )

            # Save the password
            user.set_password(password)
            user.save()

            # Create a Section instance
            section_instance = Section.objects.create(
                name=section,
            )

            # Create a Student instance
            student = Student.objects.create(
                student_id=student_id,
                section=section_instance,  # Link the student to the Section
                year_semester=year_semester,
                user=user  # Link the student to the CustomUser
            )

            # Create a FaceData instance with the uploaded face image file
            face_data = FaceData.objects.create(
                face_encoding=face_image_file,  # Associate the face image file with the face encoding attribute
                user=user  # Link the face data to the CustomUser
            )

            return JsonResponse({'message': 'Registration successful'}, status=201)
        else:
            return JsonResponse({'error': 'Face image file is required'}, status=400)
    else:
        return JsonResponse({'error': 'Only POST requests are allowed'}, status=405)
    

# @csrf_exempt
# def register_user(request):
#     if request.method == 'POST':
#         fullname = request.POST.get('fullname')
#         student_id = request.POST.get('student_id')
#         email = request.POST.get('email')
#         phonenumber = request.POST.get('phonenumber')
#         password = request.POST.get('password')
#         section = request.POST.get('section')
#         department = request.POST.get('department')
#         college = request.POST.get('college')
#         gender = request.POST.get('gender')
#         year_semester = request.POST.get('year_semester')
#         face_image_file = request.FILES.get('face_image')

#         if face_image_file:
#             try:
#                 with transaction.atomic():
#                     # Create a CustomUser instance
#                     user = CustomUser.objects.create_user(
#                         email=email,
#                         name=fullname,
#                         phone_number=phonenumber,
#                         department=department,
#                         college=college,
#                         gender=gender,
#                         role='student'
#                     )

#                     # Save the password
#                     user.set_password(password)
#                     user.save()

#                     # Create a Section instance
#                     section_instance = Section.objects.create(
#                         name=section,
#                     )

#                     # Create a Student instance
#                     student = Student.objects.create(
#                         student_id=student_id,
#                         section=section_instance,  # Link the student to the Section
#                         year_semester=year_semester,
#                         user=user  # Link the student to the CustomUser
#                     )

#                     # Read the face image file and convert it to binary data
#                     face_image_binary = face_image_file.read()

#                     # Create a FaceData instance with the uploaded face image file
#                     face_data = FaceData.objects.create(
#                         face_encoding=face_image_binary,  # Associate the face image file with the face encoding attribute
#                         user=user  # Link the face data to the CustomUser
#                     )

#                 return JsonResponse({'message': 'Registration successful'}, status=201)
#             except IntegrityError as e:
#                 return JsonResponse({'error': 'Database integrity error: ' + str(e)}, status=400)
#             except Exception as e:
#                 return JsonResponse({'error': 'An unexpected error occurred: ' + str(e)}, status=500)
#         else:
#             return JsonResponse({'error': 'Face image file is required'}, status=400)
#     else:
#         return JsonResponse({'error': 'Only POST requests are allowed'}, status=405)

@csrf_exempt
def login_user(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        student_id = data.get('student_id')
        email = data.get('email')  # Add email field
        password = data.get('password')
        
        if student_id:
            # Authenticate using student_id and password
            user = authenticate(request, student_id=student_id, password=password)
        elif email:
            # Authenticate using email and password
            user = authenticate(request, email=email, password=password)
        else:
            return JsonResponse({'error': 'Invalid request data. Provide either student ID or email and password.'}, status=400)
        
        if user is not None:
            # Generate a refresh token
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            
            # Retrieve the user's role
            user_role = user.role  # Assuming the user model has a 'role' field
            
            # Update the token field in the user model with the new access token
            user.token = access_token
            user.save()
            
            # Log the login activity
            name = user.name
            action = "Login"
            resource = "User"
            details = f"User {name} logged in successfully"
            ip_address = request.META.get('REMOTE_ADDR')
            status_code = 200
            log_activity(name, action, resource, details, ip_address, status_code)
            
            # Return the access token and user role
            return JsonResponse({'message': 'Login successful', 'access_token': access_token, 'role': user.role}, status=200)
        else:
            # Log the failed login attempt
            if student_id:
                name = student_id
            elif email:
                name = email
            action = "Login"
            resource = "User"
            details = f"Failed login attempt for user with {'' if student_id else 'email '} {name}"
            ip_address = request.META.get('REMOTE_ADDR')
            status_code = 401
            log_activity(name, action, resource, details, ip_address, status_code)
            return JsonResponse({'error': 'Invalid credentials.'}, status=401)
    else:
        return JsonResponse({'error': 'Only POST requests are allowed'}, status=405)
    
    
def get_activity_logs(request):
    if request.method == 'GET':
        logs = ActivityLog.objects.all().order_by('-timestamp')
        paginator = Paginator(logs, 10)  # Limiting to 10 logs per page

        page_number = request.GET.get('page')
        page_obj = paginator.get_page(page_number)

        data = []
        for log in page_obj:
            log_data = {
                'name': log.name,
                'action': log.action,
                'resource': log.resource,
                'details': log.details,
                'ip_address': log.ip_address,
                'status_code': log.status_code,
                'timestamp': log.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            }
            data.append(log_data)

        return JsonResponse({'logs': data, 'total_pages': paginator.num_pages}, status=200)
    else:
        return JsonResponse({'error': 'Only GET requests are allowed'}, status=405)



def user_profile(request):
    
    if request.method == 'GET':

        try:
            # Get the access token from request headers
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return JsonResponse({'error': 'Authorization header missing or invalid'}, status=status.HTTP_400_BAD_REQUEST)
            
            access_token = auth_header.split(' ')[1]

            try:
                validated_token = JWTAuthentication().get_validated_token(access_token)
                user_id = validated_token['user_id']
            except InvalidTokenError as e:
                return JsonResponse({'error': 'Invalid token: ' + str(e)}, status=status.HTTP_401_UNAUTHORIZED)

            # Retrieve the teacher object associated with the user
            user = get_object_or_404(CustomUser, id=user_id)

            # Assuming a one-to-one relationship between CustomUser and FaceData models
            try:
                face_data = get_object_or_404(FaceData, user_id=user_id)
            except FaceData.DoesNotExist:
                face_data = None

            if user:
                profile_data = {
                    'fullname': user.name,
                    # 'student_id': student.student_id,
                    'email': user.email,
                    'phonenumber': user.phone_number,
                    'college': user.college,
                    'department': user.department,
                    'gender': user.gender,
                    # 'section': model_to_dict(student.section),  # Convert Section object to dictionary
                    # Add other fields as needed
                }

                if face_data:
                    profile_data['profile_picture'] = face_data.face_encoding.url  # Assuming face_encoding is a FileField

                return JsonResponse(profile_data)
            else:
                return JsonResponse({'error': 'User profile not found'}, status=404)

        except Exception as e:
            return JsonResponse({"detail": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@csrf_exempt
@token_required
def update_profile(request, user, *args, **kwargs):
    # Load JSON data from request.body
    data = json.loads(request.body)

    # Retrieve the current profile data
    try:
        student = Student.objects.get(user=user)
    except Student.DoesNotExist:
        student = None

    try:
        face_data = FaceData.objects.get(user=user)
    except FaceData.DoesNotExist:
        face_data = None

    # Update the user profile based on the provided data
    if student:
        # Update user fields
        if 'name' in data:
            user.name = data['name']
        if 'email' in data:
            user.email = data['email']
        if 'phone_number' in data:
            user.phone_number = data['phone_number']
        if 'college' in data:
            user.college = data['college']
        if 'department' in data:
            user.department = data['department']
        if 'section' in data:
            user.section = data['section']
        if 'profile_picture' in data:
            user.profile_picture = data['profile_picture']
        if 'password' in data and data['password']:
            user.password = make_password(data['password'])
        user.save()

        # Update student fields
        if 'student_id' in data:
            student.student_id = data['student_id']
        student.save()

        # Update face data if available
        if face_data:
            if 'face_encoding' in data:
                face_data.face_encoding = data['face_encoding']
            face_data.save()

        # Construct and return the updated profile data
        profile_data = {
            'fullname': user.name,
            'student_id': student.student_id if student else None,
            'email': user.email,
            'phonenumber': user.phone_number,
            'department': user.department,
            'college': user.college,
            'section': model_to_dict(student.section) if student else None,
            'face_encoding': face_data.face_encoding.url if face_data else None,
            'profile_picture': user.profile_picture,
            # Add other fields as needed
        }
        return JsonResponse({'success': True, 'message': 'Profile updated successfully', 'profile_data': profile_data})
    else:
        return JsonResponse({'error': 'User profile not found'}, status=404)


@csrf_exempt
def send_otp(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            email = data.get('email')
            if email:
                try:
                    user = CustomUser.objects.get(email=email)
                except CustomUser.DoesNotExist:
                    return JsonResponse({'success': False, 'message': 'User with this email does not exist'})
                
                # Generate OTP
                totp = TOTP(key=user.name.encode('utf-8'))
                otp_code = totp.token()

                # Store OTP in cache
                cache.set(email, otp_code, timeout=3000)  # Set expiration time to 5 minutes
                
                # Send OTP via email
                subject = 'Password Reset OTP'
                message = render_to_string('password_reset_email.html', {'otp_code': otp_code})
                try:
                    send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [email])
                    return JsonResponse({'success': True, 'message': 'OTP sent successfully'})
                except Exception as e:
                    return JsonResponse({'success': False, 'message': f'Failed to send OTP: {str(e)}'})
            else:
                return JsonResponse({'success': False, 'message': 'Email not provided'})
        except json.JSONDecodeError:
            return JsonResponse({'success': False, 'message': 'Invalid JSON format'})
    else:
        return JsonResponse({'success': False, 'message': 'Only POST requests are allowed'})


@csrf_exempt    
def update_password(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        email = data.get('email')
        otp = data.get('otp')
        new_password = data.get('new_password')

        if email and otp and new_password:
            try:
                user = CustomUser.objects.get(email=email)
            except CustomUser.DoesNotExist:
                return JsonResponse({'success': False, 'message': 'User with this email does not exist'})

            # Retrieve OTP from cache
            cached_otp = cache.get(email)

            if cached_otp is None or str(cached_otp) != otp:
                return JsonResponse({'success': False, 'message': 'Invalid OTP'})

            # Update password
            user.set_password(new_password)
            user.save()

            # Clear OTP from cache after successful password update
            cache.delete(email)

            return JsonResponse({'success': True, 'message': 'Password updated successfully'})
        else:
            return JsonResponse({'success': False, 'message': 'Missing email, OTP, or new password'})
    else:
        return JsonResponse({'success': False, 'message': 'Only POST requests are allowed'})
    
#Permission create
logger = logging.getLogger(__name__)
@csrf_exempt  
def create_permission_request(request):
    if request.method == 'POST':
        try:
            teacher = request.POST.get('teacher')
            reason = request.POST.get('reason')
            evidence = request.FILES.get('evidence')
            student_id = request.POST.get('student_id')
            
            # Convert sick_leave to boolean
            sick_leave = request.POST.get('sickLeave', 'false').lower() == 'true'

            logger.debug(f"Received data - Teacher: {teacher}, Reason: {reason}, SickLeave: {sick_leave}")
            logger.debug(f"Evidence: {evidence}")

            # Save the form data to the database
            permission_request = PermissionRequest.objects.create(
                teacher=teacher,
                reason=reason,
                evidence=evidence,
                sick_leave=sick_leave,
                student_id=student_id,  # Assigning the student_id
                status = "pending"
            )
            logger.debug(f"Permission request created: {permission_request.id}")
            return JsonResponse({'message': 'Permission request submitted successfully.'})
        except Exception as e:
            logger.error(f"Error creating permission request: {e}")
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Invalid request method.'}, status=400)
    
    
#Course 
@csrf_exempt
def course_list(request):
    if request.method == 'GET':
        courses = Course.objects.all()
        data = list(courses.values())
        return JsonResponse(data, safe=False)

    elif request.method == 'POST':
        try:
            data = json.loads(request.body)
            unique_join_code = str(uuid.uuid4())[:10]  # Generate a unique code, limit to 10 characters
            course = Course.objects.create(
                college=data['college'],
                department=data['department'],
                name=data['name'],
                code=data['code'],
                duration=data['duration'],
                year=data['year'],
                prerequest=data['prerequest'],
                joinCode=unique_join_code
            )

            # Send notifications to all teachers
            teachers = Teacher.objects.all()
            for teacher in teachers:
                Notification.objects.create(
                    title='New Course Available',
                    message=f'A new course "{course.name}" has been added. Please choose if you want to teach this course.',
                    status='unread',
                    link=f'/choose-course/{course.id}',
                    user=teacher.user
                )
            return JsonResponse({'message': 'Course created successfully'}, status=201)
        except KeyError as e:
            return JsonResponse({'error': f'Missing key in request data: {e}'}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
        

@csrf_exempt
@require_http_methods(["GET", "PUT", "PATCH"])
def course_detail(request, pk):
    try:
        course = Course.objects.get(pk=pk)
    except Course.DoesNotExist:
        return JsonResponse({'message': 'Course not found'}, status=404)

    if request.method == 'GET':
        data = {
            'college': course.college,
            'department': course.department,
            'name': course.name,
            'code': course.code,
            'duration': course.duration,
            'year': course.year,
            'prerequest': course.prerequest
        }
        return JsonResponse(data)

    elif request.method == 'PUT':
        data = json.loads(request.body.decode('utf-8'))

        course.college = data['college']
        course.department = data['department']
        course.name = data['name']
        course.code = data['code']
        course.duration = data['duration']
        course.year = data['year']
        course.prerequest = data['prerequest']
        course.save()

        return JsonResponse({'message': 'Course updated successfully'})

    elif request.method == 'PATCH':
        data = json.loads(request.body.decode('utf-8'))

        # Update only the specified field if present in the request data
        if 'college' in data:
            course.college = data['college']
        elif 'department' in data:
            course.department = data['department']
        elif 'name' in data:
            course.name = data['name']
        elif 'code' in data:
            course.code = data['code']
        elif 'duration' in data:
            course.duration = data['duration']
        elif 'year' in data:
            course.year = data['year']
        elif 'prerequest' in data:
            course.prerequest = data['prerequest']

        course.save()

        return JsonResponse({'message': 'Course updated successfully'})
    

@csrf_exempt
def join_course(request):
    if request.method == 'POST':
        try:
            # Get the access token from request headers
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return JsonResponse({'error': 'Authorization header missing or invalid'}, status=400)
            
            access_token = auth_header.split(' ')[1]
            
            # Decode the access token to get user ID
            try:
                validated_token = JWTAuthentication().get_validated_token(access_token)
                user_id = validated_token['user_id']
            except (InvalidToken, TokenError) as e:
                return JsonResponse({'error': 'Invalid token: ' + str(e)}, status=401)

            # Fetch the user from the database
            user = get_object_or_404(CustomUser, id=user_id)
            
            # Ensure user is a student
            if user.role != 'student':
                return JsonResponse({'error': 'Only students can join courses'}, status=400)
            
            # Fetch the student
            student = get_object_or_404(Student, user=user)
            
            # Parse request data
            data = json.loads(request.body)
            join_code = data['join_code']
            
            # Fetch the course
            course = get_object_or_404(Course, joinCode=join_code)
            
            # Check if the student is already enrolled
            if CourseStudent.objects.filter(course=course, student=student).exists():
                return JsonResponse({'message': 'Student is already enrolled in this course'}, status=200)
            
            # Enroll the student
            CourseStudent.objects.create(course=course, student=student)
            
            return JsonResponse({'message': 'Student successfully enrolled'}, status=201)
        except KeyError as e:
            return JsonResponse({'error': f'Missing key in request data: {e}'}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)
    

def student_courses(request):
    if request.method == 'GET':
        try:
            # Get the access token from request headers
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return JsonResponse({'error': 'Authorization header missing or invalid'}, status=status.HTTP_400_BAD_REQUEST)
            
            access_token = auth_header.split(' ')[1]
            print(f"Access Token: {access_token}")
            
            # Decode the access token to get user ID
            try:
                validated_token = JWTAuthentication().get_validated_token(access_token)
                user_id = validated_token['user_id']
                print(f"Validated Token: {validated_token}")
                print(f"User ID: {user_id}")
            except (InvalidToken, TokenError) as e:
                return JsonResponse({'error': 'Invalid token: ' + str(e)}, status=status.HTTP_401_UNAUTHORIZED)
            
            # Retrieve the CustomUser instance using user_id
            try:
                user = CustomUser.objects.get(id=user_id)
                print(f"User: {user}")
                
                # Retrieve the Student instance using the CustomUser instance
                student = Student.objects.get(user=user)
                print(f"Student: {student}")
                
                course_students = CourseStudent.objects.filter(student=student)
                courses = [cs.course for cs in course_students]
                serializer = CourseSerializer(courses, many=True)
                return JsonResponse(serializer.data, status=status.HTTP_200_OK, safe=False)
            except CustomUser.DoesNotExist:
                return JsonResponse({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
            except Student.DoesNotExist:
                return JsonResponse({'error': 'Student not found'}, status=status.HTTP_404_NOT_FOUND)
            except Exception as e:
                return JsonResponse({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    


@csrf_exempt
def approve_permission(request, permission_id):
    try:
        permission = get_object_or_404(Permission, id=permission_id)
        permission.status = "Approved"
        permission.save()
        # attendance = Attendance.objects.get(id=attendance_id)
        # attendance.status = "Present"  # Update status to Present when approved
        # attendance.save()

        # Create notification for the student
        Notification.objects.create(
            title="Permission Approved",
            message="Your permission request has been approved.",
            status="unread",
            link="/your-profile-page",  # Change this to the appropriate link
            user=permission.student.user
        )

        return JsonResponse({'message': 'Permission approved successfully'})
    except Attendance.DoesNotExist:
        return JsonResponse({'error': 'Permission record not found'}, status=404)

@csrf_exempt
def reject_permission(request, permission_id):
    try:
        permission = get_object_or_404(Permission, id=permission_id)
        permission.status = "Rejected"
        permission.save()
        # attendance = Attendance.objects.get(id=attendance_id)
        # attendance.status = "Absent"  # Update status to Absent when rejected
        # attendance.save()

        # Create notification for the student
        Notification.objects.create(
            title="Permission Rejected",
            message="Your permission request has been rejected.",
            status="unread",
            link="/your-profile-page",  # Change this to the appropriate link
            user=permission.student.user
        )

        return JsonResponse({'message': 'Permission rejected successfully'})
    except Attendance.DoesNotExist:
        return JsonResponse({'error': 'Permission record not found'}, status=404)

# permission list
@csrf_exempt
def get_permission_requests(request):
    if request.method == 'GET':
        # Fetch all PermissionRequest entries
        permission_data = PermissionRequest.objects.all().values()
        
        # Serialize the data as JSON
        data = list(permission_data)
        return JsonResponse(data, safe=False)
    else:
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    

@api_view(['GET'])
def get_permission_details(request, permission_id):
    try:
        print(permission_id)
        permission = PermissionRequest.objects.get(id=permission_id)
        print(permission)

        # Fetch student related to the permission request
        student_id = permission.student_id
        student = Student.objects.get(id=student_id)
        print(student)

        # Fetch attendance history for the student
        attendance_history = Attendance.objects.filter(student=student).order_by('date')

        # Calculate attendance stats
        absent_days = attendance_history.filter(status="Absent").count()
        present_days = attendance_history.filter(status="Present").count()
        permission_days = attendance_history.filter(status="Permission").count()

        # Serialize data
        permission_data = PermissionRequestSerializer(permission).data
        student_data = StudentSerializer(student).data
        attendance_data = [
            {
                'date': attendance.date,
                'status': attendance.status,
            } for attendance in attendance_history
        ]

        response_data = {
            'permission': permission_data,
            'student': student_data,
            'attendance_history': attendance_data,
            'absent_days': absent_days,
            'present_days': present_days,
            'permission_days': permission_days,
        }

        return JsonResponse(response_data, safe=False)

    except PermissionRequest.DoesNotExist:
        return JsonResponse({'error': 'Permission record not found'}, status=404)
    except Exception as e:
        print(e)
        return JsonResponse({'error': 'Internal Server Error'}, status=500)


class UserList(APIView):
    def get(self, request):
        users = CustomUser.objects.all()
        data = []
        for user in users:
            user_data = {
                'email': user.email,
                'name': user.name,
                'phone_number': user.phone_number,
                'gender': user.gender,
                'department': user.department,
                'college': user.college,
                'role': user.role,
            }
            if user.role == 'student':
                # Fetch student data if the user is a student
                student = Student.objects.filter(user=user).first()
                if student:
                    user_data['student_id'] = student.student_id
                    user_data['section'] = student.section.name
                    user_data['year_semester'] = student.year_semester
            data.append(user_data)
        return Response(data)

# API endpoint to fetch data from Attendance model
class AttendanceList(APIView):
    def get(self, request):
        attendance_records = Attendance.objects.all()
        data = [{'date': record.date, 'status': record.status, 'student_id': record.student_id} for record in attendance_records]
        return Response(data)

# API endpoint to fetch data from Course model
class CourseList(APIView):
    def get(self, request):
        courses = Course.objects.all()
        data = [{'course_name': course.course_name, 'teacher_id': course.teacher_id, 'schedule_id': course.schedule_id} for course in courses]
        return Response(data)

class AttendanceRecordList(generics.ListAPIView):
    queryset = AttendanceRecord.objects.all()
    serializer_class = AttendanceRecordSerializer
class AttendanceCreate(APIView):
    def post(self, request, format=None):
        serializer = AttendanceSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)     
class AttendanceListByStatus(generics.ListAPIView):
    serializer_class = AttendanceSerializer  
    def get(self, request):
        attendance_records = Attendance.objects.all()
        data = [{'date': record.date, 'status': record.status} for record in attendance_records]
        return Response(data) 


class UserListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        users = CustomUser.objects.all()
        serializer = CustomUserSerializer(users, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = CustomUserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=201)
        return Response(serializer.errors, status=400)

class UserDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get_object(self, pk):
        try:
            return CustomUser.objects.get(pk=pk)
        except CustomUser.DoesNotExist:
            return None

    def get(self, request, pk):
        user = self.get_object(pk)
        if user is None:
            return Response(status=404)
        serializer = CustomUserSerializer(user)
        return Response(serializer.data)

    def put(self, request, pk):
        user = self.get_object(pk)
        if user is None:
            return Response(status=404)
        serializer = CustomUserSerializer(user, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)

    def delete(self, request, pk):
        user = self.get_object(pk)
        if user is None:
            return Response(status=404)
        user.delete()
        return Response(status=204)


@csrf_exempt
def add_teacher(request):
    if request.method == 'POST':
        try:
            # Print the data received from the frontend
            print('Data received from frontend:', request.POST)

            # Retrieve data from the POST request
            email = request.POST.get('email')
            name = request.POST.get('name')
            phone_number = request.POST.get('phone_number')
            gender = request.POST.get('gender')
            department = request.POST.get('department')
            college = request.POST.get('college')
            qualifications = request.POST.get('qualifications')
            semester = request.POST.get('semester')
            profile_picture = request.FILES.get('profile_picture')

            # Ensure that all required fields are present
            if not (email and name and phone_number and gender and department and college and qualifications and semester and profile_picture):
                return JsonResponse({'error': 'Missing required fields'}, status=400)

            temporary_password = get_random_string(length=8)
            # Create a CustomUser instance
            user = CustomUser.objects.create_user(
                email=email,
                name=name,
                phone_number=phone_number,
                department=department,
                college=college,
                gender=gender,
                role='teacher'
            )
            user.set_password(temporary_password)
            user.save()

            # Create a Teacher instance and assign values to its fields
            teacher = Teacher.objects.create(
                user=user,
                qualifications=qualifications,
                semester=semester
            )

            # Create a FaceData instance with the uploaded face image file
            face_data = FaceData.objects.create(
                face_encoding=profile_picture,  # Associate the face image file with the face encoding attribute
                user=user  # Link the face data to the CustomUser
            )
            subject = 'Your Temporary Password'
            message = render_to_string('temporary_password_email.html', {'temporary_password': temporary_password})
                
            send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [email])

            return JsonResponse({'message': 'Teacher added successfully'}, status=201)
        except IntegrityError as e:
            logger.error(f"IntegrityError occurred: {e}")
            return JsonResponse({'error': 'IntegrityError occurred. Please check if the data is valid.'}, status=400)
        except DatabaseError as e:
            logger.error(f"DatabaseError occurred: {e}")
            return JsonResponse({'error': 'DatabaseError occurred. Please try again later.'}, status=500)
        except Exception as e:
            logger.error(f"An unexpected error occurred: {e}")
            return JsonResponse({'error': 'An unexpected error occurred. Please try again later.'}, status=500)

    return JsonResponse({'error': 'Only POST requests are allowed'}, status=405)


@csrf_exempt
def get_teachers(request):
    if request.method == 'GET':
        try:
            # Fetch all teachers from the database
            teachers = Teacher.objects.all()

            # Serialize teacher data
            serialized_teachers = []
            for teacher in teachers:
                serialized_teacher = {
                    'id': teacher.id,
                    'name': teacher.user.name,
                    'email': teacher.user.email,
                    'department': teacher.user.department,
                    'semester': teacher.semester,
                    'phone_number': teacher.user.phone_number,
                    'gender': teacher.user.gender,
                    'college': teacher.user.college,
                    'qualifications': teacher.qualifications
                    # Add more fields as needed
                }
                serialized_teachers.append(serialized_teacher)

            # Return the serialized teacher data as JSON response
            return JsonResponse(serialized_teachers, safe=False)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Only GET requests are allowed'}, status=405)

@csrf_exempt
def edit_teacher(request, id):
    try:
        teacher = Teacher.objects.get(user_id=id)  # Retrieve Teacher instance by user_id
    except Teacher.DoesNotExist:
        return JsonResponse({'error': 'Teacher not found'}, status=404)

    if request.method in ['PUT', 'PATCH']:
        data = json.loads(request.body.decode('utf-8'))
        try:
            # Extracting data from the request
            name = data.get('name')
            email = data.get('email')
            phone_number = data.get('phone_number')
            qualifications = data.get('qualifications')
            semester = data.get('semester')

            # Update teacher's information if the data is provided
            if name is not None:
                teacher.user.name = name
            if email is not None:
                teacher.user.email = email
            if phone_number is not None:
                teacher.user.phone_number = phone_number
            teacher.user.save()

            # Update additional fields in Teacher model
            if qualifications is not None:
                teacher.qualifications = qualifications
            if semester is not None:
                teacher.semester = semester
            teacher.save()

            return JsonResponse({'message': 'Teacher updated successfully'}, status=200)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    else:
        return JsonResponse({'error': 'Only PUT or PATCH requests are allowed'}, status=405)

@csrf_exempt
def delete_teacher(request, id):
    try:
        teacher = Teacher.objects.get(user_id=id)
    except Teacher.DoesNotExist:
        return JsonResponse({'error': 'Teacher not found'}, status=404)

    if request.method == 'DELETE':
        # Delete the associated Teacher object
        teacher.delete()

        # Delete the CustomUser object
        teacher.user.delete()

        return JsonResponse({'message': 'Teacher deleted successfully'}, status=200)
    else:
        return JsonResponse({'error': 'Only DELETE requests are allowed'}, status=405)
    
class StudentList(APIView):
    def get(self, request):
        students = Student.objects.all()
        serializer = StudentSerializer(students, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)



@csrf_exempt
def handle_uploaded_file(file):
    if file.name.endswith('.csv'):
        df = pd.read_csv(file)
    elif file.name.endswith(('.xls', '.xlsx')):
        df = pd.read_excel(file)
    else:
        raise ValueError("Unsupported file format")

    print("Column Names:", df.columns)  # Print column names for debugging

    # Ensure columns are as expected
    expected_columns = ['Course Code', 'Course Name', 'Day', 'Start Time', 'End Time', 'Location', 'Instructor']
    if not all(col in df.columns for col in expected_columns):
        raise ValueError("Invalid column names in the file")

    return df

@csrf_exempt
def upload_schedule(request):
    if request.method == 'POST':
        if 'file' not in request.FILES:
            return JsonResponse({"error": "No file part in the request"}, status=400)

        file = request.FILES['file']
        try:
            df = handle_uploaded_file(file)
            for _, row in df.iterrows():
                course, _ = Course.objects.get_or_create(code=row['Course Code'], defaults={'name': row['Course Name']})
                
                # Check if location and instructor fields are present in the DataFrame
                if 'Location' in df.columns and 'Instructor' in df.columns:
                    location = row['Location']
                    instructor = row['Instructor']
                    print("Location:", location)
                    print("Instructor:", instructor)
                    schedule = Schedule(
                        day_of_the_week=row['Day'],
                        start_time=row['Start Time'],
                        end_time=row['End Time'],
                        location=location,
                        instructor=instructor,
                        course=course
                    )
                else:
                    # If location and instructor fields are not present, create Schedule without them
                    schedule = Schedule(
                        day_of_the_week=row['Day'],
                        start_time=row['Start Time'],
                        end_time=row['End Time'],
                        course=course
                    )
                    
                schedule.save()
                
            return JsonResponse({"message": "Schedules uploaded successfully."}, status=201)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)
    return JsonResponse({"error": "Invalid request"}, status=400)



def display_schedule(request):
    user = request.user

    # Initialize queryset for schedules
    schedules = Schedule.objects.all()

    # Filter schedules based on user type
    if user.is_authenticated:
        if user.role == 'teacher':
            # Filter schedules for courses where the teacher is associated with the section
            schedules = schedules.filter(course__section__teacher__user=user)
        elif user.role == 'student':
            # Filter schedules for courses where the student is enrolled in the section
            schedules = schedules.filter(course__section__students__user=user)

    # Serialize schedule data
    schedule_data = []
    for schedule in schedules:
        start_time = schedule.start_time.strftime('%H:%M:%S') if schedule.start_time else None
        end_time = schedule.end_time.strftime('%H:%M:%S') if schedule.end_time else None
        # Get the course name from the related Course model
        course_name = schedule.course.name
        # Get the teacher name by iterating over the related sections for the course
        teacher_name = 'Unknown'
        for section in schedule.course.section.all():
            if section.teacher:
                teacher_name = section.teacher.user.name
                break
        schedule_data.append({
            'id': schedule.id,
            'course_name': course_name,
            'day_of_the_week': schedule.day_of_the_week,
            'start_time': start_time,
            'end_time': end_time,
            'location': schedule.location,
            'instructor': schedule.instructor,
            'teacher_name': teacher_name
        })

    # Return JSON response with schedule data
    return JsonResponse({'schedules': schedule_data})




# @login_required
# def edit_schedule(request, schedule_id):
#     schedule = get_object_or_404(Schedule, id=schedule_id)
#     user = request.user
#     if user.user_type != 'teacher':
#         messages.error(request, "You don't have permission to edit this schedule.")
#         return redirect('display_schedule')

#     form = ScheduleForm(request.POST or None, instance=schedule)
#     if form.is_valid():
#         form.save()
#         messages.success(request, "Schedule updated successfully.")
#         return redirect('display_schedule')

#     context = {
#         'form': form,
#         'schedule': schedule
#     }
#     return render(request, 'edit_schedule.html', context)

# @login_required
# @csrf_exempt
# def delete_schedule(request, schedule_id):
#     schedule = get_object_or_404(Schedule, id=schedule_id)
#     user = request.user
#     if user.user_type != 'teacher':
#         messages.error(request, "You don't have permission to delete this schedule.")
#         return redirect('display_schedule')

#     if request.method == 'POST':
#         schedule.delete()
#         messages.success(request, "Schedule deleted successfully.")
#         return redirect('display_schedule')

#     context = {
#         'schedule': schedule
#     }
#     return render(request, 'delete_schedule.html', context)

# reminder for schedule

# @csrf_exempt
# def send_schedule_reminder(request):
#     # Get the current datetime
#     current_datetime = timezone.now()

#     # Define the duration before the schedule that the reminder should be sent
#     reminder_duration = timedelta(hours=1)  # Adjust as needed

#     # Get schedules that are nearing
#     nearing_schedules = Schedule.objects.filter(start_time__gt=current_datetime, start_time__lte=current_datetime + reminder_duration)

#     # Iterate over nearing schedules
#     for schedule in nearing_schedules:
#         # Send reminders to associated teachers
#         teachers = Teacher.objects.filter(course__schedules=schedule)
#         for teacher in teachers:
#             send_email_to_teacher(teacher.user.email, schedule)

#         # Send reminders to associated students
#         students = Student.objects.filter(course__schedules=schedule)
#         for student in students:
#             send_email_to_student(student.user.email, schedule)

#     return JsonResponse({'message': 'Schedule reminders sent successfully'}, status=200)

# def send_email_to_teacher(email, schedule):
#     # Customize the email subject and content for teachers
#     subject = f"Reminder: Your class is about to start"
#     message = f"Dear Teacher,\n\nThis is a reminder that your class is about to start.\n\nSchedule Details:\nDay: {schedule.day_of_the_week}\nStart Time: {schedule.start_time}\nEnd Time: {schedule.end_time}\n\nBest Regards,\nYour School"

#     # Send email
#     send_mail(subject, message, settings.EMAIL_HOST_USER, ['meradongwook@gmail.com', 'kynthia369@gmail.com'], fail_silently=False)

# def send_email_to_student(email, schedule):
#     # Customize the email subject and content for students
#     subject = f"Reminder: Your class is about to start"
#     message = f"Dear Student,\n\nThis is a reminder that your class is about to start.\n\nSchedule Details:\nDay: {schedule.day_of_the_week}\nStart Time: {schedule.start_time}\nEnd Time: {schedule.end_time}\n\nBest Regards,\nYour School"
#     # Send email
#     send_mail(subject, message, settings.EMAIL_HOST_USER, ['meradongwook@gmail.com', 'kynthia369@gmail.com'], fail_silently=False)




# adding teacher-course features
@csrf_exempt
def choose_course(request):
    if request.method == 'POST':
        try:
            # Get the access token from request headers
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return JsonResponse({'error': 'Authorization header missing or invalid'}, status=400)

            access_token = auth_header.split(' ')[1]

            try:
                validated_token = JWTAuthentication().get_validated_token(access_token)
                user_id = validated_token['user_id']
            except (InvalidToken, TokenError) as e:
                return JsonResponse({'error': 'Invalid token: ' + str(e)}, status=401)

            # Retrieve the user object
            user = get_object_or_404(CustomUser, id=user_id)

            # Check if the user is a teacher
            if user.role == 'teacher':
                # Retrieve the associated Teacher object
                teacher = get_object_or_404(Teacher, user=user)
            else:
                return JsonResponse({"detail": "User is not a teacher"}, status=403)

            # Parse JSON data from the request body
            try:
                data = json.loads(request.body)
            except json.JSONDecodeError:
                return JsonResponse({"detail": "Invalid JSON"}, status=400)

            # Get the list of course_ids from the parsed data
            course_ids = data.get('course_id')
            if not course_ids:
                return JsonResponse({"detail": "Course IDs are required"}, status=400)

            if not isinstance(course_ids, list):
                return JsonResponse({"detail": "Course IDs should be a list"}, status=400)

            # Create TeacherCourseChoice entries for each course_id
            for course_id in course_ids:
                course = get_object_or_404(Course, id=course_id)
                TeacherCourseChoice.objects.create(teacher=teacher, course=course)

            return JsonResponse({"detail": "Course selections submitted successfully"}, status=200)

        except jwt.ExpiredSignatureError:
            return JsonResponse({"detail": "Token has expired"}, status=401)
        except jwt.DecodeError:
            return JsonResponse({"detail": "Token is invalid"}, status=401)
        except Exception as e:
            # Log the exception for debugging
            import traceback
            traceback.print_exc()
            return JsonResponse({"detail": str(e)}, status=500)        


@csrf_exempt
def manage_course_choices(request):
    if request.method == 'GET':
        choices = TeacherCourseChoice.objects.all()
        data = [{
            'id': choice.id,
            'teacher': choice.teacher.user.name,
            'course': choice.course.name,
            'status': choice.status,
            'qualifications': choice.teacher.qualifications,
        } for choice in choices]
        return JsonResponse(data, safe=False)

    elif request.method == 'POST':
        try:
            data = json.loads(request.body)
            choice_id = data['choice_id']
            status = data['status']
            choice = TeacherCourseChoice.objects.get(id=choice_id)
            choice.status = status
            choice.save()

            # Send notification to teacher
            Notification.objects.create(
                title='Course Choice Update',
                message=f'Your choice for course "{choice.course.name}" has been {status}.',
                status='unread',
                link=f'/course-choice-status/{choice.id}',
                user=choice.teacher.user
            )

            # Update the course with the approved teacher
            if status == 'approved':
                choice.course.approved_teacher = choice.teacher
                choice.course.save()

            return JsonResponse({'message': 'Choice status updated successfully'}, status=200)
        except KeyError as e:
            return JsonResponse({'error': f'Missing key in request data: {e}'}, status=400)
        except TeacherCourseChoice.DoesNotExist:
            return JsonResponse({'error': 'Choice not found'}, status=404)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)



def teacher_courses_view(request):
    if request.method == 'GET':
        try:
            # Get the access token from request headers
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return JsonResponse({'error': 'Authorization header missing or invalid'}, status=status.HTTP_400_BAD_REQUEST)
            
            access_token = auth_header.split(' ')[1]

            try:
                validated_token = JWTAuthentication().get_validated_token(access_token)
                user_id = validated_token['user_id']
            except InvalidTokenError as e:
                return JsonResponse({'error': 'Invalid token: ' + str(e)}, status=status.HTTP_401_UNAUTHORIZED)

            # Retrieve the teacher object associated with the user
            teacher = get_object_or_404(Teacher, user_id=user_id)

            # Fetch the courses assigned to the teacher
            courses = Course.objects.filter(approved_teacher=teacher)
            serializer = CourseSerializer(courses, many=True)
            
            return JsonResponse(serializer.data, safe=False, status=status.HTTP_200_OK)

        except Exception as e:
            return JsonResponse({"detail": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



def unassigned_courses_view(request):
    if request.method == 'GET':
        try:
            # Get the access token from request headers
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return JsonResponse({'error': 'Authorization header missing or invalid'}, status=status.HTTP_400_BAD_REQUEST)
            
            access_token = auth_header.split(' ')[1]

            try:
                validated_token = JWTAuthentication().get_validated_token(access_token)
                user_id = validated_token['user_id']
            except InvalidTokenError as e:
                return JsonResponse({'error': 'Invalid token: ' + str(e)}, status=status.HTTP_401_UNAUTHORIZED)

            # Fetch courses without an approved teacher
            courses = Course.objects.filter(approved_teacher__isnull=True)
            serializer = CourseSerializer(courses, many=True)
            
            return JsonResponse(serializer.data, safe=False, status=status.HTTP_200_OK)

        except Exception as e:
            return JsonResponse({"detail": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



def get_user_notifications(request):
    if request.method == 'GET':
        try:
            # Get the access token from request headers
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return JsonResponse({'error': 'Authorization header missing or invalid'}, status=status.HTTP_400_BAD_REQUEST)

            access_token = auth_header.split(' ')[1]

            try:
                validated_token = JWTAuthentication().get_validated_token(access_token)
                user_id = validated_token['user_id']
            except (InvalidToken, TokenError) as e:
                return JsonResponse({'error': 'Invalid token: ' + str(e)}, status=status.HTTP_401_UNAUTHORIZED)

            # Fetch the notifications for the user
            notifications = Notification.objects.filter(user=user_id)
            serializer = NotificationSerializer(notifications, many=True)
            return JsonResponse(serializer.data, safe=False)  # Set safe to False to allow list serialization
        except Notification.DoesNotExist:
            return JsonResponse(status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return JsonResponse({"detail": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




def get_username(request):
    if request.method == 'GET':
        try:
            # Get the access token from request headers
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return JsonResponse({'error': 'Authorization header missing or invalid'}, status=status.HTTP_400_BAD_REQUEST)

            access_token = auth_header.split(' ')[1]

            try:
                validated_token = JWTAuthentication().get_validated_token(access_token)
                user_id = validated_token['user_id']
            except (InvalidToken, TokenError) as e:
                return JsonResponse({'error': 'Invalid token: ' + str(e)}, status=status.HTTP_401_UNAUTHORIZED)

            # Retrieve the user object
            try:
                user = CustomUser.objects.get(id=user_id)
                username = user.name
            except CustomUser.DoesNotExist:
                return JsonResponse({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

            # Return the username
            return JsonResponse({'username': username}, status=status.HTTP_200_OK)

        except Exception as e:
            return JsonResponse({"detail": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class RoleListCreateView(generics.ListCreateAPIView):
    queryset = Role.objects.all()
    serializer_class = RoleSerializer

class RoleDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Role.objects.all()
    serializer_class = RoleSerializer

class PermissionListCreateView(generics.ListCreateAPIView):
    queryset = Permission.objects.all()
    serializer_class = PermissionSerializer

class PermissionDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Permission.objects.all()
    serializer_class = PermissionSerializer


@csrf_exempt
def update_role_permissions(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            role = Role.objects.get(id=data['role'])
            permission = Permission.objects.get(id=data['permission'])

            role_permission, created = RolePermission.objects.get_or_create(role=role, permission=permission)
            if not created:
                role_permission.delete()
            
            return JsonResponse({'message': 'Role permissions updated successfully'}, status=200)
        except Role.DoesNotExist:
            return JsonResponse({'error': 'Role not found'}, status=404)
        except Permission.DoesNotExist:
            return JsonResponse({'error': 'Permission not found'}, status=404)
    else:
        return JsonResponse({'error': 'Method not allowed'}, status=405)