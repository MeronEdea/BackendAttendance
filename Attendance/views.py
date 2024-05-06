from django.shortcuts import render, HttpResponse
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import CustomUser, Student, FaceData, ActivityLog, Section
from django.contrib.auth import authenticate, login
from rest_framework.authtoken.models import Token
from .utils import log_activity, get_client_ip
from django.contrib.auth.decorators import login_required
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from .decorators import token_required


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
        face_encoding = request.FILES.get('face_image')
        section = request.POST.get('section') 
        department = request.POST.get('department') 
        college = request.POST.get('college')
        gender = request.POST.get('gender') 
        year_semester = request.POST.get('year_semester') 

        # Create a CustomUser instance
        user = CustomUser.objects.create_user(
            email=email,
            name=fullname,
            phone_number=phonenumber,
            department = department,
            college = college,
            gender = gender,
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
        
        # Create a FaceData instance
        face_data = FaceData.objects.create(
            face_encoding=face_encoding,  # Assuming you handle file upload correctly to get the face encoding
            user=user  # Link the face data to the CustomUser
        )
        
        return JsonResponse({'message': 'Registration successful'}, status=201)
    else:
        return JsonResponse({'error': 'Only POST requests are allowed'}, status=405)
    
@csrf_exempt
def login_user(request):
    if request.method == 'POST':
        student_id = request.POST.get('student_id')
        password = request.POST.get('password')
        
        # Authenticate the user using the custom backend
        user = authenticate(request, student_id=student_id, password=password)
        
        if user is not None:
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            
            user.token = access_token
            user.save()
            
            # Log the login activity
            name = user.name
            action = "Login"
            resource = "User"
            details = f"User {name} logged in successfully"
            ip_address = get_client_ip(request)
            status_code = 200
            log_activity(name, action, resource, details, ip_address, status_code)
            return JsonResponse({'message': 'Login successful', 'access_token': access_token}, status=200)
        else:
            # Log the failed login attempt
            name = student_id
            action = "Login"
            resource = "User"
            details = f"Failed login attempt for user with student ID {student_id}"
            ip_address = get_client_ip(request)
            status_code = 401
            log_activity(name, action, resource, details, ip_address, status_code)
            return JsonResponse({'error': 'Invalid student ID or password.'}, status=401)
    else:
        return JsonResponse({'error': 'Only POST requests are allowed'}, status=405)

    
    
def get_activity_logs(request):
    if request.method == 'GET':
        logs = ActivityLog.objects.all().order_by('-timestamp')[:10]  # Fetching the latest 10 logs
        data = []
        for log in logs:
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
        return JsonResponse({'logs': data}, status=200)
    else:
        return JsonResponse({'error': 'Only GET requests are allowed'}, status=405)

@token_required
def user_profile(request):
    user = request.user
    # Assuming a one-to-one relationship between CustomUser and Student models
    try:
        student = Student.objects.get(user=user)
    except Student.DoesNotExist:
        student = None

    # Assuming a one-to-one relationship between CustomUser and FaceData models
    try:
        face_data = FaceData.objects.get(user=user)
    except FaceData.DoesNotExist:
        face_data = None

    if student:
        profile_data = {
            'fullname': user.name,
            'student_id': student.student_id,
            'email': user.email,
            'phonenumber': user.phone_number,
            'section': student.section,
            # Add other fields as needed
        }
        if face_data:
            profile_data['face_encoding'] = face_data.face_encoding.url  # Assuming face_encoding is a FileField
        return JsonResponse(profile_data)
    else:
        return JsonResponse({'error': 'User profile not found'}, status=404)