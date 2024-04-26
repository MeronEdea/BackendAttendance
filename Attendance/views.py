from django.shortcuts import render, HttpResponse
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import CustomUser, Student, FaceData

# Create your views here.

def home(request):
    return HttpResponse("hi merry:)")

@csrf_exempt
def register_user(request):
    if request.method == 'POST':
        fullname = request.POST.get('fullname')
        id = request.POST.get('id')
        email = request.POST.get('email')
        phonenumber = request.POST.get('phonenumber')
        password = request.POST.get('password')
        face_encoding = request.FILES.get('face_image')
        
        # Create a CustomUser instance
        user = CustomUser.objects.create(
            email=email,
            name=fullname,
            phone_number=phonenumber,
            user_type='student'  # Assuming all registered users are students
        )
        # Save the password
        user.set_password(password)
        user.save()

        # Create a Student instance
        student = Student.objects.create(
            name=fullname,
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