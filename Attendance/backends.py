from django.contrib.auth.backends import BaseBackend
from django.contrib.auth import get_user_model
from django.core.exceptions import ObjectDoesNotExist

from .models import Student, CustomUser

class CustomAuthBackend(BaseBackend):
    def authenticate(self, request, student_id=None, email=None, password=None, **kwargs):
        UserModel = get_user_model()
        
        if student_id:
            try:
                student = Student.objects.get(student_id=student_id)
                user = student.user
                if user.check_password(password):
                    print(f"Authenticated user with student ID: {student_id}")
                    return user
            except ObjectDoesNotExist:
                pass  # Log this exception for debugging
        
        elif email:
            try:
                user = CustomUser.objects.get(email=email)
                print(f"Found user with email: {email}")
                if user.check_password(password):
                    print(f"Authenticated user with email: {email}")
                    return user
                else:
                    print(f"Password mismatch for user with email: {email}")
            except ObjectDoesNotExist:
                print(f"User with email {email} does not exist")
                pass  # Log this exception for debugging
        
        print("Authentication failed")
        return None

    def get_user(self, user_id):
        UserModel = get_user_model()
        try:
            return UserModel.objects.get(pk=user_id)
        except ObjectDoesNotExist:
            pass  # Log this exception for debugging
        return None
