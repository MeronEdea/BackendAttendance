from django.contrib.auth.backends import BaseBackend
from django.contrib.auth import get_user_model

class CustomAuthBackend(BaseBackend):
    def authenticate(self, request, student_id=None, password=None, **kwargs):
        from .models import Student  # Import within the method
        
        UserModel = get_user_model()
        try:
            student = Student.objects.get(student_id=student_id)
            user = student.user
            if user.check_password(password):
                print(user)
                return user
        except Student.DoesNotExist:
            return None
        except Exception as e:
            return None

    def get_user(self, user_id):
        from .models import Student  # Import within the method
        
        UserModel = get_user_model()
        try:
            return UserModel.objects.get(pk=user_id)
        except UserModel.DoesNotExist:
            return None