from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.core.validators import RegexValidator

# Custom user manager for the custom user model
class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(email, password, **extra_fields)

# Custom user model extending AbstractBaseUser
class CustomUser(AbstractBaseUser):
    email = models.EmailField(unique=True)
    name = models.CharField(max_length=100)
    phone_number = models.CharField(max_length=100, validators=[RegexValidator(regex=r'^\+?1?\d{9,15}$', message="Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed.")])
    user_type = models.CharField(max_length=50)

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name']

    def __str__(self):
        return self.email

# Teacher Model
class Teacher(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)

# FaceData Model
class FaceData(models.Model):
    face_encoding = models.JSONField()
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)

# Student Model
class Student(models.Model):
    name = models.CharField(max_length=100)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, default=None)

# Course Model
class Course(models.Model):
    course_name = models.CharField(max_length=100)
    teacher = models.ForeignKey(Teacher, on_delete=models.CASCADE, default=None)
    schedule = models.ForeignKey('Schedule', related_name='courses', on_delete=models.CASCADE, default=None)

# Notification Model
class Notification(models.Model):
    title = models.CharField(max_length=100)
    message = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=50)
    link = models.URLField()
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)

# Attendance Model
class Attendance(models.Model):
    date = models.DateField()
    status = models.CharField(max_length=50)
    student = models.ForeignKey(Student, on_delete=models.CASCADE, default=None)

# CourseStudent Model
class CourseStudent(models.Model):
    course = models.ForeignKey(Course, on_delete=models.CASCADE)
    student = models.ForeignKey(Student, on_delete=models.CASCADE)

# Schedule Model
class Schedule(models.Model):
    day_of_the_week = models.CharField(max_length=50)
    start_time = models.TimeField()
    end_time = models.TimeField()
    course = models.ForeignKey(Course, on_delete=models.CASCADE, related_name='schedules')