from django.db import models

# Create your models here.

# Teacher Model
class Teacher(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField()
    user_id = models.CharField(max_length=100)  # Assuming UserID is a string field

# User Model
class User(models.Model):
    name = models.CharField(max_length=100)
    user_type = models.CharField(max_length=50)  # Assuming UserType is a string field

# FaceData Model
class FaceData(models.Model):
    face_encoding = models.JSONField()
    user_id = models.CharField(max_length=100)  # Assuming UserID is a string field

# Student Model
class Student(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField()
    course_id = models.CharField(max_length=100)  # Assuming CourseID is a string field
    user_id = models.CharField(max_length=100)  # Assuming UserID is a string field

# Course Model
class Course(models.Model):
    course_name = models.CharField(max_length=100)
    teacher_id = models.CharField(max_length=100)  # Assuming TeacherID is a string field
    schedule_id = models.CharField(max_length=100)  # Assuming ScheduleID is a string field

# Notification Model
class Notification(models.Model):
    title = models.CharField(max_length=100)
    message = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=50)  # Assuming Status is a string field
    link = models.URLField()
    user_id = models.CharField(max_length=100)  # Assuming UserID is a string field

# Attendance Model
class Attendance(models.Model):
    date = models.DateField()
    status = models.CharField(max_length=50)  # Assuming Status is a string field
    student_id = models.CharField(max_length=100)  # Assuming StudentID is a string field

# CourseStudent Model
class CourseStudent(models.Model):
    course_id = models.CharField(max_length=100)  # Assuming CourseID is a string field
    student_id = models.CharField(max_length=100)  # Assuming StudentID is a string field

# Schedule Model
class Schedule(models.Model):
    day_of_the_week = models.CharField(max_length=50)
    start_time = models.TimeField()
    end_time = models.TimeField()
    course_id = models.CharField(max_length=100)  # Assuming CourseID is a string field