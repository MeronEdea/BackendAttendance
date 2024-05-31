from django.test import TestCase
from django.utils import timezone
from .models import CustomUser, Teacher, Section, Student, Course, Schedule, Notification, Attendance, CourseStudent, ActivityLog, AttendanceRecord, PermissionRequest, TeacherCourseChoice, Role, Permission, RolePermission

class CustomUserModelTest(TestCase):

    def setUp(self):
        self.user_data = {
            'email': 'testuser@example.com',
            'password': 'testpassword',
            'name': 'Test User',
            'phone_number': '+1234567890',
            'gender': 'male',
            'department': 'Computer Science',
            'college': 'Engineering',
            'role': 'student'
        }

    def test_create_user(self):
        user = CustomUser.objects.create_user(**self.user_data)
        self.assertEqual(user.email, self.user_data['email'])
        self.assertTrue(user.check_password(self.user_data['password']))
        self.assertEqual(user.role, 'student')

    def test_create_user_without_email(self):
        user_data_without_email = self.user_data.copy()
        user_data_without_email.pop('email')
        with self.assertRaises(ValueError):
            CustomUser.objects.create_user(**user_data_without_email)

    def test_create_superuser(self):
        admin_data = self.user_data.copy()
        admin_data['role'] = 'admin'
        admin_data['is_staff'] = True  # Handle unexpected argument is_staff
        admin_data['is_superuser'] = True  # Handle unexpected argument is_superuser
        admin = CustomUser.objects.create_superuser(**admin_data)
        self.assertEqual(admin.role, 'admin')

    def test_create_superuser_with_invalid_role(self):
        admin_data = self.user_data.copy()
        admin_data['role'] = 'teacher'
        admin_data['is_staff'] = True  # Handle unexpected argument is_staff
        admin_data['is_superuser'] = True  # Handle unexpected argument is_superuser
        with self.assertRaises(ValueError):
            CustomUser.objects.create_superuser(**admin_data)


class TeacherModelTest(TestCase):

    def setUp(self):
        self.user = CustomUser.objects.create_user(
            email='teacher@example.com',
            password='testpassword',
            name='Teacher Name',
            role='teacher'
        )
        self.teacher = Teacher.objects.create(
            user=self.user,
            qualifications='PhD in Computer Science',
            semester='Spring'
        )

    def test_teacher_creation(self):
        self.assertEqual(self.teacher.user.email, 'teacher@example.com')
        self.assertEqual(self.teacher.qualifications, 'PhD in Computer Science')
        self.assertEqual(self.teacher.semester, 'Spring')


class SectionModelTest(TestCase):

    def setUp(self):
        self.section = Section.objects.create(name='Section A')

    def test_section_creation(self):
        self.assertEqual(self.section.name, 'Section A')


class StudentModelTest(TestCase):

    def setUp(self):
        self.section = Section.objects.create(name='Section B')
        self.user = CustomUser.objects.create_user(
            email='student@example.com',
            password='testpassword',
            name='Student Name',
            role='student'
        )
        self.student = Student.objects.create(
            student_id='S12345',
            section=self.section,
            user=self.user,
            year_semester='2024 Spring'
        )

    def test_student_creation(self):
        self.assertEqual(self.student.student_id, 'S12345')
        self.assertEqual(self.student.section.name, 'Section B')
        self.assertEqual(self.student.user.email, 'student@example.com')
        self.assertEqual(self.student.year_semester, '2024 Spring')


class CourseModelTest(TestCase):

    def setUp(self):
        self.section = Section.objects.create(name='Section C')
        self.teacher_user = CustomUser.objects.create_user(
            email='courseteacher@example.com',
            password='testpassword',
            name='Course Teacher',
            role='teacher'
        )
        self.teacher = Teacher.objects.create(
            user=self.teacher_user,
            qualifications='PhD',
            semester='Fall'
        )
        self.course = Course.objects.create(
            college='Engineering',
            department='Computer Science',
            name='Algorithms',
            code='CS101',
            duration='6 months',
            year='2024',
            prerequest='None',
            joinCode='ALG2024',
            approved_teacher=self.teacher
        )
        self.course.section.add(self.section)

    def test_course_creation(self):
        self.assertEqual(self.course.name, 'Algorithms')
        self.assertEqual(self.course.code, 'CS101')
        self.assertEqual(self.course.department, 'Computer Science')
        self.assertEqual(self.course.approved_teacher.user.email, 'courseteacher@example.com')
        self.assertIn(self.section, self.course.section.all())


class ScheduleModelTest(TestCase):

    def setUp(self):
        self.course = Course.objects.create(
            college='Engineering',
            department='Computer Science',
            name='Algorithms',
            code='CS101',
            duration='6 months',
            year='2024',
            prerequest='None',
            joinCode='ALG2024'
        )
        self.schedule = Schedule.objects.create(
            day_of_the_week='Monday',
            start_time='09:00:00',
            end_time='11:00:00',
            location='Room 101',
            instructor='Dr. Smith',
            course=self.course
        )

    def test_schedule_creation(self):
        self.assertEqual(self.schedule.day_of_the_week, 'Monday')
        self.assertEqual(self.schedule.start_time, '09:00:00')
        self.assertEqual(self.schedule.end_time, '11:00:00')
        self.assertEqual(self.schedule.location, 'Room 101')
        self.assertEqual(self.schedule.instructor, 'Dr. Smith')
        self.assertEqual(self.schedule.course, self.course)


class NotificationModelTest(TestCase):

    def setUp(self):
        self.user = CustomUser.objects.create_user(
            email='user@example.com',
            password='testpassword',
            name='User Name'
        )
        self.notification = Notification.objects.create(
            title='Test Notification',
            message='This is a test notification.',
            status='unread',
            link='http://example.com',
            user=self.user
        )

    def test_notification_creation(self):
        self.assertEqual(self.notification.title, 'Test Notification')
        self.assertEqual(self.notification.message, 'This is a test notification.')
        self.assertEqual(self.notification.status, 'unread')
        self.assertEqual(self.notification.link, 'http://example.com')
        self.assertEqual(self.notification.user, self.user)


class AttendanceModelTest(TestCase):

    def setUp(self):
        self.section = Section.objects.create(name='Section D')
        self.user = CustomUser.objects.create_user(
            email='student@example.com',
            password='testpassword',
            name='Student Name',
            role='student'
        )
        self.student = Student.objects.create(
            student_id='S12345',
            section=self.section,
            user=self.user,
            year_semester='2024 Spring'
        )
        self.attendance = Attendance.objects.create(
            date='2024-05-01',
            status='Present',
            student=self.student
        )

    def test_attendance_creation(self):
        self.assertEqual(self.attendance.date, '2024-05-01')
        self.assertEqual(self.attendance.status, 'Present')
        self.assertEqual(self.attendance.student, self.student)


class CourseStudentModelTest(TestCase):

    def setUp(self):
        self.section = Section.objects.create(name='Section E')
        self.user = CustomUser.objects.create_user(
            email='student@example.com',
            password='testpassword',
            name='Student Name',
            role='student'
        )
        self.student = Student.objects.create(
            student_id='S12345',
            section=self.section,
            user=self.user,
            year_semester='2024 Spring'
        )
        self.course = Course.objects.create(
            college='Engineering',
            department='Computer Science',
            name='Algorithms',
            code='CS101',
            duration='6 months',
            year='2024',
            prerequest='None',
            joinCode='ALG2024'
        )
        self.course_student = CourseStudent.objects.create(
            course=self.course,
            student=self.student
        )

    def test_course_student_creation(self):
        self.assertEqual(self.course_student.course, self.course)
        self.assertEqual(self.course_student.student, self.student)


class ActivityLogModelTest(TestCase):

    def setUp(self):
        self.activity_log = ActivityLog.objects.create(
            name='Test Activity',
            action='Create',
            resource='Course',
            details='Created a new course',
            ip_address='127.0.0.1',
            status_code=201
        )

    def test_activity_log_creation(self):
        self.assertEqual(self.activity_log.name, 'Test Activity')
        self.assertEqual(self.activity_log.action, 'Create')
        self.assertEqual(self.activity_log.resource, 'Course')
        self.assertEqual(self.activity_log.details, 'Created a new course')
        self.assertEqual(self.activity_log.ip_address, '127.0.0.1')
        self.assertEqual(self.activity_log.status_code, 201)


class AttendanceRecordModelTest(TestCase):

    def setUp(self):
        self.attendance_record = AttendanceRecord.objects.create(
            date='2024-05-01',
            check_in='09:00:00',
            check_out='17:00:00',
            total_hours=8.0,
            notes='Full day'
        )

    def test_attendance_record_creation(self):
        self.assertEqual(self.attendance_record.date, '2024-05-01')
        self.assertEqual(self.attendance_record.check_in, '09:00:00')
        self.assertEqual(self.attendance_record.check_out, '17:00:00')
        self.assertEqual(self.attendance_record.total_hours, 8.0)
        self.assertEqual(self.attendance_record.notes, 'Full day')


class PermissionRequestModelTest(TestCase):

    def setUp(self):
        self.permission_request = PermissionRequest.objects.create(
            teacher='Dr. John Doe',
            reason='Medical emergency',
            evidence='path/to/evidence.jpg',
            sick_leave=True,
            student_id=12345,
            status='pending'
        )

    def test_permission_request_creation(self):
        self.assertEqual(self.permission_request.teacher, 'Dr. John Doe')
        self.assertEqual(self.permission_request.reason, 'Medical emergency')
        self.assertEqual(self.permission_request.evidence, 'path/to/evidence.jpg')
        self.assertTrue(self.permission_request.sick_leave)
        self.assertEqual(self.permission_request.student_id, 12345)
        self.assertEqual(self.permission_request.status, 'pending')


class TeacherCourseChoiceModelTest(TestCase):

    def setUp(self):
        self.teacher_user = CustomUser.objects.create_user(
            email='teacher@example.com',
            password='testpassword',
            name='Teacher Name',
            role='teacher'
        )
        self.teacher = Teacher.objects.create(
            user=self.teacher_user,
            qualifications='PhD',
            semester='Fall'
        )
        self.course = Course.objects.create(
            college='Engineering',
            department='Computer Science',
            name='Data Structures',
            code='CS102',
            duration='6 months',
            year='2024',
            prerequest='None',
            joinCode='DS2024'
        )
        self.teacher_course_choice = TeacherCourseChoice.objects.create(
            teacher=self.teacher,
            course=self.course,
            status='pending'
        )

    def test_teacher_course_choice_creation(self):
        self.assertEqual(self.teacher_course_choice.teacher, self.teacher)
        self.assertEqual(self.teacher_course_choice.course, self.course)
        self.assertEqual(self.teacher_course_choice.status, 'pending')


class RoleModelTest(TestCase):

    def setUp(self):
        self.role = Role.objects.create(name='Admin')

    def test_role_creation(self):
        self.assertEqual(self.role.name, 'Admin')


class PermissionModelTest(TestCase):

    def setUp(self):
        self.permission = Permission.objects.create(
            codename='add_user',
            name='Can add user',
            description='Permission to add a new user'
        )

    def test_permission_creation(self):
        self.assertEqual(self.permission.codename, 'add_user')
        self.assertEqual(self.permission.name, 'Can add user')
        self.assertEqual(self.permission.description, 'Permission to add a new user')


class RolePermissionModelTest(TestCase):

    def setUp(self):
        self.role = Role.objects.create(name='Admin')
        self.permission = Permission.objects.create(
            codename='add_user',
            name='Can add user'
        )
        self.role_permission = RolePermission.objects.create(
            role=self.role,
            permission=self.permission
        )

    def test_role_permission_creation(self):
        self.assertEqual(self.role_permission.role, self.role)
        self.assertEqual(self.role_permission.permission, self.permission)
