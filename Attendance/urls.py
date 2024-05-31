from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path("", views.home, name="home"),
    path('api/register/', views.register_user, name='register_user'),
    path('api/login/', views.login_user, name='login_user'),
    path('api/activity-logs/', views.get_activity_logs, name='get_activity_logs'),
    path('api/profile/', views.user_profile, name='user_profile'),
    path('api/updateprofile/', views.update_profile, name='update_profile'),
    path('api/generate_otp/', views.send_otp, name='send_otp'),
    path('api/update_password/', views.update_password, name='update_password'),
     path('api/students/', views.StudentList.as_view(), name='student-list'),
    path('api/create_permission/', views.create_permission_request, name='create_permission_request'),
    path('api/students_permission/', views.get_permission_requests, name='get_student_permissions'),
    path('api/get_permission_details/<int:permission_id>/', views.get_permission_details, name='get_permission_details'),
    path('api/approve-permission/<int:permission_id>/', views.approve_permission, name='approve_permission'),
    path('api/reject-permission/<int:permission_id>/', views.reject_permission, name='reject_permission'),
    path('api/courses/', views.course_list, name='course-list'),
    path('api/courses/<int:pk>/', views.course_detail, name='course-detail'),
    path('api/join_course/', views.join_course, name='join_course'),
    path('api/student_courses/', views.student_courses, name='student_courses'),

    path('api/attendance/', views.AttendanceRecordList.as_view(), name='attendance-list'),
    path('api/attendance/create/', views.AttendanceCreate.as_view(), name='attendance-create'),
    path('api/users/', views.UserList.as_view(), name='user_list'),  
    path('api/Attendance/', views.AttendanceList.as_view(), name='attendance_list'), #returns attendance list
    path('Courses/', views.CourseList.as_view(), name='course_list'),
    path('', views.AttendanceRecordList.as_view(), name='attendance-list'),
    path('api/attendance/', views.AttendanceListByStatus.as_view(), name='attendance-list'),
    # path('users/', views.UserListView.as_view(), name='user-list'),
    # path('users/<int:pk>/', views.UserDetailView.as_view(), name='user-detail'),


    path("api/add_teacher/", views.add_teacher, name="add_teacher"),
    path("api/teachers/", views.get_teachers, name="get_teachers"),
    path("api/edit_teacher/<int:id>/", views.edit_teacher, name="edit_teacher"),
    path('api/display_schedule/', views.display_schedule, name='display_schedule_api'),
    # path('api/send_schedule_reminder/', views.send_schedule_reminder, name='send_schedule_reminder'),
    path('api/delete_teacher/<str:id>/', views.delete_teacher, name='delete_teacher'),
    # path('delete_schedule/<int:schedule_id>/', views.delete_schedule, name='delete_schedule'),
    # path('add_schedule/', views.add_schedule, name='add_schedule'),
    # path('api/delete_schedule/<str:id>/', views.delete_schedule, name='delete_schedule'),

    path('api/unassigned-courses/', views.unassigned_courses_view, name='unassigned_courses'),

    path('api/upload_schedule/', views.upload_schedule, name='upload_schedule'),

    path('api/choose-course/', views.choose_course, name='choose_course'),
    path('api/manage-course-choices/', views.manage_course_choices, name='manage_course_choices'),

    path('api/teacher-courses/', views.teacher_courses_view, name='teacher-courses'),
    path('api/username/', views.get_username, name='get_username'),
    path('api/notifications/', views.get_user_notifications, name='user_notifications'),

    path('api/roles/', views.RoleListCreateView.as_view(), name='role-list-create'),
    path('api/roles/<int:pk>/', views.RoleDetailView.as_view(), name='role-detail'),
    path('api/permissions/', views.PermissionListCreateView.as_view(), name='permission-list-create'),
    path('api/permissions/<int:pk>/', views.PermissionDetailView.as_view(), name='permission-detail'),
    path('api/role-permissions/', views.update_role_permissions, name='update-role-permissions'),

]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)