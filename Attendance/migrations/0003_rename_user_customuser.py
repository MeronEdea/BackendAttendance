# Generated by Django 4.1.13 on 2024-05-06 22:03

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('Attendance', '0002_rename_customuser_user'),
    ]

    operations = [
        migrations.RenameModel(
            old_name='User',
            new_name='CustomUser',
        ),
    ]
