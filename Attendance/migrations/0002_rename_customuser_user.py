# Generated by Django 4.1.13 on 2024-05-06 22:01

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('Attendance', '0001_initial'),
    ]

    operations = [
        migrations.RenameModel(
            old_name='CustomUser',
            new_name='User',
        ),
    ]