# Generated by Django 5.1.1 on 2024-11-01 15:19

import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0010_incidentlog'),
    ]

    operations = [
        migrations.AlterField(
            model_name='incidentlog',
            name='assigned_at',
            field=models.DateTimeField(default=django.utils.timezone.now),
        ),
    ]