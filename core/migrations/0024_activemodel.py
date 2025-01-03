# Generated by Django 5.1.1 on 2024-12-18 18:28

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0023_incident_confidence_score_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='ActiveModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('model_type', models.CharField(choices=[('jira', 'Jira Model'), ('incident', 'Incident Model')], max_length=20)),
                ('model_name', models.CharField(max_length=255)),
                ('activated_at', models.DateTimeField(auto_now=True)),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'unique_together': {('model_type',)},
            },
        ),
    ]
