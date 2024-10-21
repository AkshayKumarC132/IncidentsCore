# Generated by Django 5.1.1 on 2024-10-20 15:30

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0005_client_email_client_phone'),
    ]

    operations = [
        migrations.AddField(
            model_name='userprofile',
            name='role',
            field=models.CharField(choices=[('admin', 'Admin'), ('msp_superuser', 'MSP SuperUser'), ('msp_user', 'MSP User')], default='msp_user', max_length=20),
        ),
        migrations.CreateModel(
            name='Team',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('members', models.ManyToManyField(related_name='teams', to=settings.AUTH_USER_MODEL)),
                ('msp', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='core.integrationmspconfig')),
            ],
        ),
    ]
