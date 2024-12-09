# Generated by Django 5.1.1 on 2024-12-05 18:14

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0017_userprofile_logo_position_userprofile_logo_shape'),
    ]

    operations = [
        migrations.CreateModel(
            name='JiraTicket',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('issue_key', models.CharField(max_length=50, unique=True)),
                ('project', models.CharField(max_length=255)),
                ('summary', models.TextField()),
                ('description', models.TextField()),
                ('status', models.CharField(max_length=50)),
                ('priority', models.CharField(blank=True, max_length=50, null=True)),
                ('created_at', models.DateTimeField()),
                ('updated_at', models.DateTimeField()),
                ('resolved_at', models.DateTimeField(blank=True, null=True)),
            ],
        ),
        migrations.AlterField(
            model_name='userprofile',
            name='role',
            field=models.CharField(choices=[('admin', 'Admin'), ('msp_superuser', 'MSP SuperUser'), ('msp_user', 'MSP User'), ('gl', 'GL')], default='msp_user', max_length=20),
        ),
        migrations.AddField(
            model_name='incident',
            name='jira_ticket',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='related_incidents', to='core.jiraticket'),
        ),
    ]