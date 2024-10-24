# models.py
# Django models representing the incident management system

from django.db import models
from django.contrib.auth.models import AbstractUser

# User Profile with role selection
class UserProfile(AbstractUser):
    id = models.AutoField(primary_key=True, db_column='user_id')
    name = models.CharField(max_length=100, null=True)
    is_active = models.BooleanField(db_column='is_active', default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Role field for different types of users
    ROLE_CHOICES = [
        ('admin', 'Admin'),
        ('msp_superuser', 'MSP SuperUser'),
        ('msp_user', 'MSP User'),
    ]
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='msp_user')

    class Meta:
        db_table = "user_profile"


# Integration Type Model
class IntegrationType(models.Model):
    name = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "integration_type"


# MSP Integration Configuration
class IntegrationMSPConfig(models.Model):
    type = models.ForeignKey(IntegrationType, on_delete=models.CASCADE)
    company_id = models.CharField(max_length=100, default="")
    public_key = models.CharField(max_length=255, default="")
    private_key = models.CharField(max_length=255, default="")
    client_id = models.CharField(max_length=255, default="")
    client_secret = models.CharField(max_length=255, default="")
    instance_url = models.CharField(max_length=255, default="")
    access_token = models.CharField(max_length=512, blank=True, null=True)
    refresh_token = models.CharField(max_length=512, blank=True, null=True)
    expires_in = models.IntegerField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    user = models.ForeignKey(UserProfile, on_delete=models.CASCADE)

    class Meta:
        db_table = "msp_config"
        unique_together = ('user', 'type')

# Teams for MSPs
class Team(models.Model):
    name = models.CharField(max_length=255)
    msp = models.ForeignKey('IntegrationMSPConfig', on_delete=models.CASCADE)
    members = models.ManyToManyField(UserProfile, related_name='teams')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def _str_(self):
        return self.name

# Client Model (Extended with email and phone)
class Client(models.Model):
    name = models.CharField(max_length=255)
    email = models.EmailField(blank=True, null=True)  # Added email field
    phone = models.CharField(max_length=20, blank=True, null=True)  # Added phone field
    msp = models.ForeignKey(IntegrationMSPConfig, on_delete=models.CASCADE)
    team_member = models.ForeignKey(UserProfile, on_delete=models.SET_NULL, null=True, blank=True, related_name="clients")  # New field to assign a team member
    created_at = models.DateTimeField(auto_now_add=True)

    def _str_(self):
        return self.name


# Device Model
class Device(models.Model):
    client = models.ForeignKey(Client, on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    device_type = models.CharField(max_length=50)
    ip_address = models.CharField(max_length=15, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def _str_(self):
        return self.name


# Severity Level for Incidents
class Severity(models.Model):
    level = models.CharField(max_length=50, unique=True)

    def _str_(self):
        return self.level


# Incident Model
class Incident(models.Model):
    title = models.CharField(max_length=255)
    description = models.TextField()
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    severity = models.ForeignKey(Severity, on_delete=models.CASCADE)
    resolved = models.BooleanField(default=False)
    recommended_solution = models.TextField(null=True, blank=True)
    predicted_resolution_time = models.FloatField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def _str_(self):
        return self.title


# Agent Type
class AgentType(models.Model):
    name = models.CharField(max_length=100, unique=True)

    def _str_(self):
        return self.name


# Agent Model
class Agent(models.Model):
    agent_type = models.ForeignKey(AgentType, on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    status = models.CharField(max_length=20, default='available')

    def _str_(self):
        return f"{self.name} ({self.agent_type.name})"


# Task Model Related to an Incident
class Task(models.Model):
    agent = models.ForeignKey(Agent, on_delete=models.CASCADE)
    incident = models.ForeignKey(Incident, on_delete=models.CASCADE)
    task_description = models.TextField()
    completed = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    def _str_(self):
        return f"Task for {self.agent.name} on incident {self.incident.title[:30]}"