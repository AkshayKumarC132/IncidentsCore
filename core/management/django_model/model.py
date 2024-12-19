# models.py
# Django models representing the incident management system

from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
from django.utils.timezone import now
from datetime import timedelta

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
        ('gl', 'GL'),  # Replace God-Like with GL
    ]
    role = models.CharField(
        max_length=20, choices=ROLE_CHOICES, default='msp_user')
    # New fields for preferences
    theme = models.CharField(max_length=10, choices=[(
        'light', 'Light'), ('dark', 'Dark')], default='light')
    notifications = models.BooleanField(default=True)
    layout = models.CharField(max_length=20, choices=[(
        'default', 'Default'), ('compact', 'Compact'), ('spacious', 'Spacious')], default='default')
    background_color = models.CharField(
        max_length=7, default='#e0e5ec')  # Default color for neumorphism
    shadow_color = models.CharField(
        max_length=7, default='#a3b1c6')      # Default shadow color

    # New fields for menu position and logo URL
    menu_position = models.CharField(
        max_length=10, choices=[('top', 'Top'), ('left', 'Left')], default='top')
    logo_url = models.ImageField(upload_to='logos/', null=True, blank=True)
    font_style = models.CharField(max_length=50, default="Arial")  # Font family
    font_size = models.IntegerField(default=14)  # Font size in pixels
    font_color = models.CharField(max_length=7, default="#000000")  # Hex color for font
    logo_shape = models.CharField(max_length=50, default="rectangle")
    logo_position = models.CharField(max_length=50, default="top-left")

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
    # Jira-specific fields
    jira_api_base_url = models.URLField(max_length=255,blank=True, null=True)
    jira_user_email = models.EmailField(max_length=255,blank=True, null=True)
    jira_api_token = models.CharField(max_length=512,blank=True, null=True)
    jira_project_key = models.CharField(max_length=50,blank=True, null=True)
    jira_project_name = models.CharField(max_length=255, default="")  # New Field

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
    phone = models.CharField(max_length=20, blank=True,
                             null=True)  # Added phone field
    msp = models.ForeignKey(IntegrationMSPConfig, on_delete=models.CASCADE)
    team_member = models.ForeignKey(UserProfile, on_delete=models.SET_NULL, null=True,
                                    blank=True, related_name="clients")  # New field to assign a team member
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
    human_intervention_needed = models.BooleanField(default=False)  # New field
    assigned_agent = models.ForeignKey(
        UserProfile, on_delete=models.SET_NULL, null=True, related_name='assigned_incidents')
    assigned_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    pagent = models.CharField(max_length=50, null=True, blank=True)  # New column for Predicted Agent
    jira_ticket = models.ForeignKey(
        "JiraTicket", on_delete=models.SET_NULL, null=True, blank=True, related_name="related_incidents"
    )  # New field linking Jira tickets
    confidence_score = models.FloatField(null=True, blank=True)  # Confidence %

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


class IncidentLog(models.Model):
    incident = models.ForeignKey(Incident, on_delete=models.CASCADE)
    # Could be 'network', 'security', etc.
    assigned_agent = models.CharField(max_length=50)
    assigned_at = models.DateTimeField(default=timezone.now)
    resolution_started_at = models.DateTimeField(null=True, blank=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    # In hours, calculated after resolution
    resolution_time = models.FloatField(null=True, blank=True)

    class Meta:
        db_table = 'incident_log'

class Notification(models.Model):
    user = models.ForeignKey(UserProfile, on_delete=models.CASCADE)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    read = models.BooleanField(default=False)

    def _str_(self):
        return f"Notification for {self.user.username}"
    
class TicketHistory(models.Model):
    incident = models.ForeignKey(Incident, on_delete=models.CASCADE)
    action = models.CharField(max_length=255)
    performed_by = models.ForeignKey(UserProfile, on_delete=models.CASCADE, null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    def _str_(self):
        return f"{self.incident.title} - {self.action}"
    
class ScreenRecording(models.Model):
    is_recording = models.BooleanField(default=False)
    file_path = models.CharField(max_length=255, null=True)
    incident = models.IntegerField(null=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    archived_at = models.DateTimeField(null=True, blank=True)

    def is_archivable(self):
        return now() > self.uploaded_at + timedelta(days=90)

class KnoxAuthtoken(models.Model):
    digest = models.CharField(primary_key=True, max_length=128)
    created = models.DateTimeField()
    user = models.ForeignKey(UserProfile, models.CASCADE, null=True, blank=True, db_column='user_id')
    expiry = models.DateTimeField(blank=True, null=True)
    token_key = models.CharField(max_length=8, null=True, blank=True)

    class Meta:
        managed = False
        db_table = 'knox_authtoken'

class JiraTicket(models.Model):
    issue_key = models.CharField(max_length=50)  # Unique Jira issue identifier
    project = models.CharField(max_length=255)
    summary = models.TextField()
    description = models.TextField()
    status = models.CharField(max_length=50)
    priority = models.CharField(max_length=50, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    user = models.ForeignKey(UserProfile, on_delete=models.SET_NULL, null=True, blank=True)  # New field for the associated user profile
    predicted_agent = models.CharField(max_length=50, null=True, blank=True)  # e.g., Software, Human
    confidence_score = models.FloatField(null=True, blank=True)  # Confidence %
    predicted_category = models.CharField(max_length=50, null=True, blank=True)  # Bug, Feature Request, etc.
    predicted_resolution_time = models.FloatField(null=True, blank=True)  # Predicted resolution time (hours/days)

    class Meta:
        unique_together = ('user', 'issue_key')  # Ensures uniqueness per user and issue_key

    def _str_(self):
        return f"{self.project} - {self.issue_key}"

class ActiveModel(models.Model):
    MODEL_TYPE_CHOICES = [
        ('jira', 'Jira Model'),
        ('incident', 'Incident Model'),
    ]

    user = models.ForeignKey(UserProfile, on_delete=models.SET_NULL, null=True, blank=True)  # New field for the associated user profile
    model_type = models.CharField(max_length=20, choices=MODEL_TYPE_CHOICES)
    model_name = models.CharField(max_length=255)  # Name of the active model file
    activated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('model_type',)  # Ensure only one active model per type

    def _str_(self):
        return f"{self.model_type}: {self.model_name}"
    
class MLModel(models.Model):
    name = models.CharField(max_length=255)
    type = models.CharField(max_length=100)  # e.g., 'JIRA', 'Incident'
    status = models.CharField(
        max_length=50, choices=[('Active', 'Active'), ('Inactive', 'Inactive')]
    )
    dependencies = models.ManyToManyField('self', blank=True, symmetrical=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def _str_(self):
        return self.name
    

class ModelManagement(models.Model):
    name = models.CharField(max_length=255, unique=True)
    file = models.FileField(upload_to='models/', null=True)
    size = models.FloatField(default=0)  # Store size in KB
    status = models.CharField(
        max_length=10,
        choices=[('active', 'Active'), ('inactive', 'Inactive')],
        default='inactive'
    )
    parameters = models.JSONField(default=dict)  # Store editable parameters

    uploaded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'model_management'
        verbose_name = 'Model Management'
        verbose_name_plural = 'Model Management'

    def _str_(self):
        return f"{self.name} ({self.status})"