# models.py
# Django models representing the incident management system

from django.db import models
from django.contrib.auth.models import AbstractUser

class UserProfile(AbstractUser):
    id = models.AutoField(primary_key=True,db_column='user_id')
    name = models.CharField(max_length=100,null=True)
    is_active = models.BooleanField(db_column='is_active',default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table="user_profile"

class IntegrationType(models.Model):
    name = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table="integration_type"
    
class IntegrationMSPConfig(models.Model):
    type = models.ForeignKey(IntegrationType,on_delete=models.CASCADE)
    company_id = models.CharField(max_length=100,default="")
    public_key = models.CharField(max_length=255,default="")
    private_key = models.CharField(max_length=255,default="")
    client_id = models.CharField(max_length=255,default="")
    client_secret = models.CharField(max_length=255,default="")
    instance_url = models.CharField(max_length=255,default="")
    access_token = models.CharField(max_length=512, blank=True, null=True)  # New field for access token
    refresh_token = models.CharField(max_length=512, blank=True, null=True)  # New field for refresh token
    expires_in = models.IntegerField(blank=True, null=True)  # New field for expiry duration in seconds
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    user = models.ForeignKey(UserProfile, on_delete=models.CASCADE)
    
    class Meta:
        db_table="msp_config"
        unique_together = ('user', 'type')  # Ensure user and type combination is unique


class Client(models.Model):
    name = models.CharField(max_length=255)
    msp = models.ForeignKey(IntegrationMSPConfig, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    def _str_(self):
        return self.name

class Device(models.Model):
    client = models.ForeignKey(Client, on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    device_type = models.CharField(max_length=50)
    ip_address = models.CharField(max_length=15, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def _str_(self):
        return self.name
    
class Severity(models.Model):
    level = models.CharField(max_length=50, unique=True)

    def __str__(self):
        return self.level

class Incident(models.Model):
    title = models.CharField(max_length=255)
    description = models.TextField()
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    severity = models.ForeignKey(Severity,on_delete=models.CASCADE)
    resolved = models.BooleanField(default=False)
    recommended_solution = models.TextField(null=True, blank=True)
    predicted_resolution_time = models.FloatField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def _str_(self):
        return self.title
    
    # Define different types of agents (Network, Security, Hardware, etc.)
class AgentType(models.Model):
    name = models.CharField(max_length=100, unique=True)  # Example: Network, Security, Hardware

    def _str_(self):
        return self.name

# Define specific agents
class Agent(models.Model):
    agent_type = models.ForeignKey(AgentType, on_delete=models.CASCADE)
    name = models.CharField(max_length=100)  # Example: NetworkAgent1, SecurityAgent1
    status = models.CharField(max_length=20, default='available')  # Tracks if agent is busy or available

    def _str_(self):
        return f"{self.name} ({self.agent_type.name})"

# Define real-life incidents (e.g., network outage, security breach)
# Define the tasks related to incidents (e.g., restart device, reroute traffic, block IP)
class Task(models.Model):
    agent = models.ForeignKey(Agent, on_delete=models.CASCADE)
    incident = models.ForeignKey(Incident, on_delete=models.CASCADE)
    task_description = models.TextField()  # Example: Restart router to fix outage
    completed = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    def _str_(self):
        return f"Task for {self.agent.name} on incident {self.incident.description[:30]}"