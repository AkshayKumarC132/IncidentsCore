# serializers.py
# Django REST framework serializers for incident management

from rest_framework import serializers
from .models import *

class RegisterSerializer(serializers.Serializer):
    username = serializers.CharField()
    email = serializers.CharField()
    password = serializers.CharField()
    
    
class LoginSerialzier(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()

class MSPSerializer(serializers.ModelSerializer):
    class Meta:
        model = IntegrationMSPConfig
        fields = '_all_'        
        
# User Profile Serializer
# class UserProfileSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = UserProfile
#         fields = ['id', 'username', 'email', 'is_active','password']


# IntegrationType Serializer
class IntegrationTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = IntegrationType
        fields = ['id', 'name']


# MSP Integration Configuration Serializer
class IntegrationMSPConfigSerializer(serializers.ModelSerializer):
    type = IntegrationTypeSerializer()

    class Meta:
        model = IntegrationMSPConfig
        fields = ['id', 'type', 'company_id', 'public_key', 'private_key', 'client_id', 'client_secret', 'instance_url', 'access_token', 'refresh_token', 'expires_in']


# Client Serializer
class ClientSerializer(serializers.ModelSerializer):
    class Meta:
        model = Client
        fields = ['id', 'name', 'email', 'phone', 'msp', 'created_at']

# Device Serializer
class DeviceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Device
        fields = ['id', 'name', 'device_type', 'client', 'ip_address', 'created_at']

# Severity Serializer
class SeveritySerializer(serializers.ModelSerializer):
    class Meta:
        model = Severity
        fields = ['id', 'level']

# Incident Serializer
class IncidentSerializer(serializers.ModelSerializer):
    severity = SeveritySerializer()
    device = DeviceSerializer()

    class Meta:
        model = Incident
        fields = ['id', 'title', 'description', 'device', 'severity', 'resolved', 'recommended_solution', 'predicted_resolution_time', 'created_at']

# Agent Serializer
class AgentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Agent
        fields = ['id', 'name', 'agent_type', 'status']

# Task Serializer
class TaskSerializer(serializers.ModelSerializer):
    agent = AgentSerializer()
    incident = IncidentSerializer()

    class Meta:
        model = Task
        fields = ['id', 'agent', 'incident', 'task_description', 'completed', 'created_at', 'completed_at']