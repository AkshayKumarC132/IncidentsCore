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

class IntegrationTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = IntegrationType
        fields = ['id', 'name']  # Include 'id' if you need it, or remove if not necessary

class MspSerializer(serializers.ModelSerializer):
    type_name = serializers.CharField(source='type.name', read_only=True)  # Get the type name
    class Meta:
        model = IntegrationMSPConfig
        fields = ['id', 'company_id', 'type_name']  # Add other fields if necessary       
        
# User Profile Serializer
# class UserProfileSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = UserProfile
#         fields = ['id', 'username', 'email', 'is_active','password']

# User Profile Serializer
class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ['id', 'username', 'email', 'name', 'role', 'is_active', 'created_at']
        
class TeamSerializer(serializers.ModelSerializer):
    members = UserProfileSerializer(many=True, read_only=True)  # Make it read-only in the serializer

    class Meta:
        model = Team
        fields = ['id', 'name', 'msp', 'members', 'created_at', 'updated_at']

    def create(self, validated_data):
        members_data = self.initial_data.get('members')  # Get members data from the initial input
        team = Team.objects.create(**validated_data)  # Create the team instance
        if members_data:
            for member_id in members_data:
                user = UserProfile.objects.get(id=member_id)
                team.members.add(user)  # Add each member to the team
        team.save()
        return team

    def update(self, instance, validated_data):
        members_data = self.initial_data.get('members')  # Get members data from the input
        instance = super().update(instance, validated_data)  # Update the other fields normally
        if members_data:
            instance.members.clear()  # Clear the current members
            for member_id in members_data:
                user = UserProfile.objects.get(id=member_id)
                instance.members.add(user)  # Add the new members
        instance.save()
        return instance



# IntegrationType Serializer
# Serializer for IntegrationType
class IntegrationTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = IntegrationType
        fields = ['id', 'name', 'created_at']

# Serializer for MSP Configuration
class IntegrationMSPConfigSerializer(serializers.ModelSerializer):
    type = IntegrationTypeSerializer(read_only=True)  # Display integration type name in response
    type_id = serializers.PrimaryKeyRelatedField(queryset=IntegrationType.objects.all(), write_only=True)

    class Meta:
        model = IntegrationMSPConfig
        fields = [
            'id', 'type', 'type_id', 'company_id', 'public_key', 'private_key',
            'client_id', 'client_secret', 'instance_url', 'access_token', 'refresh_token',
            'expires_in', 'created_at', 'updated_at', 'user'
        ]
        extra_kwargs = {
            'access_token': {'read_only': True},
            'refresh_token': {'read_only': True},
            'user': {'read_only': True}
        }

    def create(self, validated_data):
        # Assign the current user to the MSP config
        user = self.context['request'].user
        validated_data['user'] = user
        return super().create(validated_data)

# Client Serializer
class ClientSerializer(serializers.ModelSerializer):
    team_member = UserProfileSerializer()

    class Meta:
        model = Client
        fields = ['id', 'name', 'email', 'phone', 'msp', 'team_member', 'created_at']

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
        
        
class TeamSerializerr(serializers.ModelSerializer):
    members = serializers.PrimaryKeyRelatedField(queryset=UserProfile.objects.all(), many=True)

    class Meta:
        model = Team
        fields = ['id', 'name', 'msp', 'members', 'created_at', 'updated_at']
        read_only_fields = ['created_at', 'updated_at']
        
class ClientSerializerr(serializers.ModelSerializer):
    team_member = UserProfileSerializer(read_only=True)  # For one-to-one relationship
    class Meta:
        model = Client
        fields = ['id', 'name', 'email', 'phone', 'msp','team_member']
        
class DeviceSerializerr(serializers.ModelSerializer):
    class Meta:
        model = Device
        fields = ['id', 'name', 'device_type', 'ip_address', 'client']
        
class IncidentSerializerr(serializers.ModelSerializer):
    class Meta:
        model = Incident
        fields = ['id', 'title', 'description', 'severity', 'device', 'recommended_solution', 'predicted_resolution_time', 'resolved']