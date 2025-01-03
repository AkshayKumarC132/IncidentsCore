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
        # Include 'id' if you need it, or remove if not necessary
        fields = ['id', 'name']


class MspSerializer(serializers.ModelSerializer):
    type_name = serializers.CharField(
        source='type.name', read_only=True)  # Get the type name

    class Meta:
        model = IntegrationMSPConfig
        # Add other fields if necessary
        fields = ['id', 'company_id', 'type_name']

# User Profile Serializer
# class UserProfileSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = UserProfile
#         fields = ['id', 'username', 'email', 'is_active','password']

# User Profile Serializer


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ['id', 'username', 'email', 'name', 'role', 'is_active', 'created_at', 'theme',
                  'notifications', 'layout', 'background_color', 'shadow_color', 'menu_position', 'logo_url',
                  'font_style','font_size','font_color','logo_position','logo_shape']


class TeamSerializer(serializers.ModelSerializer):
    # Make it read-only in the serializer
    members = UserProfileSerializer(many=True, read_only=True)

    class Meta:
        model = Team
        fields = ['id', 'name', 'msp', 'members', 'created_at', 'updated_at']

    def create(self, validated_data):
        # Get members data from the initial input
        members_data = self.initial_data.get('members')
        # Create the team instance
        team = Team.objects.create(**validated_data)
        if members_data:
            for member_id in members_data:
                user = UserProfile.objects.get(id=member_id)
                team.members.add(user)  # Add each member to the team
        team.save()
        return team

    def update(self, instance, validated_data):
        members_data = self.initial_data.get(
            'members')  # Get members data from the input
        # Update the other fields normally
        instance = super().update(instance, validated_data)
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
    # Display integration type name in response
    type = IntegrationTypeSerializer(read_only=True)
    type_id = serializers.PrimaryKeyRelatedField(
        queryset=IntegrationType.objects.all(), write_only=True)

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
        fields = ['id', 'name', 'email', 'phone',
                  'msp', 'team_member', 'created_at']

# Device Serializer


class DeviceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Device
        fields = ['id', 'name', 'device_type',
                  'client', 'ip_address', 'created_at']

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
        fields = ['id', 'title', 'description', 'device', 'severity', 'resolved',
                  'recommended_solution', 'predicted_resolution_time', 'created_at','pagent']

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
        fields = ['id', 'agent', 'incident', 'task_description',
                  'completed', 'created_at', 'completed_at']


class TeamSerializerr(serializers.ModelSerializer):
    members = serializers.PrimaryKeyRelatedField(
        queryset=UserProfile.objects.all(), many=True)

    class Meta:
        model = Team
        fields = ['id', 'name', 'msp', 'members', 'created_at', 'updated_at']
        read_only_fields = ['created_at', 'updated_at']


class ClientSerializerr(serializers.ModelSerializer):
    team_member = UserProfileSerializer(
        read_only=True)  # For one-to-one relationship
    msp = IntegrationMSPConfigSerializer(read_only = True)

    class Meta:
        model = Client
        fields = ['id', 'name', 'email', 'phone', 'msp', 'team_member']


class DeviceSerializerr(serializers.ModelSerializer):
    client = ClientSerializerr(read_only = True)
    class Meta:
        model = Device
        fields = ['id', 'name', 'device_type', 'ip_address', 'client']

class JiraTicketSerializer(serializers.ModelSerializer):
    class Meta:
        model = JiraTicket
        fields = ["id", "issue_key", "project", "summary", "description", "status", "priority"]

class IncidentSerializerr(serializers.ModelSerializer):
    jira_ticket = JiraTicketSerializer(read_only=True)
    device = DeviceSerializerr(read_only=True)

    class Meta:
        model = Incident
        fields = '__all__'  # This line includes all fields from the model


class IncidentSerializers(serializers.ModelSerializer):
    severity_level = serializers.SerializerMethodField()
    device_name = serializers.SerializerMethodField()

    class Meta:
        model = Incident
        fields = [
            'id', 'title', 'description', 'device', 'severity', 'severity_level',
            'device_name', 'resolved', 'recommended_solution', 'predicted_resolution_time',
            'human_intervention_needed', 'created_at'
        ]

    def get_severity_level(self, obj):
        return obj.severity.level  # Assuming 'level' is the attribute in Severity

    def get_device_name(self, obj):
        return obj.device.name  # Assuming 'name' is the attribute in Device
    
    
class IncidentLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = IncidentLog
        fields = ['id', 'incident', 'assigned_agent', 'assigned_at', 'resolved_at', 'resolution_time']
        
class IntegrationMSPConfigSerializer(serializers.ModelSerializer):
    class Meta:
        model = IntegrationMSPConfig
        fields = ['type', 'company_id', 'public_key', 'client_id', 'instance_url']

class IntegrationStatusSerializer(serializers.ModelSerializer):
    class Meta:
        model = IntegrationType
        fields = ['id', 'name']

class IntegrationDetailsSerializer(serializers.Serializer):
    project_count = serializers.IntegerField(required=False)
    ticket_count = serializers.IntegerField(required=False)
    client_count = serializers.IntegerField(required=False)
    last_sync = serializers.DateTimeField(required=False)
    sync_enabled = serializers.BooleanField(required=False)
    status = serializers.CharField(required=False)
    error_message = serializers.CharField(required=False)

class ConnectedIntegrationSerializer(serializers.ModelSerializer):
    integration_type = serializers.CharField(source='type.name')
    status = serializers.SerializerMethodField()
    details = IntegrationDetailsSerializer(required=False)
    
    class Meta:
        model = IntegrationMSPConfig
        fields = [
            'id', 
            'integration_type',
            'status',
            'company_id',
            'instance_url',
            'created_at',
            'updated_at',
            'details',
            'jira_api_base_url',
        ]

    def get_status(self, obj):
        if not obj.type:
            return 'Configuration Error'
            
        status_checks = {
            'Jira': self._check_jira_status,
            'ConnectWise': self._check_connectwise_status,
            'HaloPSA': self._check_halopsa_status
        }
        
        check_function = status_checks.get(obj.type.name)
        if check_function:
            return check_function(obj)
        return 'Unknown'

    def _check_jira_status(self, obj):
        if not obj.jira_api_base_url or not obj.jira_api_token:
            return 'Configuration Required'
        if not getattr(obj, 'jira_sync_enabled', True):
            return 'Sync Disabled'
        return 'Active'

    def _check_connectwise_status(self, obj):
        if not obj.private_key or not obj.public_key:
            return 'Configuration Required'
        return 'Active'

    def _check_halopsa_status(self, obj):
        if not obj.client_secret or not obj.client_id:
            return 'Configuration Required'
        return 'Active'
    
class MLModelSerializer(serializers.ModelSerializer):
    class Meta:
        model = MLModel
        fields = '__all__'