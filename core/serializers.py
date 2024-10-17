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

class ClientSerializer(serializers.ModelSerializer):
    class Meta:
        model = Client
        fields = '_all_'

class DeviceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Device
        fields = '_all_'

class IncidentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Incident
        fields = '_all_'