from rest_framework.generics import CreateAPIView
from rest_framework.decorators import api_view
from django.contrib.auth.models import User
from rest_framework.response import Response
from rest_framework import status
from django.db import transaction
from django.contrib.auth import authenticate, login, logout
from django.views.decorators.csrf import csrf_exempt
from pytz import utc
from .serializers import *
from .models import *
from rest_framework import status
from django.contrib.auth.decorators import login_required
from rest_framework import generics, permissions
from django.utils.decorators import method_decorator
from django.contrib.auth.decorators import login_required
from rest_framework.views import APIView
from django.db.models import Avg,Count
from django.shortcuts import render
from django.http import HttpResponse
import pandas as pd
from datetime import datetime
from django.shortcuts import redirect
from django.core.paginator import Paginator
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
import base64
from incidentmanagement.settings import TestConnectWiseCredentialsViaURL,TestHaloPSACredentialsViaURL,ConnectWiseClientId
import requests
from django.http import JsonResponse
from rest_framework.decorators import api_view,permission_classes,action
from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.hashers import make_password
from django.db import IntegrityError  # Importing IntegrityError to handle duplicate entries
from rest_framework.authtoken.models import Token
from rest_framework.permissions import AllowAny
from django.contrib.auth import get_user_model


@api_view(['POST'])
@permission_classes([AllowAny])
def register(request):
    required_fields = ['username', 'email', 'password', 'name']

    # Check if required fields are present and not empty
    missing_or_empty_fields = [
        field for field in required_fields
        if field not in request.data or not request.data[field].strip()
    ]

    if missing_or_empty_fields:
        return Response(
            {"error": f"Fields cannot be null or empty: {', '.join(missing_or_empty_fields)}"},
            status=status.HTTP_400_BAD_REQUEST
        )

    # Extracting fields
    username = request.data['username']
    email = request.data['email']
    password = request.data['password']
    name = request.data['name']
    role = request.data.get('role', 'msp_user')  # Default to 'msp_user' if not provided

    # Validate if role is one of the allowed choices
    allowed_roles = ['admin', 'msp_superuser', 'msp_user']
    if role not in allowed_roles:
        return Response(
            {"error": f"Invalid role. Allowed roles are: {', '.join(allowed_roles)}"},
            status=status.HTTP_400_BAD_REQUEST
        )
    if UserProfile.objects.filter(email = email).exists():
        return Response(
            {"error": "Email already exists. Please choose a different email."},
            status=status.HTTP_400_BAD_REQUEST
        )

    try:
        # Creating the user profile
        user = UserProfile.objects.create_user(
            username=username,
            email=email,
            password=(password),
            name=name,
            role=role,
            is_active=True  # Assuming user is active upon registration
        )
        user.save()

    except IntegrityError as e:
        if 'user_profile.username' in str(e):
            return Response(
                {"error": "Username already exists. Please choose a different username."},
                status=status.HTTP_400_BAD_REQUEST
            )
        if 'user_profile.email' in str(e):
            return Response(
                {"error": "Email already exists. Please choose a different email."},
                status=status.HTTP_400_BAD_REQUEST
            )
        return Response(
            {"error": "An error occurred during registration."},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

    # Serialize and return the newly created user profile
    serializer = UserProfileSerializer(user)
    return Response(serializer.data, status=status.HTTP_201_CREATED)


class LoginViewAPI(APIView):
    serializer_class = LoginSerialzier
    permission_classes = [AllowAny]  # Allow anyone to access this view
    
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']
            # Authenticate the user
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                # Get or create the token for the user
                token, created = Token.objects.get_or_create(user=user)
                
                profile = UserProfile.objects.filter(username = username).values()
                return Response(
                    {
                        'message':"Login Successfull",
                        "data":profile,
                        'token': token.key,  # Return the token
                    }
                )
            else:
                return Response({'message': "Invalid username or password"}, status=status.HTTP_401_UNAUTHORIZED)

class LogoutViewAPI(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            up = UserProfile.objects.get(username = request.user)
            token = Token.objects.get(user = up)
            # Get the token from the request
            # token = request.auth
            # Check if the token exists
            if token:
                token.delete()  # Delete the token
            return Response({'message': 'Logout successful.'})
        except Exception as e:
            return Response({'error': str(e)}, status=400)

# View to List and Create Integration Types (Admin or Superuser access)
class IntegrationTypeView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Get the list of available integration types
        integration_types = IntegrationType.objects.all()
        serializer = IntegrationTypeSerializer(integration_types, many=True)
        return Response(serializer.data)

    def post(self, request):
        # Only allow admins or superusers to create new integration types
        if request.user.role not in ['admin', 'msp_superuser']:
            return Response(
                {"error": "You do not have permission to create integration types."},
                status=status.HTTP_403_FORBIDDEN
            )
        serializer = IntegrationTypeSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# View to setup MSP integration configuration
# Assuming ConnectWise and HaloPSA endpoints and client IDs are defined elsewhere
ConnectWiseClientId = "006d3e9d-26aa-461b-914c-1b6901beea3b"
TestConnectWiseCredentialsViaURL = "https://api-staging.connectwisedev.com/v2022_2/apis/3.0/service/tickets"
TestHaloPSACredentialsViaURL = "https://xamplify.halopsa.com/auth/token"

class IntegrationMSPConfigView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Only MSP admins or superusers can set up integrations
        if request.user.role not in ['admin', 'msp_superuser']:
            return Response(
                {"error": "You do not have permission to set up MSP integrations."},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Extract necessary fields from request
        type_id = request.data.get('type_id')
        company_id = request.data.get('company_id', "")
        public_key = request.data.get('public_key', "")
        private_key = request.data.get('private_key', "")
        client_id = request.data.get('client_id', "")
        client_secret = request.data.get('client_secret', "")
        instance_url = request.data.get('instance_url', "")

        # Get integration type instance
        type_instance = get_object_or_404(IntegrationType, id=type_id)
        user = request.user

        # Check if a configuration already exists for the user and the type
        config, created = IntegrationMSPConfig.objects.get_or_create(
            user=user,
            type=type_instance,
            defaults={
                'company_id': company_id,
                'public_key': public_key,
                'private_key': private_key,
                'client_id': client_id,
                'client_secret': client_secret,
                'instance_url': instance_url,
                'updated_at': datetime.now(),
            }
        )

        # If the config already exists, update it
        if not created:
            config.company_id = company_id
            config.public_key = public_key
            config.private_key = private_key
            config.client_id = client_id
            config.client_secret = client_secret
            config.instance_url = instance_url
            config.updated_at = datetime.now()

        # Handle ConnectWise integration type
        if type_instance.name == 'ConnectWise':
            auth_token = base64.b64encode(f"{company_id}+{public_key}:{private_key}".encode()).decode()
            headers = {
                "Authorization": f"Basic {auth_token}",
                "clientID": ConnectWiseClientId,
                "Content-Type": "application/json"
            }
            response = requests.get(TestConnectWiseCredentialsViaURL, headers=headers)

            # If response fails, return error
            if response.status_code != 200:
                return Response(
                    {"error": f"Failed to save configuration: {response.json()}"},
                    status=status.HTTP_400_BAD_REQUEST
                )

        # Handle HaloPSA integration type
        elif type_instance.name == 'HaloPSA':
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            payload = f'grant_type=client_credentials&client_id={client_id}&client_secret={client_secret}&scope=all'
            response = requests.post(TestHaloPSACredentialsViaURL, headers=headers, data=payload)

            # If response fails, return error
            if response.status_code != 200:
                return Response(
                    {"error": f"Failed to save configuration: {response.json()}"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Extract and save tokens
            tokens_data = response.json()
            access_token = tokens_data.get('access_token')
            config.access_token = access_token
            config.refresh_token = tokens_data.get('refresh_token')
            config.expires_in = tokens_data.get('expires_in')

            # Fetch and save clients data from HaloPSA
            halo_headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
            client_response = requests.get(f"{instance_url}/api/Client", headers=halo_headers)

            if client_response.status_code == 200:
                clients_data = client_response.json().get('clients', [])
                for client_data in clients_data:
                    client, _ = Client.objects.update_or_create(
                        name=client_data['name'],
                        msp=config,
                        defaults={'created_at': datetime.now()}
                    )

            # Fetch and save tickets and associated devices from HaloPSA
            tickets_response = requests.get(f"{instance_url}/api/Tickets", headers=halo_headers)
            if tickets_response.status_code == 200:
                tickets_data = tickets_response.json().get('tickets', [])
                for ticket in tickets_data:
                    severity, _ = Severity.objects.get_or_create(id=ticket['priority_id'])
                    ticket_client_id = ticket['client_id']

                    if ticket_client_id:
                        # Fetch devices for the client
                        device_response = requests.get(
                            f"{instance_url}/api/Asset",
                            headers=halo_headers,
                            params={"client_id": ticket_client_id}
                        )
                        if device_response.status_code == 200:
                            devices_data = device_response.json().get('assets', [])
                            for device_data in devices_data:
                                device_name = f"{device_data['inventory_number']} {device_data['key_field']}"
                                device, _ = Device.objects.update_or_create(
                                    name=device_name,
                                    client=client,
                                    defaults={'created_at': datetime.now()}
                                )

                                # Create or update incidents for the device
                                Incident.objects.update_or_create(
                                    title=ticket['summary'],
                                    device=device,
                                    defaults={
                                        'description': ticket['details'],
                                        'severity': severity,
                                        'resolved': ticket.get('resolved', False),
                                        'recommended_solution': ticket.get('recommended_solution', ''),
                                        'predicted_resolution_time': ticket.get('predicted_resolution_time', 0),
                                        'created_at': datetime.now(),
                                    }
                                )

        # Save the configuration after validation
        config.save()
        return Response(
            {"message": "Integration configuration saved successfully."},
            status=status.HTTP_201_CREATED
        )

    def get(self, request):
        # Get the MSP config for the current user (admins can view all configs)
        if request.user.role == 'admin':
            configs = IntegrationMSPConfig.objects.all()
        else:
            configs = IntegrationMSPConfig.objects.filter(user=request.user)
        serializer = IntegrationMSPConfigSerializer(configs, many=True)
        return Response(serializer.data)
    
class TeamManagementAPI(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Ensure only admins and superusers can create teams
        if request.user.role not in ['admin', 'msp_superuser']:
            return Response(
                {"error": "You do not have permission to create teams."},
                status=status.HTTP_403_FORBIDDEN
            )

        # Extract team name and MSP configuration ID from request data
        team_name = request.data.get('name')
        msp_id = request.data.get('msp_id')
        member_ids = request.data.get('members', [])

        # Validate input
        if not team_name or not msp_id:
            return Response(
                {"error": "Team name and MSP configuration ID are required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Get the MSP configuration object
        msp = get_object_or_404(IntegrationMSPConfig, id=msp_id)

        # Only allow users within the same MSP configuration to be added
        members = UserProfile.objects.filter(id__in=member_ids, role__in=['admin', 'msp_superuser', 'msp_user'])

        # Create the team and assign members
        team = Team.objects.create(name=team_name, msp=msp)
        team.members.set(members)
        team.save()

        # Serialize the response
        serializer = TeamSerializerr(team)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def get(self, request, team_id=None):
        # Allow only MSP admins and superusers to view teams
        if request.user.role not in ['admin', 'msp_superuser']:
            return Response(
                {"error": "You do not have permission to view teams."},
                status=status.HTTP_403_FORBIDDEN
            )

        if team_id is None:
            # Filter teams by the MSP configuration the user is linked to
            teams = Team.objects.filter(msp__user=request.user)
            serializer = TeamSerializer(teams, many=True)
            return Response(serializer.data)
        else:
            # Fetch a specific team
            team = get_object_or_404(Team, id=team_id, msp__user=request.user)
            serializer = TeamSerializer(team)
            return Response(serializer.data)

    def put(self, request, team_id):
        # Ensure only admins and superusers can modify teams
        if request.user.role not in ['admin', 'msp_superuser']:
            return Response(
                {"error": "You do not have permission to update teams."},
                status=status.HTTP_403_FORBIDDEN
            )

        # Fetch the team object
        team = get_object_or_404(Team, id=team_id, msp__user=request.user)

        # Extract data from request
        team_name = request.data.get('name', team.name)
        member_ids = request.data.get('members', [])

        # Only allow users within the same MSP configuration to be added as members
        members = UserProfile.objects.filter(id__in=member_ids, role__in=['admin', 'msp_superuser', 'msp_user'])

        # Update team data
        team.name = team_name
        team.members.set(members)
        team.save()

        # Serialize response
        serializer = TeamSerializerr(team)
        return Response(serializer.data)

    def delete(self, request, team_id):
        # Ensure only admins and superusers can delete teams
        if request.user.role not in ['admin', 'msp_superuser']:
            return Response(
                {"error": "You do not have permission to delete teams."},
                status=status.HTTP_403_FORBIDDEN
            )

        # Fetch and delete the team
        team = get_object_or_404(Team, id=team_id, msp__user=request.user)
        team.delete()

        return Response({"message": "Team deleted successfully."}, status=status.HTTP_204_NO_CONTENT)
    

class ClientManagementAPI(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Ensure only admins and superusers can create clients
        if request.user.role not in ['admin', 'msp_superuser']:
            return Response(
                {"error": "You do not have permission to create clients."},
                status=status.HTTP_403_FORBIDDEN
            )

        # Extract client data from request
        client_name = request.data.get('name')
        client_email = request.data.get('email',"")
        client_phone = request.data.get('phone',"")
        msp_id = request.data.get('msp_id')
        team_member_id = request.data.get('team_member')
        if team_member_id:
            team_member = UserProfile.objects.get(id=team_member_id)
        else:
            team_member = None

        # Validate input
        if not client_name or not msp_id:
            return Response(
                {"error": "Client name and MSP configuration ID are required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Get the MSP configuration object
        msp = get_object_or_404(IntegrationMSPConfig, id=msp_id)

        # Assign team member if provided
        team_member = None
        if team_member_id:
            team_member = get_object_or_404(UserProfile, id=team_member_id)


        # Create the client
        client = Client.objects.create(
            name=client_name,
            email=client_email,
            phone=client_phone,
            msp=msp,
            team_member=team_member  # Assign team member to client
        )

        # Serialize the response
        serializer = ClientSerializerr(client)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def get(self, request, client_id=None):
        if request.user.role not in ['admin', 'msp_superuser']:
            return Response(
                {"error": "You do not have permission to view clients."},
                status=status.HTTP_403_FORBIDDEN
            )

        if client_id is None:
            # Fetch all clients linked to the user's MSP
            clients = Client.objects.filter(msp__user=request.user)
            serializer = ClientSerializerr(clients, many=True)
            return Response(serializer.data)
        else:
            # Fetch a specific client
            client = get_object_or_404(Client, id=client_id, msp__user=request.user)
            serializer = ClientSerializerr(client)
            return Response(serializer.data)

    def put(self, request, client_id):
        # Ensure only admins and superusers can update clients
        if request.user.role not in ['admin', 'msp_superuser']:
            return Response(
                {"error": "You do not have permission to update clients."},
                status=status.HTTP_403_FORBIDDEN
            )

        # Fetch the client object
        client = get_object_or_404(Client, id=client_id, msp__user=request.user)

        # Extract data from request
        client_name = request.data.get('name', client.name)
        client_email = request.data.get('email', client.email)
        client_phone = request.data.get('phone', client.phone)

        # Update client data
        client.name = client_name
        client.email = client_email
        client.phone = client_phone
        client.save()

        # Serialize response
        serializer = ClientSerializerr(client)
        return Response(serializer.data)

    def delete(self, request, client_id):
        # Ensure only admins and superusers can delete clients
        if request.user.role not in ['admin', 'msp_superuser']:
            return Response(
                {"error": "You do not have permission to delete clients."},
                status=status.HTTP_403_FORBIDDEN
            )

        # Fetch and delete the client
        client = get_object_or_404(Client, id=client_id, msp__user=request.user)
        client.delete()

        return Response({"message": "Client deleted successfully."}, status=status.HTTP_204_NO_CONTENT)
    
    
class DeviceManagementAPI(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Ensure only admins and superusers can create devices
        if request.user.role not in ['admin', 'msp_superuser']:
            return Response(
                {"error": "You do not have permission to create devices."},
                status=status.HTTP_403_FORBIDDEN
            )

        # Extract data from request
        name = request.data.get('name')
        device_type = request.data.get('device_type')
        ip_address = request.data.get('ip_address')
        client_id = request.data.get('client_id')

        # Validate input
        if not name or not device_type or not client_id:
            return Response(
                {"error": "Name, device type and client ID are required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Get the client object
        client = get_object_or_404(Client, id=client_id, msp__user=request.user)

        # Create the device
        device = Device.objects.create(name=name, device_type=device_type, ip_address=ip_address, client=client)

        # Serialize the response
        serializer = DeviceSerializer(device)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def get(self, request, device_id=None):
        # Allow only admins and superusers to view devices
        if request.user.role not in ['admin', 'msp_superuser']:
            return Response(
                {"error": "You do not have permission to view devices."},
                status=status.HTTP_403_FORBIDDEN
            )

        if device_id is None:
            # Fetch all devices associated with the client's MSP
            devices = Device.objects.filter(client__msp__user=request.user)
            serializer = DeviceSerializer(devices, many=True)
            return Response(serializer.data)
        else:
            # Fetch a specific device
            device = get_object_or_404(Device, id=device_id, client__msp__user=request.user)
            serializer = DeviceSerializer(device)
            return Response(serializer.data)

    def put(self, request, device_id):
        # Ensure only admins and superusers can update devices
        if request.user.role not in ['admin', 'msp_superuser']:
            return Response(
                {"error": "You do not have permission to update devices."},
                status=status.HTTP_403_FORBIDDEN
            )

        # Fetch the device object
        device = get_object_or_404(Device, id=device_id, client__msp__user=request.user)

        # Extract data from request
        name = request.data.get('name', device.name)
        device_type = request.data.get('device_type', device.device_type)
        ip_address = request.data.get('ip_address', device.ip_address)

        # Update device data
        device.name = name
        device.device_type = device_type
        device.ip_address = ip_address
        device.save()

        # Serialize response
        serializer = DeviceSerializer(device)
        return Response(serializer.data)

    def delete(self, request, device_id):
        # Ensure only admins and superusers can delete devices
        if request.user.role not in ['admin', 'msp_superuser']:
            return Response(
                {"error": "You do not have permission to delete devices."},
                status=status.HTTP_403_FORBIDDEN
            )

        # Fetch and delete the device
        device = get_object_or_404(Device, id=device_id, client__msp__user=request.user)
        device.delete()

        return Response({"message": "Device deleted successfully."}, status=status.HTTP_204_NO_CONTENT)
    
class IncidentManagementAPI(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Ensure only admins and team members can create incidents
        if request.user.role not in ['admin', 'msp_superuser', 'msp_user']:
            return Response(
                {"error": "You do not have permission to create incidents."},
                status=status.HTTP_403_FORBIDDEN
            )

        # Extract data from request
        title = request.data.get('title')
        description = request.data.get('description')
        severity = request.data.get('severity')
        device_id = request.data.get('device_id')
        recommended_solutions = request.data.get('recommended_solutions', '')
        predicted_resolution_time = request.data.get('predicted_resolution_time', None)

        # Validate input
        if not title or not description or not severity or not device_id:
            return Response(
                {"error": "Title, description, severity, and device ID are required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Get the device object
        device = get_object_or_404(Device, id=device_id)

        # Create the incident
        incident = Incident.objects.create(
            title=title,
            description=description,
            severity=severity,
            device=device,
            recommended_solution=recommended_solutions,
            predicted_resolution_time=predicted_resolution_time
        )

        # Serialize the response
        serializer = IncidentSerializerr(incident)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def get(self, request, incident_id=None):
        # Allow only admins and team members to view incidents
        if request.user.role not in ['admin', 'msp_superuser', 'msp_user']:
            return Response(
                {"error": "You do not have permission to view incidents."},
                status=status.HTTP_403_FORBIDDEN
            )

        if incident_id is None:
            # Fetch all incidents associated with devices managed by the user's MSP
            incidents = Incident.objects.filter(device__client__msp__user=request.user)
            serializer = IncidentSerializerr(incidents, many=True)
            return Response(serializer.data)
        else:
            # Fetch a specific incident
            incident = get_object_or_404(Incident, id=incident_id, device__client__msp__user=request.user)
            serializer = IncidentSerializerr(incident)
            return Response(serializer.data)

    def put(self, request, incident_id):
        # Ensure only admins and team members can update incidents
        if request.user.role not in ['admin', 'msp_superuser', 'msp_user']:
            return Response(
                {"error": "You do not have permission to update incidents."},
                status=status.HTTP_403_FORBIDDEN
            )

        # Fetch the incident object
        incident = get_object_or_404(Incident, id=incident_id, device__client__msp__user=request.user)

        # Extract data from request
        title = request.data.get('title', incident.title)
        description = request.data.get('description', incident.description)
        severity = request.data.get('severity', incident.severity)
        recommended_solutions = request.data.get('recommended_solutions', incident.recommended_solutions)
        predicted_resolution_time = request.data.get('predicted_resolution_time', incident.predicted_resolution_time)
        resolved = request.data.get('resolved', incident.resolved)

        # Update incident data
        incident.title = title
        incident.description = description
        incident.severity = severity
        incident.recommended_solutions = recommended_solutions
        incident.predicted_resolution_time = predicted_resolution_time
        incident.resolved = resolved
        incident.save()

        # Serialize response
        serializer = IncidentSerializerr(incident)
        return Response(serializer.data)

    def delete(self, request, incident_id):
        # Ensure only admins and team members can delete incidents
        if request.user.role not in ['admin', 'msp_superuser', 'msp_user']:
            return Response(
                {"error": "You do not have permission to delete incidents."},
                status=status.HTTP_403_FORBIDDEN
            )

        # Fetch and delete the incident
        incident = get_object_or_404(Incident, id=incident_id, device__client__msp__user=request.user)
        incident.delete()

        return Response({"message": "Incident deleted successfully."}, status=status.HTTP_204_NO_CONTENT)
    

class AssignClientsToTeamMembers(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        team_id = request.data.get('team_id')
        client_ids = request.data.get('client_ids')  # Array of client IDs
        team_member_id = request.data.get('team_member_id')  # The team member ID to assign the clients to

        # Validate the input
        if not team_id or not client_ids or not team_member_id:
            return Response({"error": "team_id, client_ids, and team_member_id are required."},
                            status=status.HTTP_400_BAD_REQUEST)

        # Get the team and validate it exists
        team = get_object_or_404(Team, id=team_id)

        # Check if the team member is part of the team
        if not team.members.filter(id=team_member_id).exists():
            return Response({"error": "The specified team member is not part of this team."},
                            status=status.HTTP_403_FORBIDDEN)

        # Assign clients to the team member
        clients = Client.objects.filter(id__in=client_ids)
        clients.update(team_member_id=team_member_id)  # Assign the team member to each client

        return Response({"message": "Clients successfully assigned to the team member."},
                        status=status.HTTP_200_OK)

    def get(self, request, team_id):
        # Retrieve clients assigned to a team member
        clients = Client.objects.filter(team_member__team__id=team_id)
        serializer = ClientSerializerr(clients, many=True)
        return Response(serializer.data)

    def delete(self, request):
        team_id = request.data.get('team_id')
        client_ids = request.data.get('client_ids')

        if not team_id or not client_ids:
            return Response({"error": "team_id and client_ids are required."},
                            status=status.HTTP_400_BAD_REQUEST)

        clients = Client.objects.filter(id__in=client_ids)
        clients.update(team_member=None)  # Remove assignment

        return Response({"message": "Clients successfully unassigned."}, status=status.HTTP_200_OK)
    
    
@api_view(['GET'])
def get_team_members(request):
    user = request.user
    teams = Team.objects.filter(msp__user=user)  # Filter based on MSP and user
    team_members = UserProfile.objects.filter(teams__in=teams).distinct()  # Fetch members of those teams
    serializer = UserProfileSerializer(team_members, many=True)
    return Response(serializer.data)