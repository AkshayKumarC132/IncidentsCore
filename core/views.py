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



# # Create or get the record for 'ConnectWise'
# IntegrationType.objects.get_or_create(id=1, defaults={'name': 'ConnectWise'})

# # Create or get the record for 'HaloPSA'
# IntegrationType.objects.get_or_create(id=2, defaults={'name': 'HaloPSA'})

class RegisterViewAPI(APIView):
    serializer_class = RegisterSerializer
    
    def get(self, request):
        # Render the login page
        return render(request, 'register.html')

    @transaction.atomic()
    @csrf_exempt
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            username = serializer.validated_data['username']
            email = serializer.validated_data['email']
            pwd = serializer.validated_data['password']
            if (UserProfile.objects.filter(username=username).exists()):
                return Response({"message": "username already exists"}, status=status.HTTP_400_BAD_REQUEST)
            UserProfile.objects.create_user(username=username, password=pwd, email=email, is_active=True)

            # Redirect to a success page or login page after registration
            return render(request, 'registration_success.html')

        return Response({"message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

class LoginViewAPI(APIView):
    serializer_class = LoginSerialzier
    permission_classes = [AllowAny]  # Allow anyone to access this view
    
    def get(self, request):
        # Render the login page
        return render(request, 'login.html')

    # @csrf_exempt
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
            # Get the token from the request
            token = request.auth
            # Check if the token exists
            if token:
                token.delete()  # Delete the token
            return Response({'message': 'Logout successful.'})
        except Exception as e:
            return Response({'error': str(e)}, status=400)

@login_required
def select_integration_type(request):
    integration_types = IntegrationType.objects.all()
    return render(request, 'select_integration_type.html', {'integration_types': integration_types})

@login_required
def integration_config(request, type_id):
    # Ensure you pass the integration type to the template for rendering fields correctly.
    integration_type = get_object_or_404(IntegrationType, id=type_id)
    return render(request, 'integration_config.html', {'type_id': type_id, 'integration_type': integration_type.name})

@login_required
def save_integration_config(request):
    if request.method == 'POST':
        type_id = request.POST.get('type_id')
        company_id = request.POST.get('company_id', "")
        public_key = request.POST.get('public_key', "")
        private_key = request.POST.get('private_key', "")
        client_id = request.POST.get('client_id', "")
        client_secret = request.POST.get('client_secret', "")
        instance_url = request.POST.get('instance_url', "")

        type_instance = get_object_or_404(IntegrationType, id=type_id)
        user = request.user

        # Check if a configuration with the same user and type already exists
        config, created = IntegrationMSPConfig.objects.get_or_create(
            user=user, 
            type=type_instance,
            defaults={
                'company_id': company_id or "",
                'public_key': public_key or "",
                'private_key': private_key or "",
                'client_id': client_id or  "",
                'client_secret': client_secret or "",
                'instance_url': instance_url or "",
                "updated_at" : datetime.now()
            }
        )

        # Update the configuration if it already exists
        if not created:
            config.company_id = company_id
            config.public_key = public_key
            config.private_key = private_key
            config.client_id = client_id
            config.client_secret = client_secret
            config.instance_url = instance_url
            config.updated_at = datetime.now()

        if type_instance.name == 'ConnectWise':
            # Create the authorization token
            auth_token = base64.b64encode(f"{company_id}+{public_key}:{private_key}".encode()).decode()
            headers = {
                "Authorization": f"Basic {auth_token}",
                "clientID": ConnectWiseClientId,
                "Content-Type": "application/json"
            }
            endpoint = TestConnectWiseCredentialsViaURL
            response = requests.get(endpoint, headers=headers)
            
            # Only save if the response is successful
            if response.status_code != 200:
                return HttpResponse(f"Failed to save configuration: {response.json()}", status=400)
            
        elif type_instance.name == 'HaloPSA':
            headers = {
                "Content-Type": "application/x-www-form-urlencoded"
            }
            payload = f'grant_type=client_credentials&client_id={client_id}&client_secret={client_secret}&scope=all'
            endpoint = TestHaloPSACredentialsViaURL
            response = requests.post(endpoint, headers=headers, data=payload)
            
            # Only save if the response is successful
            if response.status_code != 200:
                return HttpResponse(f"Failed to save configuration: {response.json()}", status=400)
            
            # Extract tokens from response JSON
            tokens_data = response.json()
            access_token = tokens_data.get('access_token')
            config.access_token = access_token
            config.refresh_token = tokens_data.get('refresh_token')
            config.expires_in = tokens_data.get('expires_in')
            
            halo_headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
            
            # 1. Fetch and save client data
            client_response = requests.get(f"{instance_url}/api/Client", headers=halo_headers)
            if client_response.status_code == 200:
                clients_data = client_response.json()['clients']
                
                for client_data in clients_data:
                    client, created = Client.objects.update_or_create(
                                name=client_data['name'],
                                msp=config,
                                defaults={
                                    'created_at': datetime.now()
                                }
                            )
                    # if created:
                    #     print(f"Client '{client_data['name']}' created successfully.")
                    # else:
                    #     print(f"Client '{client_data['name']}' updated successfully.")

            # 2. Fetch and save ticket (incident) data with associated devices
            tickets_response = requests.get(f"{instance_url}/api/Tickets", headers=halo_headers)
            if tickets_response.status_code == 200:
                tickets_data = tickets_response.json()['tickets']
                
                for ticket in tickets_data:
                    severity, _ = Severity.objects.get_or_create(id=ticket['priority_id'])
                    
                    # Fetch client ID from the ticket to get associated devices
                    ticket_client_id = ticket['client_id']
                    
                    # If client_id exists, fetch the associated devices
                    if ticket_client_id:
                        # Fetch devices for this specific client
                        device_response = requests.get(
                            f"{instance_url}/api/Asset",
                            headers=halo_headers,
                            params={"client_id": ticket_client_id}
                        )
                        
                        if device_response.status_code == 200:
                            devices_data = device_response.json()['assets']
                            
                            for device_data in devices_data:
                                device_name = device_data['inventory_number'] + ' ' + device_data['key_field']
                                
                                # Get or create the device associated with the client
                                device, created = Device.objects.update_or_create(
                                    name=device_name,
                                    client=client,
                                    defaults={
                                        # 'device_type': device_data.get('type', ''),
                                        # 'ip_address': device_data.get('ip_address', ''),
                                        'created_at': datetime.now()
                                    }
                                )

                                # Create or update the Incident for each device
                                Incident.objects.update_or_create(
                                    title=ticket['summary'],
                                    device=device,
                                    defaults={
                                        'description': ticket['details'],
                                        'severity': severity,
                                        'resolved': ticket.get('resolved', False),
                                        'recommended_solution': ticket.get('recommended_solution', ''),
                                        'predicted_resolution_time': ticket.get('predicted_resolution_time', 0),
                                        'created_at': datetime.now()
                                    }
                                )
        
        # Save the updated or new configuration only if the validation passed
        try:
            config.save()
            return redirect('dashboard')  # Replace 'dashboard_view' with the actual name of your dashboard URL pattern
        except Exception as e:
            return HttpResponse(f"Failed to save configuration: {str(e)}", status=400)

    return HttpResponse("Invalid request method.", status=405)

# Register user with role
@api_view(['POST'])
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

@login_required(login_url='/account/login/')
def dashboard_view(request):
    # Fetch the user's profile to filter incidents and devices
    user_profile = request.user
    
    # user_profile = UserProfile.objects.get(username = user_profile)
    # Fetch the MSP configuration for the user
    user_msp_config = IntegrationMSPConfig.objects.filter(user=user_profile).distinct()
    
    # Fetch incidents and devices associated with the user's MSP
    incident_list = Incident.objects.filter(device__client__msp__in=user_msp_config).order_by('id').distinct()
    device_list = Device.objects.filter(client__msp__in=user_msp_config).order_by('id').distinct()
    
    # Pagination for incidents
    incident_paginator = Paginator(incident_list, 10)  # Show 10 incidents per page
    incident_page_number = request.GET.get('incident_page')
    incident_page_obj = incident_paginator.get_page(incident_page_number)

    # Pagination for devices
    device_paginator = Paginator(device_list, 10)  # Show 10 devices per page
    device_page_number = request.GET.get('device_page')
    device_page_obj = device_paginator.get_page(device_page_number)

    # KPI calculations
    total_incidents = incident_list.count()
    resolved_incidents = incident_list.filter(resolved=True).count()
    unresolved_incidents = incident_list.filter(resolved=False).count()
    avg_resolution_time = incident_list.aggregate(Avg('predicted_resolution_time'))['predicted_resolution_time__avg'] or 0
    severity_counts = Incident.objects.values('severity__level').annotate(count=Count('id'))

    context = {
        'total_incidents': total_incidents,
        'resolved_incidents': resolved_incidents,
        'unresolved_incidents': unresolved_incidents,
        'avg_resolution_time': avg_resolution_time,
        'incident_page_obj': incident_page_obj,
        'device_page_obj': device_page_obj,
        'severity_counts': severity_counts,
    }

    return render(request, 'dashboard.html', context)


# UserProfile ViewSet
# class UserProfileViewSet(viewsets.ModelViewSet):
#     queryset = UserProfile.objects.all()
#     serializer_class = UserProfileSerializer


# IntegrationType ViewSet
class IntegrationTypeViewSet(viewsets.ModelViewSet):
    queryset = IntegrationType.objects.all()
    serializer_class = IntegrationTypeSerializer
    permission_classes = [IsAuthenticated]


# IntegrationMSPConfig ViewSet
class IntegrationMSPConfigViewSet(viewsets.ModelViewSet):
    queryset = IntegrationMSPConfig.objects.all()
    serializer_class = IntegrationMSPConfigSerializer
    permission_classes = [IsAuthenticated]


# Client ViewSet
class ClientViewSet(viewsets.ModelViewSet):
    queryset = Client.objects.all()
    serializer_class = ClientSerializer
    permission_classes = [IsAuthenticated]

    @action(detail=True, methods=['post'])
    def assign_team_member(self, request, pk=None):
        client = self.get_object()
        try:
            # Fetch the team member by ID
            team_member = UserProfile.objects.get(id=request.data['team_member_id'])
            client.team_member = team_member  # Assuming the Client model has a team_member field
            client.save()
            return Response({'status': 'Team member assigned'})
        except UserProfile.DoesNotExist:
            return Response({'error': 'Team member not found'}, status=404)

# Device ViewSet
class DeviceViewSet(viewsets.ModelViewSet):
    queryset = Device.objects.all()
    serializer_class = DeviceSerializer
    permission_classes = [IsAuthenticated]

# Severity ViewSet
class SeverityViewSet(viewsets.ModelViewSet):
    queryset = Severity.objects.all()
    serializer_class = SeveritySerializer

# Incident ViewSet
class IncidentViewSet(viewsets.ModelViewSet):
    queryset = Incident.objects.all()
    serializer_class = IncidentSerializer
    permission_classes = [IsAuthenticated]

# Agent ViewSet
class AgentViewSet(viewsets.ModelViewSet):
    queryset = Agent.objects.all()
    serializer_class = AgentSerializer

# Task ViewSet
class TaskViewSet(viewsets.ModelViewSet):
    queryset = Task.objects.all()
    serializer_class = TaskSerializer

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def dashboard_summary(request):
    # Ensure the user is authenticated
    if not request.user.is_authenticated:
        return Response({'error': 'User not authenticated'}, status=401)

    # Get the user profile
    user_profile = request.user

    # Fetch the user's MSP configuration
    try:
        msp_config = IntegrationMSPConfig.objects.get(user=user_profile)
    except IntegrationMSPConfig.DoesNotExist:
        return Response({'error': 'MSP configuration not found for this user'}, status=404)

    # Fetch total number of customers for the user's MSP
    total_customers = Client.objects.filter(msp=msp_config).count()

    # Fetch total number of devices for the user's MSP
    total_devices = Device.objects.filter(client__msp=msp_config).count()

    # Fetch number of active incidents for the user's MSP
    active_incidents = Incident.objects.filter(device__client__msp=msp_config, resolved=False).count()

    # Fetch number of resolved incidents for the user's MSP
    resolved_incidents = Incident.objects.filter(device__client__msp=msp_config, resolved=True).count()
    
    # Fetch incident data for the user's MSP
    incident_data = Incident.objects.filter(device__client__msp=msp_config).values()

    # Return the data as a dictionary
    data = {
        'total_customers': total_customers,
        'total_devices': total_devices,
        'active_incidents': active_incidents,
        'resolved_incidents': resolved_incidents,
        'incident_data': list(incident_data)  # Convert to list for JSON serialization
    }

    return Response(data)

class UserProfileViewSet(viewsets.ModelViewSet):
    queryset = UserProfile.objects.all()
    serializer_class = UserProfileSerializer
    # permission_classes = [IsAuthenticated]


class TeamViewSet(viewsets.ModelViewSet):
    queryset = Team.objects.all()
    serializer_class = TeamSerializer
    permission_classes = [IsAuthenticated]

    @action(detail=True, methods=['post'])
    def add_member(self, request, pk=None):
        team = self.get_object()
        user = UserProfile.objects.get(id=request.data['user_id'])
        team.members.add(user)
        team.save()
        return Response({'status': 'Member added'})

    @action(detail=True, methods=['post'])
    def remove_member(self, request, pk=None):
        team = self.get_object()
        user = UserProfile.objects.get(id=request.data['user_id'])
        team.members.remove(user)
        team.save()
        return Response({'status': 'Member removed'})

from rest_framework.authtoken.models import Token
from rest_framework.exceptions import AuthenticationFailed

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def dashboard_data_(request):

    user = request.user
    data = {}

    # Add user role to the response
    data['role'] = user.role

    # Get the user's associated devices and clients based on their role
    if user.role == 'admin':
        # Admin sees all incidents
        user_devices = Device.objects.all()
        user_clients = Client.objects.all()
    elif user.role == 'msp_superuser':
        # Get all MSP configurations associated with the user
        msp_configs = user.integrationmspconfig_set.all()
        if msp_configs.exists():
            # Fetch clients related to all MSPs
            user_clients = Client.objects.filter(msp__in=msp_configs)
            user_devices = Device.objects.filter(client__in=user_clients)
        else:
            # No MSP configurations found, return empty lists
            user_clients = Client.objects.none()
            user_devices = Device.objects.none()
    else:  # MSP User
        # Fetch clients associated with the MSP user
        user_clients = Client.objects.filter(msp__user=user)
        user_devices = Device.objects.filter(client__in=user_clients)

    # Summary for incidents by severity based on user's devices or clients
    data['severitySummary'] = list(
        Incident.objects.filter(device__in=user_devices).values('severity__level').annotate(count=Count('id'))
    )

    # Summary for incidents by device based on user's devices or clients
    data['deviceSummary'] = list(
        Incident.objects.filter(device__in=user_devices).values('device__name').annotate(count=Count('id'))
    )

    # Check user role for detailed statistics
    if user.role == 'admin':  # Admin
        data['total_customers'] = Client.objects.count()
        data['total_devices'] = Device.objects.count()
        data['active_incidents'] = Incident.objects.filter(resolved=False).count()
        data['resolved_incidents'] = Incident.objects.filter(resolved=True).count()
        data['incident_data'] = list(Incident.objects.all().values())

    elif user.role == 'msp_superuser':  # MSP SuperUser
        data['total_customers'] = user_clients.count()  # Total customers based on filtered clients
        data['total_devices'] = user_devices.count()    # Total devices based on filtered devices

        # Fetch incidents related to the devices of these clients
        data['active_incidents'] = Incident.objects.filter(resolved=False, device__client__in=user_clients).count()
        data['resolved_incidents'] = Incident.objects.filter(resolved=True, device__client__in=user_clients).count()
        data['incident_data'] = list(Incident.objects.filter(device__client__in=user_clients).values())

    else:  # MSP User
        data['total_customers'] = user_clients.count()  # Total customers based on filtered clients
        data['total_devices'] = user_devices.count()     # Total devices based on filtered devices

        # Fetch incidents related to the devices of these clients
        data['active_incidents'] = Incident.objects.filter(resolved=False, device__client__in=user_clients).count()
        data['resolved_incidents'] = Incident.objects.filter(resolved=True, device__client__in=user_clients).count()
        data['incident_data'] = list(Incident.objects.filter(device__client__in=user_clients).values())

    return Response(data)

class MspViewSet(viewsets.ReadOnlyModelViewSet):  # Use ReadOnlyModelViewSet for GET requests
    queryset = IntegrationMSPConfig.objects.all()  # You can filter by user if necessary
    serializer_class = MspSerializer
    # permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # Optionally filter by the current user
        return IntegrationMSPConfig.objects.filter(user=self.request.user)