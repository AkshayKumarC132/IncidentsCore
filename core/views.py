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
from .serializers import MSPSerializer
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
from rest_framework.decorators import api_view

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
    
    def get(self, request):
        # Render the login page
        return render(request, 'login.html')

    @csrf_exempt
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']
            # Authenticate the user
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                profile = UserProfile.objects.get(username = username)
                if IntegrationMSPConfig.objects.filter(user = profile).exists():
                    return redirect('/api/dashboard')
                return redirect('/api/select-integration-type/')  # Adjust the URL as needed
            else:
                return Response({'message': "Invalid username or password"}, status=status.HTTP_401_UNAUTHORIZED)

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
                                device_name = device_data['inventory_number'] + device_data['key_field']
                                
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
