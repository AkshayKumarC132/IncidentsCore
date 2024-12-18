from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import authenticate, login, logout
from django.views.decorators.csrf import csrf_exempt
from pytz import utc
from .serializers import *
from .models import *
from rest_framework import status
from django.contrib.auth.decorators import login_required
from django.contrib.auth.decorators import login_required
from rest_framework.views import APIView
from django.db.models import Avg, Count
from django.shortcuts import render
from django.http import HttpResponse
from datetime import datetime
from django.shortcuts import redirect
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
import base64
from incidentmanagement.settings import TestConnectWiseCredentialsViaURL, TestHaloPSACredentialsViaURL, ConnectWiseClientId
import requests
from django.http import JsonResponse
from rest_framework.decorators import api_view, permission_classes, action
from rest_framework import viewsets
from django.db import IntegrityError, transaction
from django.utils.datastructures import MultiValueDictKeyError
import json
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from core.management.ml_model.MLModel import IncidentMLModel
from core.orchestration.OrchestrationLayer import OrchestrationLayer
import os
from knox.models import AuthToken
from incidentmanagement import settings
import pytesseract
from django.db.models import Q
from datetime import timedelta  # Add this import at the top of the file
import joblib

# Get the current operating system
os_name = os.name

if os_name == 'nt':  # Windows
    pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
elif os_name == 'posix':  # Linux/Mac
    pytesseract.pytesseract.tesseract_cmd = r'/usr/bin/tesseract'

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
    # Default to 'msp_user' if not provided
    role = request.data.get('role', 'msp_user')

    # Validate if role is one of the allowed choices
    allowed_roles = ['admin', 'msp_superuser', 'msp_user','gl']
    if role not in allowed_roles:
        return Response(
            {"error": f"Invalid role. Allowed roles are: {', '.join(allowed_roles)}"},
            status=status.HTTP_400_BAD_REQUEST
        )
    if UserProfile.objects.filter(email=email).exists():
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
    # permission_classes = [AllowAny]  # Allow anyone to access this view

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']
            # Authenticate the user
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                try:
                    token_instance, token = AuthToken.objects.create(user)
                except Exception as e:
                    print("Error creating token:", e)
                    return Response({'message': "Failed to create token"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

                # Retrieve user profile
                profile = UserProfile.objects.filter(username=username).values()

                return Response(
                    {
                        'message': "Login Successful",
                        "data": profile,
                        'token': token,  # Return the token
                    },
                    status=status.HTTP_200_OK,
                )
            else:
                return Response({'message': "Invalid username or password"}, status=status.HTTP_401_UNAUTHORIZED)
            

class LogoutViewAPI(APIView):
    
    # permission_classes = [IsAuthenticated]  # Only authenticated users can log out

    def post(self, request,token):
        print('aa')
        # Retrieve the user's token instance from the request
        try:
            auth_token_instance = KnoxAuthtoken.objects.get(token_key=token)
        except :
            return Response({"message": "Invalid Token"}, status=status.HTTP_400_BAD_REQUEST)

        # auth_token_instance = request.auth  # Knox sets the AuthToken object in request.auth
        if auth_token_instance:
            try:
                # Delete the token from the database
                auth_token_instance.delete()
                return Response({"message": "Logout successful"}, status=status.HTTP_200_OK)
            except Exception as e:
                return Response({"message": f"Error during logout: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response({"message": "Invalid token or already logged out"}, status=status.HTTP_400_BAD_REQUEST)
# View to List and Create Integration Types (Admin or Superuser access)

def token_verification(token):
    try:
        user = KnoxAuthtoken.objects.get(token_key= token).user
    except:
        return {'status':400,'error':'Invalid Token'}
    if user:
        return {'status':200,'user':user}
    else:
        return {'status':400,'error':'user not Found'}

@api_view(['GET'])
# @permission_classes([IsAuthenticated])
def dashboard_data_(request,token):
    user = token_verification(token)
    if user['status'] ==200:
        user = user
        print(user)
    else:
        return Response({'message':user['error']},status=status.HTTP_400_BAD_REQUEST)
    # user = request.user
    user_profile = user['user'] 
    user = UserProfile.objects.get(id=user_profile.id)
    data = {}

    # Add user role to the response
    data['role'] = user.role

    # Get the user's associated devices and clients based on their role
    if user.role == 'admin' or user.role == 'gl':
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



@api_view(['GET'])
def get_preferences(request,token):
    user = token_verification(token)
    if user['status'] ==200:
        user = user
    else:
        return Response({'message':user['error']},status=status.HTTP_400_BAD_REQUEST)
    # user = request.user
    user_profile = user['user'] 
    # user = UserProfile.objects.get(id=user_profile.id)
    serializer = UserProfileSerializer(user_profile)
    return Response(serializer.data)


@api_view(['GET'])
def get_assigned_tickets(request, token):
    user = token_verification(token)
    if user['status'] == 200:
        user = user
    else:
        return Response({'message': user['error']}, status=status.HTTP_400_BAD_REQUEST)
    
    user_profile = user['user'] 
    user = UserProfile.objects.get(id=user_profile.id)
    
    # Get sort parameters from query string
    sort_by = request.query_params.get('sort_by', 'id')  # Default sort by ID
    order = request.query_params.get('order', 'asc')     # Default ascending order
    
    # Build the base queryset
    tickets = Incident.objects.filter(
        assigned_agent=user,
        resolved=False,
        jira_ticket = None
    ).filter(
        Q(pagent='human') | Q(pagent=None)
    )
    
    # Apply sorting
    if order.lower() == 'desc':
        sort_by = f'-{sort_by}'
    
    # Add sorting to queryset
    tickets = tickets.order_by(sort_by)
    
    ticket_data = [
        {
            'id': ticket.id,
            'title': ticket.title,
            'description': ticket.description,
            'severity': ticket.severity.level,
            'assigned_at': ticket.assigned_at,
            'created_at': ticket.created_at,
            'is_recording': False,
            # logos/recordings/4/recording_final.mp4
            'video_path': f'recordings/{ticket.id}/recording_final.mp4' if ScreenRecording.objects.filter(incident=ticket.id).exists() else None
        } for ticket in tickets
    ]
    return Response(ticket_data)


@api_view(['POST'])
def update_preferences(request,token):
    # user_profile = request.user
    user = token_verification(token)
    if user['status'] ==200:
        user = user
    else:
        return Response({'message':user['error']},status=status.HTTP_400_BAD_REQUEST)
    # user = request.user
    user_profile = user['user'] 
    data = request.data

    # Update fields from the request data
    user_profile.theme = data.get('theme', user_profile.theme)

    # Convert notifications field to boolean
    notifications_value = data.get('notifications', user_profile.notifications)
    if isinstance(notifications_value, str):
        user_profile.notifications = notifications_value.lower() == 'true'
    else:
        user_profile.notifications = notifications_value

    user_profile.layout = data.get('layout', user_profile.layout)
    user_profile.background_color = data.get(
        'background_color', user_profile.background_color)
    user_profile.shadow_color = data.get(
        'shadow_color', user_profile.shadow_color)
    user_profile.menu_position = data.get(
        'menu_position', user_profile.menu_position)
    user_profile.font_style = data.get('font_style', user_profile.font_style)
    user_profile.font_size = data.get('font_size', user_profile.font_size)
    user_profile.font_color = data.get('font_color', user_profile.font_color)
    user_profile.logo_shape = data.get('logo_shape', user_profile.logo_shape)
    user_profile.logo_position = data.get('logo_position', user_profile.logo_position)

    # Handle logo upload
    if 'logo_url' in request.FILES:
        logo_file = request.FILES['logo_url']
        print(logo_file)
        path = default_storage.save(
            f'logos/{logo_file.name}', ContentFile(logo_file.read()))
        user_profile.logo_url = path

    user_profile.save()
    return Response({"status": "success", "message": "Preferences updated successfully."})


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
@api_view(['POST'])
def save_integration_config(request,token):
    if request.method == 'POST':
        type_id = request.POST.get('type_id')
        company_id = request.POST.get('company_id', "")
        public_key = request.POST.get('public_key', "")
        private_key = request.POST.get('private_key', "")
        client_id = request.POST.get('client_id', "")
        client_secret = request.POST.get('client_secret', "")
        instance_url = request.POST.get('instance_url', "")

        type_instance = get_object_or_404(IntegrationType, id=type_id)
        user = token_verification(token)
        if user['status'] ==200:
            user = user
            print(user)
        else:
            return Response({'message':user['error']},status=status.HTTP_400_BAD_REQUEST)
        # user = request.user

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
                return HttpResponse(f"Failed to save configuration: {response.json()}", status=status.HTTP_400_BAD_REQUEST)
            
        elif type_instance.name == 'HaloPSA':
            headers = {
                "Content-Type": "application/x-www-form-urlencoded"
            }
            payload = f'grant_type=client_credentials&client_id={client_id}&client_secret={client_secret}&scope=all'
            endpoint = TestHaloPSACredentialsViaURL
            response = requests.post(endpoint, headers=headers, data=payload)
            
            # Only save if the response is successful
            if response.status_code != 200:
                return HttpResponse(f"Failed to save configuration: {response.json()}", status=status.HTTP_400_BAD_REQUEST)
            
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
            return HttpResponse(f"Failed to save configuration: {str(e)}", status=status.HTTP_400_BAD_REQUEST)

    return HttpResponse("Invalid request method.", status=status.HTTP_405_METHOD_NOT_ALLOWED)



class RunOrchestrationView(APIView):

    def post(self, request, incident_id,token):
        user = token_verification(token)
        if user['status'] ==200:
            user_profile = user['user'] 
        else:
            return Response({'message':user['error']},status=status.HTTP_400_BAD_REQUEST)
        try:
            # Fetch the incident by ID
            incident = Incident.objects.get(id=incident_id)

            try:
                # Initialize the OrchestrationLayer and dispatch the incident
                orchestrator = OrchestrationLayer()
            except Exception as e :
                return Response({'message':str(e)})
            agent_name = orchestrator.dispatch_incident(incident)
            # orchestrator.start_listening()
            return Response({"message": "Incident {} dispatched successfully to {}".format(incident.title, agent_name)}, status=status.HTTP_200_OK)

        except Incident.DoesNotExist:
            return Response({"error": "Incident not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
@api_view(['GET'])
def get_incident_logs(request, token,incident_id):
    print(incident_id)
    user = token_verification(token)
    if user['status'] ==200:
        user = user
    else:
        return Response({'message':user['error']},status=status.HTTP_400_BAD_REQUEST)
    # user = request.user
    logs = IncidentLog.objects.filter(incident__id=incident_id)
    serializer = IncidentLogSerializer(logs, many=True)
    return Response(serializer.data)


@api_view(['GET'])
def get_all_incident_logs(request,token):
    user = token_verification(token)
    if user['status'] ==200:
        user = user
    else:
        return Response({'message':user['error']},status=status.HTTP_400_BAD_REQUEST)
    # user = request.user
    logs = IncidentLog.objects.all().order_by('-assigned_at')  # Fetch all logs ordered by assignment time
    serializer = IncidentLogSerializer(logs, many=True)
    return Response(serializer.data)



@api_view(['GET'])
def get_incident_log_details(request,token):
    # Get the current user's MSP configuration
    user = token_verification(token)
    if user['status'] ==200:
        user = user['user']
    else:
        return Response({'message':user['error']},status=status.HTTP_400_BAD_REQUEST)
    # # user = request.user
    # user_msp_configs = IntegrationMSPConfig.objects.filter(user=user)

    # # Retrieve logs for incidents associated with the user's MSP configurations
    # logs = IncidentLog.objects.filter(
    #     incident__device__client__msp__in=user_msp_configs
    # ).select_related('incident')
    # Check if the user has the GL (Global Leader) role
    # is_gl = user.role.filter(name='GL').exists()  # Assuming roles are related to user and role name is 'GL'
    if user.role == 'gl' or user.role =='admin':
        is_gl = True
    else:
        is_gl = False
        
    # If the user is GL, fetch all incident logs
    if is_gl:
        logs = IncidentLog.objects.all().select_related('incident')
        user_msp_configs = None  # GL doesn't need MSP configuration filtering
    else:
        # If the user is not GL, proceed with filtering by MSP config
        user_msp_configs = IntegrationMSPConfig.objects.filter(user=user)
        logs = IncidentLog.objects.filter(
            incident__device__client__msp__in=user_msp_configs
        ).select_related('incident')
    
    # Prepare log data
    log_data = [{
        'incident_id': log.incident.id,
        'assigned_agent': log.assigned_agent,
        'assigned_at': log.assigned_at,
        'resolved_at': log.resolved_at,
        'resolution_time': log.resolution_time if log.resolution_time else 'N/A'
    } for log in logs]

    # Calculate summary data
    total_incidents = logs.count()
    human_intervention_incidents = logs.filter(assigned_agent='human').count()
    avg_resolution_time = logs.filter(resolved_at__isnull=False).aggregate(avg_resolution=Avg('resolution_time'))['avg_resolution'] or 0

    # Incident distribution by severity
    severity_counts = logs.values('incident__severity__level').annotate(count=Count('incident__severity__level'))

    summary_data = {
        'total_incidents': total_incidents,
        'human_intervention_incidents': human_intervention_incidents,
        'average_resolution_time': avg_resolution_time,
        'severity_distribution': {item['incident__severity__level']: item['count'] for item in severity_counts}
    }

    return Response({
        'logs': log_data,
        'summary': summary_data
    })



@api_view(['POST'])
def upload_recording_chunk(request, token):
    user = token_verification(token)
    if user['status'] == 200:
        user = user
    else:
        return Response({'message': user['error']}, status=status.HTTP_400_BAD_REQUEST)

    ticket_id = request.data.get('ticket_id')
    file = request.FILES.get('file')

    if not file:
        return Response({"error": "No file uploaded"}, status=status.HTTP_400_BAD_REQUEST)

    # Ensure the 'recordings' directory exists
    recordings_dir = os.path.join(settings.MEDIA_ROOT, 'recordings', str(ticket_id))
    try:
        os.makedirs(recordings_dir, exist_ok=True)
    except Exception as e:
        return Response({"error": f"Could not create recordings directory: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    # Save the chunk with incremental naming
    chunk_index = len(os.listdir(recordings_dir))  # Get current chunk count
    chunk_path = os.path.join(recordings_dir, f"chunk_{chunk_index}.bin")
    

    try:
        with open(chunk_path, 'wb') as f:
            for chunk in file.chunks():
                f.write(chunk)
    except Exception as e:
        return Response({"error": f"Failed to save file: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    ScreenRecording.objects.update_or_create(
        incident=ticket_id,
        defaults={'is_recording': True}  # You can specify other fields to update here as needed
    )
    return Response({"status": "Chunk uploaded successfully", "ticket_id": ticket_id}, status=status.HTTP_201_CREATED)

    # # Extract the file extension
    # file_name, file_extension = os.path.splitext(file.name)
    # if not file_extension:
    #     file_extension = ".mp4"  # Default extension if none provided

    chunk_path = os.path.join(directory_path, file.name)

    # Save the uploaded chunk
    try:
        with open(chunk_path, 'wb') as f:
            for chunk in file.chunks():
                f.write(chunk)
    except Exception as e:
        return Response({"error": f"Failed to save file: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    return Response({"status": "Chunk uploaded successfully", "ticket_id": ticket_id}, status=status.HTTP_201_CREATED)



class ClientManagementAPI(APIView):
    def post(self, request,token):
        user = token_verification(token)
        if user['status'] ==200:
            user_profile = user['user'] 
        else:
            return Response({'message':user['error']},status=status.HTTP_400_BAD_REQUEST)
        # Ensure only admins and superusers can create clients
        if user_profile.role not in ['admin', 'msp_superuser','gl']:
            return Response(
                {"error": "You do not have permission to create clients."},
                status=status.HTTP_403_FORBIDDEN
            )

        # Extract client data from request
        client_name = request.data.get('name')
        client_email = request.data.get('email', "")
        client_phone = request.data.get('phone', "")
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

    def get(self, request,client_id=None,token=''):
        user = token_verification(token)
        if user['status'] ==200:
            user_profile = user['user'] 
        else:
            return Response({'message':user['error']},status=status.HTTP_400_BAD_REQUEST)
        if user_profile.role not in ['admin', 'msp_superuser','gl']:
            return Response(
                {"error": "You do not have permission to view clients."},
                status=status.HTTP_403_FORBIDDEN
            )

        if user_profile.role == 'gl':
            if client_id is None:
                # Fetch all clients without filtering by MSP
                clients = Client.objects.all()
                serializer = ClientSerializerr(clients, many=True)
                return Response(serializer.data)
            else:
                # Fetch a specific client
                client = get_object_or_404(Client, id=client_id)
                serializer = ClientSerializerr(client)
                return Response(serializer.data)
        else:
            if client_id is None:
                # Fetch clients linked to the user's MSP
                clients = Client.objects.filter(msp__user=user_profile)
                serializer = ClientSerializerr(clients, many=True)
                return Response(serializer.data)
            else:
                # Fetch a specific client linked to the user's MSP
                client = get_object_or_404(Client, id=client_id, msp__user=user_profile)
                serializer = ClientSerializerr(client)
                return Response(serializer.data)


    def put(self, request, client_id,token):
        # Ensure only admins and superusers can update clients
        user = token_verification(token)
        if user['status'] ==200:
            user_profile = user['user'] 
        else:
            return Response({'message':user['error']},status=status.HTTP_400_BAD_REQUEST)
        if user_profile.role not in ['admin', 'msp_superuser','gl']:
            return Response(
                {"error": "You do not have permission to update clients."},
                status=status.HTTP_403_FORBIDDEN
            )

        # Fetch the client object
        client = get_object_or_404(
            Client, id=client_id, msp__user=user_profile)

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

    def delete(self, request, client_id,token):
        user = token_verification(token)
        if user['status'] ==200:
            user_profile = user['user'] 
        else:
            return Response({'message':user['error']},status=status.HTTP_400_BAD_REQUEST)
        # Ensure only admins and superusers can delete clients
        if user_profile.role not in ['admin', 'msp_superuser','gl']:
            return Response(
                {"error": "You do not have permission to delete clients."},
                status=status.HTTP_403_FORBIDDEN
            )

        # Fetch and delete the client
        client = get_object_or_404(
            Client, id=client_id, msp__user=user_profile)
        client.delete()

        return Response({"message": "Client deleted successfully."}, status=status.HTTP_204_NO_CONTENT)



class SeverityAPI(APIView):
    # Only authenticated users can access this API

    def get(self, request,token):
        user = token_verification(token)
        if user['status'] ==200:
            user_profile = user['user'] 
        else:
            return Response({'message':user['error']},status=status.HTTP_400_BAD_REQUEST)
        # Fetch all severity levels from the database
        severities = Severity.objects.all()
        serializer = SeveritySerializer(severities, many=True)
        return Response(serializer.data)
    

class DeviceManagementAPI(APIView):

    def post(self, request,token):
        user = token_verification(token)
        if user['status'] ==200:
            user_profile = user['user'] 
        else:
            return Response({'message':user['error']},status=status.HTTP_400_BAD_REQUEST)
        # Ensure only admins and superusers can create devices
        if user_profile.role not in ['admin', 'msp_superuser','gl']:
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
        client = get_object_or_404(
            Client, id=client_id, msp__user=user_profile)

        # Create the device
        device = Device.objects.create(
            name=name, device_type=device_type, ip_address=ip_address, client=client)

        # Serialize the response
        serializer = DeviceSerializer(device)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def get(self, request, device_id=None,token=''):
        # Allow only admins and superusers to view devices
        user = token_verification(token)
        if user['status'] ==200:
            user_profile = user['user'] 
        else:
            return Response({'message':user['error']},status=status.HTTP_400_BAD_REQUEST)
        if user_profile.role not in ['admin', 'msp_superuser','gl']:
            return Response(
                {"error": "You do not have permission to view devices."},
                status=status.HTTP_403_FORBIDDEN
            )

        # If role is 'gl', fetch all devices
        if user_profile.role == 'gl':
            if device_id is None:
                # Fetch all devices
                devices = Device.objects.all()
                serializer = DeviceSerializer(devices, many=True)
                return Response(serializer.data)
            else:
                # Fetch a specific device
                device = get_object_or_404(Device, id=device_id)
                serializer = DeviceSerializer(device)
                return Response(serializer.data)
        else:
            # Fetch devices associated with the user's MSP
            if device_id is None:
                devices = Device.objects.filter(client__msp__user=user_profile)
                serializer = DeviceSerializer(devices, many=True)
                return Response(serializer.data)
            else:
                device = get_object_or_404(Device, id=device_id, client__msp__user=user_profile)
                serializer = DeviceSerializer(device)
                return Response(serializer.data)

    def put(self, request, device_id,token):
        user = token_verification(token)
        if user['status'] ==200:
            user_profile = user['user'] 
        else:
            return Response({'message':user['error']},status=status.HTTP_400_BAD_REQUEST)
        # Ensure only admins and superusers can update devices
        if user_profile.role not in ['admin', 'msp_superuser','gl']:
            return Response(
                {"error": "You do not have permission to update devices."},
                status=status.HTTP_403_FORBIDDEN
            )

        # Fetch the device object
        device = get_object_or_404(
            Device, id=device_id, client__msp__user=user_profile)

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

    def delete(self, request, device_id,token):
        user = token_verification(token)
        if user['status'] ==200:
            user_profile = user['user'] 
        else:
            return Response({'message':user['error']},status=status.HTTP_400_BAD_REQUEST)
        # Ensure only admins and superusers can delete devices
        if user_profile.role not in ['admin', 'msp_superuser','gl']:
            return Response(
                {"error": "You do not have permission to delete devices."},
                status=status.HTTP_403_FORBIDDEN
            )

        # Fetch and delete the device
        device = get_object_or_404(
            Device, id=device_id, client__msp__user=user_profile)
        device.delete()

        return Response({"message": "Device deleted successfully."}, status=status.HTTP_204_NO_CONTENT)



class IncidentManagementAPI(APIView):

    def post(self, request,token):
        user = token_verification(token)
        if user['status'] ==200:
            user_profile = user['user'] 
        else:
            return Response({'message':user['error']},status=status.HTTP_400_BAD_REQUEST)
        # Ensure only admins and team members can create incidents
        if user_profile.role not in ['admin', 'msp_superuser', 'msp_user']:
            return Response(
                {"error": "You do not have permission to create incidents."},
                status=status.HTTP_403_FORBIDDEN
            )

        # Extract data from request
        title = request.data.get('title')
        description = request.data.get('description')
        severity = request.data.get('severity')
        device_id = request.data.get('deviceId')
        recommended_solutions = request.data.get('recommended_solutions', '')
        predicted_resolution_time = request.data.get(
            'predicted_resolution_time', None)

        # Validate input
        if not title or not description or not severity or not device_id:
            return Response(
                {"error": "Title, description, severity, and device ID are required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Get the device object
        device = get_object_or_404(Device, id=device_id)
        severity = get_object_or_404(Severity, level=severity)

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

    def get(self, request, incident_id=None, token=''):
        # Verify the token
        user = token_verification(token)
        if user['status'] == 200:
            user_profile = user['user']
        else:
            return Response({'message': user['error']}, status=status.HTTP_400_BAD_REQUEST)

        # Ensure the user has permission to view incidents
        if user_profile.role not in ['admin', 'msp_superuser', 'msp_user', 'gl']:
            return Response(
                {"error": "You do not have permission to view incidents."},
                status=status.HTTP_403_FORBIDDEN
            )

        # Fetch incidents based on the user's role
        if user_profile.role == 'gl':
            incidents = Incident.objects.all()
        else:
            incidents = Incident.objects.filter(
                device__client__msp__user=user_profile
            )

        # Handle filtering by Jira tickets
        jira_ticket_filter = request.query_params.get('jira_ticket')
        if jira_ticket_filter is not None:
            # Convert the query parameter to a boolean value
            jira_ticket_filter = jira_ticket_filter.lower() in ['true', '1', 'yes']
            incidents = incidents.filter(jira_ticket__isnull=not jira_ticket_filter)

        # Handle additional filtering and sorting
        pagent = request.query_params.get('pagent')
        sort_by = request.query_params.get('sort_by', 'created_at')
        order = request.query_params.get('order', 'desc')

        if pagent:
            incidents = incidents.filter(pagent__icontains=pagent)

        if order == 'desc':
            sort_by = f"-{sort_by}"
        incidents = incidents.order_by(sort_by)

        # Handle specific incident retrieval or list all
        if incident_id is not None:
            # Fetch a specific incident
            incident = get_object_or_404(incidents, id=incident_id)
            serializer = IncidentSerializer(incident)
            return Response(serializer.data)

        # Serialize and return the filtered and sorted list
        serializer = IncidentSerializer(incidents, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


    def put(self, request, incident_id,token):
        user = token_verification(token)
        if user['status'] ==200:
            user_profile = user['user'] 
        else:
            return Response({'message':user['error']},status=status.HTTP_400_BAD_REQUEST)
        # Ensure only admins and team members can update incidents
        if user_profile.role not in ['admin', 'msp_superuser', 'msp_user']:
            return Response(
                {"error": "You do not have permission to update incidents."},
                status=status.HTTP_403_FORBIDDEN
            )

        # Fetch the incident object
        incident = get_object_or_404(
            Incident, id=incident_id, device__client__msp__user=user_profile)

        # Extract data from request
        title = request.data.get('title', incident.title)
        description = request.data.get('description', incident.description)
        severity = request.data.get('severity', incident.severity)
        recommended_solutions = request.data.get(
            'recommended_solutions', incident.recommended_solutions)
        predicted_resolution_time = request.data.get(
            'predicted_resolution_time', incident.predicted_resolution_time)
        resolved = request.data.get('resolved', incident.resolved)

        # Update incident data
        incident.title = title
        incident.description = description
        incident.severity = severity
        incident.recommended_solution = recommended_solutions
        incident.predicted_resolution_time = predicted_resolution_time
        incident.resolved = resolved
        incident.save()

        # Serialize response
        serializer = IncidentSerializerr(incident)
        return Response(serializer.data)

    def delete(self, request, incident_id,token):
        user = token_verification(token)
        if user['status'] ==200:
            user_profile = user['user'] 
        else:
            return Response({'message':user['error']},status=status.HTTP_400_BAD_REQUEST)
        # Ensure only admins and team members can delete incidents
        if user_profile.role not in ['admin', 'msp_superuser', 'msp_user']:
            return Response(
                {"error": "You do not have permission to delete incidents."},
                status=status.HTTP_403_FORBIDDEN
            )

        # Fetch and delete the incident
        incident = get_object_or_404(
            Incident, id=incident_id, device__client__msp__user=user_profile)
        incident.delete()

        return Response({"message": "Incident deleted successfully."}, status=status.HTTP_204_NO_CONTENT)


class TeamManagementAPI(APIView):

    def post(self, request,token):
        user = token_verification(token)
        if user['status'] ==200:
            user_profile = user['user'] 
        else:
            return Response({'message':user['error']},status=status.HTTP_400_BAD_REQUEST)
        # Ensure only admins and superusers can create teams
        if user_profile.role not in ['admin', 'msp_superuser','gl']:
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
        members = UserProfile.objects.filter(id__in=member_ids, role__in=[
                                             'admin', 'msp_superuser', 'msp_user'])

        # Create the team and assign members
        team = Team.objects.create(name=team_name, msp=msp)
        team.members.set(members)
        team.save()

        # Serialize the response
        serializer = TeamSerializerr(team)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def get(self, request, team_id=None,token=''):
        user = token_verification(token)
        if user['status'] ==200:
            user_profile = user['user'] 
        else:
            return Response({'message':user['error']},status=status.HTTP_400_BAD_REQUEST)
        # Allow only MSP admins and superusers to view teams
        if user_profile.role not in ['admin', 'msp_superuser','gl']:
            return Response(
                {"error": "You do not have permission to view teams."},
                status=status.HTTP_403_FORBIDDEN
            )

        if team_id is None:
            # Filter teams by the MSP configuration the user is linked to
            teams = Team.objects.filter(msp__user=user_profile)
            serializer = TeamSerializer(teams, many=True)
            return Response(serializer.data)
        else:
            # Fetch a specific team
            team = get_object_or_404(Team, id=team_id, msp__user=user_profile)
            serializer = TeamSerializer(team)
            return Response(serializer.data)

    def put(self, request, team_id,token):
        user = token_verification(token)
        if user['status'] ==200:
            user_profile = user['user'] 
        else:
            return Response({'message':user['error']},status=status.HTTP_400_BAD_REQUEST)
        # Ensure only admins and superusers can modify teams
        if user_profile.role not in ['admin', 'msp_superuser','gl']:
            return Response(
                {"error": "You do not have permission to update teams."},
                status=status.HTTP_403_FORBIDDEN
            )

        # Fetch the team object
        team = get_object_or_404(Team, id=team_id, msp__user=user_profile)

        # Extract data from request
        team_name = request.data.get('name', team.name)
        member_ids = request.data.get('members', [])

        # Only allow users within the same MSP configuration to be added as members
        members = UserProfile.objects.filter(id__in=member_ids, role__in=[
                                             'admin', 'msp_superuser', 'msp_user'])

        # Update team data
        team.name = team_name
        team.members.set(members)
        team.save()

        # Serialize response
        serializer = TeamSerializerr(team)
        return Response(serializer.data)

    def delete(self, request, team_id,token):
        user = token_verification(token)
        if user['status'] ==200:
            user_profile = user['user'] 
        else:
            return Response({'message':user['error']},status=status.HTTP_400_BAD_REQUEST)
        # Ensure only admins and superusers can delete teams
        if user_profile.role not in ['admin', 'msp_superuser','gl']:
            return Response(
                {"error": "You do not have permission to delete teams."},
                status=status.HTTP_403_FORBIDDEN
            )

        # Fetch and delete the team
        team = get_object_or_404(Team, id=team_id, msp__user=user_profile)
        team.delete()

        return Response({"message": "Team deleted successfully."}, status=status.HTTP_204_NO_CONTENT)


class AssignClientsToTeamMembers(APIView):

    def post(self, request,token):
        user = token_verification(token)
        if user['status'] ==200:
            user_profile = user['user'] 
        else:
            return Response({'message':user['error']},status=status.HTTP_400_BAD_REQUEST)
        team_id = request.data.get('team_id')
        client_ids = request.data.get('client_ids')  # Array of client IDs
        # The team member ID to assign the clients to
        team_member_id = request.data.get('team_member_id')

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
        # Assign the team member to each client
        clients.update(team_member_id=team_member_id)

        return Response({"message": "Clients successfully assigned to the team member."},
                        status=status.HTTP_200_OK)

    def get(self, request, team_id,token):
        user = token_verification(token)
        if user['status'] ==200:
            user_profile = user['user'] 
        else:
            return Response({'message':user['error']},status=status.HTTP_400_BAD_REQUEST)
        # Retrieve clients assigned to a team member
        clients = Client.objects.filter(team_member__team__id=team_id)
        serializer = ClientSerializerr(clients, many=True)
        return Response(serializer.data)

    def delete(self, request,token):
        user = token_verification(token)
        if user['status'] ==200:
            user_profile = user['user'] 
        else:
            return Response({'message':user['error']},status=status.HTTP_400_BAD_REQUEST)
        team_id = request.data.get('team_id')
        client_ids = request.data.get('client_ids')

        if not team_id or not client_ids:
            return Response({"error": "team_id and client_ids are required."},
                            status=status.HTTP_400_BAD_REQUEST)

        clients = Client.objects.filter(id__in=client_ids)
        clients.update(team_member=None)  # Remove assignment

        return Response({"message": "Clients successfully unassigned."}, status=status.HTTP_200_OK)
    


@api_view(['GET'])
def get_team_members(request,token):
    user = token_verification(token)
    if user['status'] ==200:
        user_profile = user['user'] 
    else:
        return Response({'message':user['error']},status=status.HTTP_400_BAD_REQUEST)
    teams = Team.objects.filter(msp__user=user_profile)  # Filter based on MSP and user
    team_members = UserProfile.objects.filter(
        teams__in=teams).distinct()  # Fetch members of those teams
    serializer = UserProfileSerializer(team_members, many=True)
    return Response(serializer.data)




def validate_connectwise_credentials(data):
    """
    Function to validate ConnectWise credentials by making an API call to ConnectWise.
    """
    company_id = data['company_id']
    public_key = data['public_key']
    private_key = data['private_key']
    client_id = data['client_id']
    instance_url = data['instance_url']

    # Create the authorization token
    auth_token = base64.b64encode(
        f"{company_id}+{public_key}:{private_key}".encode()).decode()

    # Prepare headers with Basic Auth and clientID
    headers = {
        "Authorization": f"Basic {auth_token}",
        "clientID": client_id,
        "Content-Type": "application/json"
    }

    # API endpoint to validate credentials
    url = f"{instance_url}/v4_6_release/apis/3.0/system/info"

    # Send the GET request
    response = requests.get(url, headers=headers)

    # Return if the request was successful and the response data
    return response.status_code == 200, response.json()



# Utility function for creating Integration configuration
def create_integration_msp_config(user, type, data, response):
    print(user, type, data, response)
    try:
        # Fetch or create IntegrationType
        integration_type, _ = IntegrationType.objects.get_or_create(name=type)

        # Base defaults without tokens
        defaults = {
            'company_id': data.get('company_id', ''),
            'public_key': data.get('public_key', ''),
            'private_key': data.get('private_key', ''),
            'client_id': data.get('client_id', ''),
            'client_secret': data.get('client_secret', ''),
            'instance_url': data.get('instance_url', ''),
        }

        # Conditionally add tokens if they exist in the response
        if 'access_token' in response:
            defaults['access_token'] = response['access_token']

        if 'refresh_token' in response:
            defaults['refresh_token'] = response['refresh_token']

        if 'expires_in' in response:
            defaults['expires_in'] = response['expires_in']

        # Update or create the config
        config, created = IntegrationMSPConfig.objects.update_or_create(
            user=user,
            type=integration_type,
            defaults=defaults
        )

        return config, created
    except Exception as e:
        return Response({'Error Saving the details : '}, str(e))
# ConnectWise Configuration


def fetch_connectwise_data(config):
    try:
        # Generate Base64 encoded auth token
        auth_token = base64.b64encode(
            f"{config.company_id}+{config.public_key}:{config.private_key}".encode()).decode()

        # Update headers with the new authentication method
        headers = {
            "Authorization": f"Basic {auth_token}",
            "clientID": config.client_id,
            "Content-Type": "application/json"
        }

        # Fetch all clients and store them in a dictionary for quick lookup by name
        url_clients = f"{config.instance_url}/v4_6_release/apis/3.0/company/companies"
        response = requests.get(url_clients, headers=headers)

        if response.status_code == 200:
            clients_data = response.json()
            clients_lookup = {}

            # Create or update clients and build a lookup dictionary
            for client_data in clients_data:
                try:
                    client, created = Client.objects.update_or_create(
                        name=client_data['name'],
                        msp=config,  # Associate with the correct MSP configuration
                        defaults={
                            'email': client_data.get('emailAddress', ''),
                            'phone': client_data.get('phoneNumber', '')
                        }
                    )
                    clients_lookup[client_data['name']
                                   ] = client  # Add to lookup
                except Exception as e:
                    print(
                        f"Error processing client {client_data['name']}: {str(e)}")

        # Fetch Devices and associate them with the correct client based on the client name
        url_devices = f"{config.instance_url}/v4_6_release/apis/3.0/company/configurations"
        response_devices = requests.get(url_devices, headers=headers)

        if response_devices.status_code == 200:
            devices_data = response_devices.json()
            for device_data in devices_data:
                try:
                    # Lookup client by name from the devices data
                    client_name = device_data.get('company', {}).get(
                        'name')  # Assuming 'company' key holds client info
                    client = clients_lookup.get(client_name)

                    if client:
                        Device.objects.update_or_create(
                            name=device_data['name'],
                            client=client,  # Associate with the correct Client
                            defaults={
                                'device_type': device_data.get('type', {}).get('name'),
                                'ip_address': device_data.get('ipAddress', '')
                            }
                        )
                    else:
                        print(
                            f"Client not found for device: {device_data['name']}")

                except Exception as e:
                    print(f"Error updating or creating device: {str(e)}")

        # Fetch Incidents and associate them with the correct client and devices
        url_incidents = f"{config.instance_url}/v4_6_release/apis/3.0/service/tickets"
        response_incidents = requests.get(url_incidents, headers=headers)

        if response_incidents.status_code == 200:
            incidents_data = response_incidents.json()
            for incident_data in incidents_data:
                try:
                    # Lookup client by name (assuming incidents have a client key with a name)
                    client_name = incident_data.get('company', {}).get('name')
                    client = clients_lookup.get(client_name)

                    if client:
                        # Get related device for the incident
                        device = Device.objects.filter(
                            client=client).first()  # Assuming the first device

                        if device:
                            # Get or create Severity level
                            severity, _ = Severity.objects.get_or_create(
                                level=incident_data.get('severity', 'Low')
                            )

                            incident, created = Incident.objects.update_or_create(
                                title=incident_data['summary'],
                                device=device,  # Associate with the Device
                                severity=severity,  # Associate with the Severity
                                defaults={
                                    'description': incident_data.get('description', incident_data.get('summary','')),
                                    'resolved': incident_data.get('status', {}).get('name', '') == 'Closed',
                                    'recommended_solution': incident_data.get('resolution', ''),
                                    'predicted_resolution_time': incident_data.get('estimatedResolutionTime', None)
                                }
                            )
                            # Use your ML model to predict the time and solution
                            model = IncidentMLModel()
                            predicted_time = model.predict_time({
                                'severity_id': incident.severity_id,
                                'device_id': incident.device_id
                            })

                            predicted_solution = model.predict_solution({
                                'severity_id': incident.severity_id,
                                'device_id': incident.device_id,
                                'description': incident.description
                            })

                            # Update the incident with predicted values
                            incident.predicted_resolution_time = predicted_time
                            incident.recommended_solution = predicted_solution
                            incident.save()
                        else:
                            print(f"No device found for client: {client_name}")
                    else:
                        print(
                            f"Client not found for incident: {incident_data['summary']}")

                except Exception as e:
                    print(f"Error updating or creating incident: {str(e)}")

    except Exception as e:
        return Response({str(e)})


@csrf_exempt
@api_view(['GET', 'POST'])
# @permission_classes([IsAuthenticated])
def connectwise_setup(request,token):
    if request.method == 'POST':
        user = token_verification(token)
        if user['status'] ==200:
            user_profile = user['user'] 
        else:
            return Response({'message':user['error']},status=status.HTTP_400_BAD_REQUEST)
        try:
            # data = request.POST  # This will extract form data sent as application/x-www-form-urlencoded
            # Alternatively, if JSON is sent:
            data = json.loads(request.body)
            """
            API View to connect and save ConnectWise configuration
            """
            instance_url = data['instance_url']
            company_id = data['company_id']
            client_id = data['client_id']
            public_key = data['public_key']
            private_key = data['private_key']

            is_valid, response_data = validate_connectwise_credentials({
                'instance_url': instance_url,
                'company_id': company_id,
                'client_id': client_id,
                'public_key': public_key,
                'private_key': private_key,
            })
            print(is_valid, response_data)


            if is_valid:
                # Save configuration if valid
                config, created = create_integration_msp_config(
                    user=user_profile,
                    type='ConnectWise',
                    data=data,
                    response=response_data
                )
                print(config)
                print(created)
                # Fetch additional data after saving the configuration
                fetch_connectwise_data(config)

                return JsonResponse({"status": "success", "message": "ConnectWise configuration saved"})
            else:
                return JsonResponse({"status": "failed", "message": "Invalid ConnectWise credentials", "data": response_data}, status=status.HTTP_400_BAD_REQUEST)
        except MultiValueDictKeyError as e:
            return JsonResponse({'error': f'Missing key: {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    elif request.method == 'GET':
        user = token_verification(token)
        if user['status'] ==200:
            user_profile = user['user'] 
        else:
            return Response({'message':user['error']},status=status.HTTP_400_BAD_REQUEST)
        try:
            # Retrieve ConnectWise configuration for the authenticated user
            type = IntegrationType.objects.get(name='ConnectWise')
            config = IntegrationMSPConfig.objects.filter(
                user=user_profile, type=type).first()

            if config:
                return JsonResponse({
                    "status": "success",
                    "data": {
                        "instance_url": config.instance_url,
                        "company_id": config.company_id,
                        "client_id": config.client_id,
                        "public_key": config.public_key,
                        # Do not return sensitive data such as private_key in the response
                    }
                })
            else:
                return JsonResponse({"status": "failed", "message": "No ConnectWise configuration found"}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    else:
        return JsonResponse({'error': 'Invalid request method'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)


# HaloPSA Configuration
def validate_halopsa_credentials(data):
    """
    Function to validate HaloPSA credentials by making an API call to HaloPSA.
    """
    url = f"{data['instance_url']}/auth/token"

    payload = 'grant_type=client_credentials&client_id={}&client_secret={}&scope=all'.format(
        data['client_id'], data['client_secret'])
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    response = requests.post(url, headers=headers, data=payload)
    return response.status_code == 200, response.json()


# Fetching Data for HaloPSA
def fetch_halopsa_data(config):
    try:
        url = f"{config.instance_url}/auth/token"

        payload = 'grant_type=client_credentials&client_id={}&client_secret={}&scope=all'.format(
            config.client_id, config.client_secret)
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        auth_response = requests.post(url, headers=headers, data=payload)
        if not auth_response.status_code == 200:
            return Response({'message': "No Valid Credentials Provided"})
        IntegrationMSPConfig.objects.filter(id=config.id).update(access_token=auth_response.json(
        )['access_token'], expires_in=auth_response.json()['expires_in'], refresh_token=auth_response.json()['refresh_token'])

        # Fetch all clients and store them in a dictionary for quick lookup by name
        url_clients = f"{config.instance_url}/api/Client"
        headers = {
            "Authorization": f"Bearer {config.access_token}",
            "Content-Type": "application/json"
        }

        client_response = requests.get(url_clients, headers=headers)
        if client_response.status_code == 200:
            clients_data = client_response.json()
            clients_lookup = {}

            # Create or update clients and build a lookup dictionary
            for client_data in clients_data.get('clients', []):
                try:
                    client, created = Client.objects.update_or_create(
                        name=client_data['name'],
                        msp=config,  # Associate with the correct MSP configuration
                        defaults={
                            'email': client_data.get('email', ''),
                            'phone': client_data.get('phone', '')
                        }
                    )
                    clients_lookup[client_data['name']
                                   ] = client  # Add to lookup
                except Exception as e:
                    print(
                        f"Error processing client {client_data['name']}: {str(e)}")
        else:
            return Response({'Invalid Acces Token'})
        # Fetch Devices and associate them with the correct client based on client_name
        url_devices = f"{config.instance_url}/api/Asset"
        response_devices = requests.get(url_devices, headers=headers)
        if response_devices.status_code == 200:
            devices_data = response_devices.json()
            for device_data in devices_data['assets']:
                try:
                    # Lookup client by name from the devices data
                    client_name = device_data.get('client_name')
                    client = clients_lookup.get(client_name)

                    if client:
                        Device.objects.update_or_create(
                            name=device_data['inventory_number'] +
                            ' - ' + device_data['key_field'],
                            client=client,  # Associate with the correct Client
                            defaults={
                                'device_type': device_data.get('deviceType', ''),
                                'ip_address': device_data.get('ipAddress', '')
                            }
                        )
                    else:
                        print(
                            f"Client not found for device: {device_data['inventory_number']}")

                except Exception as e:
                    print(f"Error updating or creating device: {str(e)}")

        # Fetch Incidents and associate them with the correct client and devices
        url_incidents = f"{config.instance_url}/api/Tickets"
        response_incidents = requests.get(url_incidents, headers=headers)
        if response_incidents.status_code == 200:
            incidents_data = response_incidents.json()
            for incident_data in incidents_data['tickets']:
                try:
                    # Lookup client by name (assuming incidents have a client_name key)
                    client_name = incident_data.get('client_name')
                    client = clients_lookup.get(client_name)

                    if client:
                        # Get related device for the incident
                        device = Device.objects.filter(
                            client=client).first()  # Assuming the first device

                        if device:
                            # Get or create Severity level
                            severity, _ = Severity.objects.get_or_create(
                                id=incident_data.get('priority_id')
                            )

                            incident, created = Incident.objects.update_or_create(
                                title=incident_data['summary'],
                                device=device,  # Associate with the Device
                                severity=severity,  # Associate with the Severity
                                defaults={
                                    'description': incident_data.get('description', incident_data.get('summary','')),
                                    'resolved': incident_data.get('status', '') == 'Closed',
                                    'recommended_solution': incident_data.get('resolution', ''),
                                    'predicted_resolution_time': incident_data.get('estimatedResolutionTime', None)
                                }
                            )
                            # Use your ML model to predict the time and solution
                            model = IncidentMLModel()
                            predicted_time = model.predict_time({
                                'severity_id': incident.severity_id,
                                'device_id': incident.device_id
                            })

                            predicted_solution = model.predict_solution({
                                'severity_id': incident.severity_id,
                                'device_id': incident.device_id,
                                'description': incident.description
                            })

                            # Update the incident with predicted values
                            incident.predicted_resolution_time = predicted_time
                            incident.recommended_solution = predicted_solution
                            incident.save()
                        else:
                            print(f"No device found for client: {client_name}")
                    else:
                        print(
                            f"Client not found for incident: {incident_data['summary']}")

                except Exception as e:
                    print(f"Error updating or creating incident: {str(e)}")

    except Exception as e:
        print("HaloPSA Fetch details Error", str(e))
        return Response({str(e)})


@csrf_exempt
@api_view(['POST'])
def halopsa_setup(request,token):
    if request.method == 'POST':
        """
        API View to connect and save HaloPSA configuration
        """
        # data = request.POST  # or request.data if using Django Rest Framework
        user = token_verification(token)
        if user['status'] ==200:
            user_profile = user['user'] 
        else:
            return Response({'message':user['error']},status=status.HTTP_400_BAD_REQUEST)
        data = json.loads(request.body)
        is_valid, response_data = validate_halopsa_credentials(data)

        if is_valid:
            # Save configuration if valid
            config, created = create_integration_msp_config(
                user=user_profile,
                type='HaloPSA',
                data=data,
                response=response_data
            )
            # Fetch additional data after saving the configuration
            fetch_halopsa_data(config)
            return JsonResponse({"status": "success", "message": "HaloPSA configuration saved"})
        else:
            return JsonResponse({"status": "failed", "message": "Invalid HaloPSA credentials", "data": response_data}, status=status.HTTP_400_BAD_REQUEST)



@api_view(['GET'])
def fetch_data(request,token):
    """
    API view to fetch data from both ConnectWise and HaloPSA depending on the configuration.
    """
    # Get the user and their integration configurations
    user = token_verification(token)
    if user['status'] ==200:
        user_profile = user['user'] 
    else:
        return Response({'message':user['error']},status=status.HTTP_400_BAD_REQUEST)
    config_list = IntegrationMSPConfig.objects.filter(user=user_profile)

    for config in config_list:
        if config.type.name == "ConnectWise":
            fetch_connectwise_data(config)
        elif config.type.name == "HaloPSA":
            fetch_halopsa_data(config)

    return JsonResponse({"status": "success", "message": "Data fetched successfully"})


class IncidentsByStatus(APIView):

    def get(self, request, status,token):
        user = token_verification(token)
        if user['status'] ==200:
            user = user['user'] 
        else:
            return Response({'message':user['error']},status=status.HTTP_400_BAD_REQUEST)
        
        # Check if the status is 'active' or 'resolved'
        if status == 'active':
            incidents = Incident.objects.filter(resolved=False)
        else:
            incidents = Incident.objects.filter(resolved=True)

        # Role-specific filtering
        if user.role in ['msp_superuser', 'msp_user']:
            # Restrict incidents to MSP clients associated with the user
            msp_configs = user.integrationmspconfig_set.all()
            if msp_configs.exists():
                clients = Client.objects.filter(msp__in=msp_configs)
                incidents = incidents.filter(device__client__in=clients)
            else:
                incidents = incidents.none()
        elif user.role != 'gl':
            # Non-'gl' and non-MSP roles cannot access incidents
            return Response({"error": "You do not have permission to view incidents."},
                            status=status.HTTP_403_FORBIDDEN)

        # Prepare the response data
        incident_data = list(
            incidents.select_related('device', 'severity').values(
                'id','title', 'device__name', 'severity__level', 'resolved'
            )
        )

        return Response(incident_data, status=status.HTTP_200_OK)




class IncidentsByDevice(APIView):

    def get(self, request, device,token):
        # Get the user's associated devices
        user = token_verification(token)
        if user['status'] ==200:
            user_profile = user['user'] 
        else:
            return Response({'message':user['error']},status=status.HTTP_400_BAD_REQUEST)
        # Handle data access based on the user's role
        if user_profile.role == 'gl':
            # 'gl' users can access all incidents filtered by device name
            incidents = Incident.objects.filter(device__name=device)
        else:
            # Get the user's associated devices
            user_devices = Device.objects.filter(client__msp__user=user_profile)

            # Filter incidents by device name and user's devices
            incidents = Incident.objects.filter(
                device__name=device, device__in=user_devices
            )

        # Prepare the incident data
        incident_data = list(incidents.values(
            'id','title', 'device__name', 'severity__level', 'resolved'))
        return Response(incident_data)



class IncidentsBySeverity(APIView):

    def get(self, request, severity,token):
        user = token_verification(token)
        if user['status'] ==200:
            user_profile = user['user'] 
        else:
            return Response({'message':user['error']},status=status.HTTP_400_BAD_REQUEST)
        # Handle data access based on the user's role
        if user_profile.role == 'gl':
            # 'gl' users can access all incidents filtered by severity
            incidents = Incident.objects.filter(severity__level=severity)
        else:
            # Get the user's associated devices
            user_devices = Device.objects.filter(client__msp__user=user_profile)
            
            # Filter incidents by severity and user's devices
            incidents = Incident.objects.filter(
                severity__level=severity, device__in=user_devices
            )
        incident_data = list(incidents.values(
            'id','title', 'device__name', 'severity__level', 'resolved'))
        return Response(incident_data)



@api_view(['POST'])
def start_recording(request,token):
    user = token_verification(token)
    if user['status'] ==200:
        user_profile = user['user'] 
    else:
        return Response({'message':user['error']},status=status.HTTP_400_BAD_REQUEST)
    ticket_id = request.data.get('ticket_id')

    ScreenRecording.objects.create(is_recording = True, incident = ticket_id)
    # Logic to initialize recording session
    return Response({"status": "Recording started", "ticket_id": ticket_id})


@api_view(['POST'])
# @permission_classes([IsAuthenticated])
def stop_recording(request,token):
    user = token_verification(token)
    if user['status'] ==200:
        user_profile = user['user'] 
    else:
        return Response({'message':user['error']},status=status.HTTP_400_BAD_REQUEST)
    ticket_id = request.data.get('ticket_id')
    # Logic to finalize recording session
    return Response({"status": "Recording stopped", "ticket_id": ticket_id})

import cv2
import os

# @api_view(['POST'])
# @csrf_exempt
# def finalize_recording(request, token):
#     user = token_verification(token)
#     if user['status'] == 200:
#         user_profile = user['user']
#     else:
#         return Response({'message': user['error']}, status=status.HTTP_400_BAD_REQUEST)

#     if request.method == 'POST':
#         ticket_id = request.data.get('ticket_id')
#         upload_dir = os.path.join(settings.BASE_DIR,'logos','recordings', str(ticket_id))  # Adjust path as needed
#         concatenated_file = os.path.join(upload_dir, 'concatenated_recording.bin')
#         mp4_file_path = os.path.join(upload_dir, 'recording_final.mp4')

#         # Concatenate chunk files
#         try:
#             # Ensure the upload directory exists
#             if not os.path.exists(upload_dir):
#                 return JsonResponse({'error': f"Upload directory not found: Start Recording First..!!"}, status=status.HTTP_400_BAD_REQUEST)
            
#             chunk_files = sorted(
#                 [os.path.join(upload_dir, f) for f in os.listdir(upload_dir) if f.startswith('chunk_') and f.endswith('.bin')]
#             )
#             if not chunk_files:
#                 return Response({"error": "No chunk files found in the directory"}, status=status.HTTP_400_BAD_REQUEST)


#             # Combine chunks into one file
#             with open(concatenated_file, 'wb') as output_file:
#                 for chunk_file in chunk_files:
#                     with open(chunk_file, 'rb') as f:
#                         output_file.write(f.read())

#         except Exception as e:
#             return JsonResponse({'error': f"Failed to concatenate chunk files: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


#         # Convert combined file to MP4
#         try:
#             cap = cv2.VideoCapture(concatenated_file)

#             # Ensure video can be opened
#             if not cap.isOpened():
#                 return JsonResponse({'error': "Failed to open concatenated file"}, status=status.HTTP_400_BAD_REQUEST)

#             # Get video properties
#             frame_width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
#             frame_height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
#             fps = cap.get(cv2.CAP_PROP_FPS) or 20.0  # Fallback to 20 FPS if not set

#             fourcc = cv2.VideoWriter_fourcc(*'mp4v')  # Codec for MP4
#             out = cv2.VideoWriter(mp4_file_path, fourcc, fps, (frame_width, frame_height))

#             while cap.isOpened():
#                 ret, frame = cap.read()
#                 if not ret:
#                     break
#                 out.write(frame)

#             cap.release()
#             out.release()

#             # Optionally delete the original files and concatenated file
#             for chunk_file in chunk_files:
#                 os.remove(chunk_file)
#             os.remove(concatenated_file)

#             description = process_video_for_description(mp4_file_path)
#             update_incident_description(ticket_id, description)

#             return JsonResponse({
#                 'message': 'Recording finalized and converted to MP4',
#                 'mp4_file_path': mp4_file_path
#             })

#         except Exception as e:
#             return JsonResponse({'error': f"Failed to convert to MP4: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#     return JsonResponse({'error': 'Invalid request method'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

class MspViewSet(viewsets.ReadOnlyModelViewSet):  # Use ReadOnlyModelViewSet for GET requests
    queryset = IntegrationMSPConfig.objects.all()  # You can filter by user if necessary
    serializer_class = MspSerializer
    # permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # user = token_verification(token)
        # if user['status'] ==200:
        #     user_profile = user['user'] 
        # else:
        #     return Response({'message':user['error']},status=status.HTTP_400_BAD_REQUEST)
        # Optionally filter by the current user
        return IntegrationMSPConfig.objects.filter(user=self.request.user.id)
    

@api_view(['POST'])
@csrf_exempt
def extract_text_from_video(request, token):
    user = token_verification(token)
    if user['status'] == 200:
        user_profile = user['user']
    else:
        return Response({'message': user['error']}, status=status.HTTP_400_BAD_REQUEST)

    if request.method == 'POST':
        ticket_id = request.data.get('ticket_id')
        upload_dir = os.path.join(settings.BASE_DIR,'logos','recordings', str(ticket_id))
        video_file_path = os.path.join(upload_dir, 'recording_final.mp4')

        if not os.path.exists(video_file_path):
            return Response({"error": f"Video file does not exist at {video_file_path}"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            print("Loading video for text extraction...")
            cap = cv2.VideoCapture(video_file_path)

            if not cap.isOpened():
                return JsonResponse({'error': "Failed to open video file"}, status=status.HTTP_400_BAD_REQUEST)

            frame_count = 0
            extracted_text = []

            while cap.isOpened():
                ret, frame = cap.read()
                if not ret:
                    break

                gray_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)

                # Perform OCR
                text = pytesseract.image_to_string(gray_frame)
                extracted_text.append({"frame": frame_count, "text": text.strip()})

                frame_count += 1

            cap.release()

            return JsonResponse({
                'message': 'Text extraction completed successfully',
                'extracted_text': extracted_text
            })

        except Exception as e:
            print(f"Error during text extraction: {str(e)}")
            return JsonResponse({'error': f"Failed to extract text from video: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    return JsonResponse({'error': 'Invalid request method'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)



# def filter_and_simplify_actions(text):
#     """
#     Filter and simplify actions from detected text.
#     """
#     # Keywords for action detection
#     keywords = {
#         "login": ["login", "sign in"],
#         "search": ["search", "find", "query"],
#         "navigate": ["navigate", "visit", "go to"],
#         "form_submit": ["submit", "send", "post"],
#         "upload": ["upload", "attach", "add"]
#     }

#     for action, words in keywords.items():
#         for word in words:
#             if word in text.lower():
#                 # Return a simplified action based on the keyword
#                 return f"User performed {action.replace('_', ' ')}"

#     # Return None for irrelevant text
#     return None




# def generate_refined_workflow(video_path, output_dir, interval=5):
#     """
#     Generate a refined workflow from video frames, focusing on user actions.
#     Remove duplicate actions while preserving the earliest occurrence.
#     """
#     # Extract frames
#     extract_frames(video_path, output_dir, interval)
#     workflow_steps = []
#     frame_rate = get_video_frame_rate(video_path)

#     seen_actions = set()  # Track unique actions to avoid duplicates

#     for frame_file in sorted(os.listdir(output_dir)):
#         frame_path = os.path.join(output_dir, frame_file)

#         # Detect text from each frame
#         text = detect_text(frame_path)
#         if not text:
#             continue

#         # Simplify and categorize actions
#         action = filter_and_simplify_actions(text)
#         if action and action not in seen_actions:  # Only add new actions
#             # Calculate timestamp from frame number
#             frame_number = int(frame_file.split("_")[1].split(".")[0])
#             timestamp = str(datetime.timedelta(seconds=frame_number / frame_rate))

#             workflow_steps.append({
#                 "frame": frame_file,
#                 "action": action,
#                 "timestamp": timestamp
#             })
#             seen_actions.add(action)  # Mark action as seen

#     if not workflow_steps:
#         return {"error": "No relevant actions detected"}
    
#     # Sort workflow steps by timestamp
#     workflow_steps = sorted(workflow_steps, key=lambda x: datetime.timedelta(seconds=_parse_timestamp(x["timestamp"])))

#     return {"steps": workflow_steps}

# def _parse_timestamp(timestamp_str):
#     """
#     Helper function to parse a timestamp string into total seconds.
#     """
#     h, m, s = map(float, timestamp_str.split(":"))
#     return h * 3600 + m * 60 + s

# def process_video_for_description(video_path):
#     """
#     Extracts a summarized description of actions performed in the video.
#     """
#     cap = cv2.VideoCapture(video_path)
#     frame_count = 0
#     fps = int(cap.get(cv2.CAP_PROP_FPS))
#     descriptions = []

#     while cap.isOpened():
#         ret, frame = cap.read()
#         if not ret:
#             break

#         # Extract every nth frame (e.g., 1 frame every second)
#         if frame_count % (fps * 1) == 0:
#             text = pytesseract.image_to_string(frame, lang="eng").strip()
#             if text:
#                 descriptions.append(text)

#         frame_count += 1

#     cap.release()

#     # Summarize descriptions into coherent text
#     summary = summarize_descriptions(descriptions)
#     return summary

# def summarize_descriptions(descriptions):
#     """
#     Summarizes extracted descriptions into a coherent text.
#     """
#     unique_descriptions = list(set(descriptions))  # Remove duplicates
#     summary = " ".join(sent_tokenize(" ".join(unique_descriptions)))  # Combine sentences
#     return summary

# def update_incident_description(incident_id, description):
#     """
#     Updates the description column in the Incident table.
#     """
#     try:
#         incident = Incident.objects.get(id=incident_id)
#         incident.description = description
#         incident.save()
#         print(f"Incident {incident_id} description updated successfully.")
#     except Incident.DoesNotExist:
#         print(f"Incident {incident_id} not found.")

# class GenerateWorkflowView(APIView):
#     """
#     API View to process a video and generate a workflow with timestamps.
#     """

#     def post(self, request, *args, **kwargs):
#         ticket_id = request.data.get("ticket_id")
#         video_path = os.path.join(settings.BASE_DIR, "logos", "recordings", str(ticket_id), "recording_final.mp4")
#         output_dir = os.path.join(settings.BASE_DIR, "logos", "recordings", str(ticket_id), "frames")
#         output_file = os.path.join(settings.BASE_DIR, "logos", "recordings", str(ticket_id), "refined_workflow.json")

#         if not os.path.exists(video_path):
#             return Response({"error": "Video not found"}, status=status.HTTP_404_NOT_FOUND)

#         try:
#             # Generate refined workflow
#             workflow = generate_refined_workflow(video_path, output_dir)

#             # Save workflow to JSON file
#             with open(output_file, "w") as json_file:
#                 json.dump(workflow, json_file, indent=4)

#             return Response(workflow, status=status.HTTP_200_OK)

#         except Exception as e:
#             return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@csrf_exempt
def finalize_recording(request, token):
    """
    Finalize a screen recording by converting chunks to MP4 and analyzing the content.
    
    Args:
        request: HTTP request containing ticket_id and optional confidence_threshold
        token: Authentication token
    
    Returns:
        JsonResponse with processing results or error message
    """
    # Validate user
    user = token_verification(token)
    if user['status'] != 200:
        return Response({'message': user['error']}, status=status.HTTP_400_BAD_REQUEST)

    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid request method'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    try:
        # Extract and validate request data
        ticket_id = request.data.get('ticket_id')
        if not ticket_id:
            return JsonResponse({'error': 'ticket_id is required'}, status=status.HTTP_400_BAD_REQUEST)

        # Setup paths
        upload_dir = os.path.join(settings.BASE_DIR, 'logos', 'recordings', str(ticket_id))
        concatenated_file = os.path.join(upload_dir, 'concatenated_recording.bin')
        mp4_file_path = os.path.join(upload_dir, 'recording_final.mp4')
        frames_dir = os.path.join(upload_dir, "frames")

        # Ensure directories exist
        os.makedirs(frames_dir, exist_ok=True)

        # Validate upload directory
        if not os.path.exists(upload_dir):
            return JsonResponse(
                {'error': "Upload directory not found: Start Recording First..!!"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Process chunk files
        chunk_files = sorted([
            f for f in os.listdir(upload_dir)
            if f.startswith('chunk_') and f.endswith('.bin')
        ])
        
        if not chunk_files:
            return JsonResponse(
                {"error": "No chunk files found in the directory"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Concatenate chunks
        try:
            with open(concatenated_file, 'wb') as output_file:
                for chunk_name in chunk_files:
                    chunk_path = os.path.join(upload_dir, chunk_name)
                    with open(chunk_path, 'rb') as f:
                        output_file.write(f.read())
        except Exception as e:
            return JsonResponse(
                {'error': f"Failed to concatenate chunk files: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        # Convert to MP4
        try:
            cap = cv2.VideoCapture(concatenated_file)
            if not cap.isOpened():
                return JsonResponse(
                    {'error': "Failed to open concatenated file"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Get video properties
            frame_width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
            frame_height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
            fps = cap.get(cv2.CAP_PROP_FPS) or 20.0

            # Initialize video writer
            fourcc = cv2.VideoWriter_fourcc(*'mp4v')
            out = cv2.VideoWriter(mp4_file_path, fourcc, fps, (frame_width, frame_height))

            # Process frames
            while cap.isOpened():
                ret, frame = cap.read()
                if not ret:
                    break
                out.write(frame)

            # Clean up video objects
            cap.release()
            out.release()

            # Clean up temporary files
            for chunk_name in chunk_files:
                os.remove(os.path.join(upload_dir, chunk_name))
            os.remove(concatenated_file)

            # Update ScreenRecording entry with the file path
            relative_path = f'recordings/{ticket_id}/recording_final.mp4'
            if ScreenRecording.objects.filter(incident=ticket_id).exists():
                screen_recording = ScreenRecording.objects.get(incident=ticket_id)
                screen_recording.file_path = relative_path
                screen_recording.save()

            # Analyze video content
            workflow = generate_refined_workflow(mp4_file_path, frames_dir)
            if 'steps' not in workflow or not workflow['steps']:
                return JsonResponse(
                    {'error': "No relevant actions detected in video"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Process results
            description, predicted_agents = summarize_workflow_steps(workflow)
            confidence_threshold = float(request.data.get('confidence_threshold', 75))
            assigned_agent = determine_agent_assignment(predicted_agents, confidence_threshold)

            # Handle resolved cases
            if assigned_agent == 'human' and request.data.get('resolved_agent'):
                resolved_agent = request.data['resolved_agent']
                predicted_agents[resolved_agent] = "100.00%"
                assigned_agent = resolved_agent

            # Update incident
            incident = Incident.objects.get(id=ticket_id)
            incident.description = description
            incident.pagent = assigned_agent
            incident.save()

            return JsonResponse({
                'message': 'Recording finalized and converted to MP4',
                'mp4_file_path': mp4_file_path,
                'workflow': workflow,
                'description': description,
                'predicted_agents': predicted_agents,
                'assigned_agent': assigned_agent
            })

        except Exception as e:
            return JsonResponse(
                {'error': f"Failed to process video: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    except Exception as e:
        return JsonResponse(
            {'error': f"Unexpected error: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

def get_video_frame_rate(video_path):
    """
    Retrieve the frame rate of a video.
    """
    cap = cv2.VideoCapture(video_path)
    frame_rate = cap.get(cv2.CAP_PROP_FPS)
    cap.release()
    return frame_rate

def extract_frames(video_path, output_dir, interval=5):
    """
    Extract frames from a video at specified intervals.
    """
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    cap = cv2.VideoCapture(video_path)
    frame_rate = int(cap.get(cv2.CAP_PROP_FPS))
    frame_count = 0

    while cap.isOpened():
        ret, frame = cap.read()
        if not ret:
            break

        # Extract frames based on interval
        if frame_count % (frame_rate * interval) == 0:
            frame_path = os.path.join(output_dir, f"frame_{frame_count}.png")
            cv2.imwrite(frame_path, frame)

        frame_count += 1

    cap.release()


def detect_text(frame_path):
    """
    Detect text from an image frame using OCR.
    """
    image = cv2.imread(frame_path)
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    _, thresh = cv2.threshold(gray, 150, 255, cv2.THRESH_BINARY)

    # Perform OCR on the preprocessed image
    text = pytesseract.image_to_string(thresh, lang="eng")
    return text.strip()


def determine_agent_assignment(predicted_agents, threshold):
    """
    Determine which agent to assign the incident to based on confidence levels.
    """
    top_agent = None
    max_confidence = 0

    for agent, confidence_str in predicted_agents.items():
        confidence = float(confidence_str.replace('%', ''))
        if confidence > max_confidence:
            max_confidence = confidence
            top_agent = agent

    if max_confidence >= threshold:
        return top_agent  # Assign to the predicted agent
    return "human"  # Assign to human if confidence is below the threshold


def filter_and_simplify_actions(text):
    """
    Filter and simplify actions from detected text and predict the agent type with confidence scores.
    """
    agent_keywords = {
        "network": [
            "network", "connectivity", "ping", "router", "firewall",
            "latency", "bandwidth", "IP", "DNS", "VPN", "gateway"
        ],
        "security": [
            "security", "threat", "antivirus", "attack", "breach",
            "malware", "ransomware", "encryption", "firewall", "auth",
            "policy", "credentials", "multi-factor authentication", "cyberattack"
        ],
        "hardware": [
            "hardware", "printer", "laptop", "device", "keyboard",
            "mouse", "monitor", "CPU", "server", "hard drive", "RAM"
        ],
        "software": [
            "software", "application", "install", "error", "bug",
            "update", "patch", "program", "system", "setup", "reinstall", "driver"
        ],
        "human": [
            "login", "search", "manual", "user", "upload",
            "navigate", "enter", "input", "fill", "type", "click", "read", "access"
        ],
    }

    action_keywords = {
        "login": ["login", "sign in", "sign-in", "authenticate"],
        "search": ["search", "find", "query", "lookup", "browse"],
        "upload": ["upload", "attach", "add file", "insert", "send"],
        "configure": ["configure", "setup", "install", "initialize", "apply"],
        "navigate": ["navigate", "visit", "go to", "access"],
        "download": ["download", "save", "export"],
        "reset": ["reset", "reboot", "restart"],
        "patch": ["patch", "update", "fix"],
        "monitor": ["monitor", "check", "track"],
        "resolve": ["resolve", "troubleshoot", "fix", "repair"],
    }

    confidence_scores = {}

    # Calculate confidence scores based on keyword matches
    for agent, keywords in agent_keywords.items():
        score = sum(1 for word in keywords if word in text.lower())
        if score > 0:
            confidence_scores[agent] = score

    # Normalize confidence scores to percentages
    total_score = sum(confidence_scores.values())
    if total_score > 0:
        confidence_scores = {agent: (score / total_score) * 100 for agent, score in confidence_scores.items()}

    # Filter out agents with low confidence (e.g., < 10%)
    confidence_scores = {agent: score for agent, score in confidence_scores.items() if score >= 10}

    # Sort agents by confidence score in descending order
    sorted_agents = sorted(confidence_scores.items(), key=lambda x: x[1], reverse=True)

    # Detect actions based on keywords
    detected_action = None
    for action, keywords in action_keywords.items():
        for word in keywords:
            if word in text.lower():
                detected_action = f"User performed {action}"
                break
        if detected_action:
            break

    if not detected_action:
        detected_action = "User performed an unknown task"

    if sorted_agents:
        top_agent, confidence = sorted_agents[0]
        return detected_action, top_agent, confidence, confidence_scores
    else:
        return detected_action, "unknown", 0, {}


def generate_refined_workflow(video_path, output_dir, interval=5):
    """
    Generate a refined workflow from video frames, focusing on user actions.
    """
    extract_frames(video_path, output_dir, interval)
    workflow_steps = []
    frame_rate = get_video_frame_rate(video_path)

    for frame_file in sorted(os.listdir(output_dir)):
        frame_path = os.path.join(output_dir, frame_file)
        text = detect_text(frame_path)

        if text:  # Only process if text is detected
            action, agent_type, confidence, confidence_scores = filter_and_simplify_actions(text)
            if action:
                frame_number = int(frame_file.split("_")[1].split(".")[0])
                timestamp = str(timedelta(seconds=frame_number / frame_rate))

                workflow_steps.append({
                    "frame": frame_file,
                    "action": action,
                    "agent": agent_type,
                    "confidence": f"{confidence:.2f}%",
                    "timestamp": timestamp
                })

    if not workflow_steps:
        return {"error": "No relevant actions detected"}

    return {"steps": workflow_steps}


def summarize_workflow_steps(workflow):
    """
    Summarize workflow steps into a coherent description and predict agents with confidence scores.
    """
    ordered_actions = []
    agent_confidences = {}

    for step in workflow['steps']:
        action = step['action']
        agent = step.get('agent', 'unknown')
        confidence = float(step.get('confidence', "0").strip('%'))

        # Add action to description if unique
        if action not in ordered_actions:
            ordered_actions.append(action)

        # Aggregate confidence for each agent
        if agent != 'unknown':
            agent_confidences[agent] = agent_confidences.get(agent, 0) + confidence

    # Normalize aggregated confidence scores
    total_confidence = sum(agent_confidences.values())
    if total_confidence > 0:
        agent_confidences = {agent: f"{score / total_confidence * 100:.2f}%" for agent, score in agent_confidences.items()}

    # Prepare description
    description = ". ".join(ordered_actions).capitalize() + "."

    return description, agent_confidences


class PostResolutionClassification(APIView):
    def post(self, request, incident_id):
        """
        Handle the post-resolution classification for an incident.
        """
        # Your logic here, similar to the function-based view
        try:
            # Fetch the incident by ID
            incident = Incident.objects.get(id=incident_id)

            # Ensure the incident was assigned to human initially
            # if incident.pagent != "human":
            #     return Response(
            #         {'error': 'This incident was not assigned to a human agent'},
            #         status=status.HTTP_400_BAD_REQUEST
            #     )

            # Extract data from the request
            classification = request.data.get('classification', '').strip().lower()
            description = request.data.get('description', '').strip()

            # Validate classification
            valid_classifications = ['software', 'network', 'hardware', 'security', 'human']
            if classification not in valid_classifications:
                return Response(
                    {'error': f'Invalid classification. Valid options are: {", ".join(valid_classifications)}'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Update the incident record
            incident.pagent = classification
            incident.assigned_agent = None
            if description:
                incident.description = f"{incident.description}\n\nPost-resolution Update: {description}"
            incident.save()

            # Log the update for retraining
            retraining_log = {
                "incident_id": incident.id,
                "classification": classification,
                "description": description,
            }
            log_retraining_data(retraining_log)

            return Response(
                {'message': 'Post-resolution classification updated successfully'},
                status=status.HTTP_200_OK
            )

        except Incident.DoesNotExist:
            return Response({'error': 'Incident not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



def log_retraining_data(data):
    """
    Log retraining data for future ML model improvements.
    """
    retraining_log_path = os.path.join(settings.BASE_DIR, 'retraining_data.json')

    # Append new data to the log file
    try:
        if not os.path.exists(retraining_log_path):
            with open(retraining_log_path, 'w') as f:
                json.dump([], f)

        with open(retraining_log_path, 'r+') as f:
            logs = json.load(f)
            logs.append(data)
            f.seek(0)
            json.dump(logs, f, indent=4)

        print("Retraining data logged successfully.")
    except Exception as e:
        print(f"Error logging retraining data: {str(e)}")


class FetchJiraIssues(APIView):
    def get(self, request, token):
        if not token:
            return Response({"error": "Token is required"}, status=status.HTTP_400_BAD_REQUEST)

        user = token_verification(token)
        if user['status'] != 200:
            return Response({'message': user['error']}, status=status.HTTP_400_BAD_REQUEST)

        # Fetch Jira integration details
        try:
            msp_config = IntegrationMSPConfig.objects.get(user=user['user'], type__name='Jira')
        except IntegrationMSPConfig.DoesNotExist:
            return Response({"error": "Jira integration is not configured for this user."}, status=status.HTTP_404_NOT_FOUND)

        # Validate Jira configuration
        jira_api_base_url = msp_config.jira_api_base_url
        jira_user_email = msp_config.jira_user_email
        jira_api_token = msp_config.jira_api_token
        jira_project_key = msp_config.jira_project_key
        jira_project_name = msp_config.jira_project_name

        if not all([jira_api_base_url, jira_user_email, jira_api_token, jira_project_key,jira_project_name]):
            return Response({"error": "Incomplete Jira integration configuration."}, status=status.HTTP_400_BAD_REQUEST)

        # Fetch tickets from Jira using pagination
        jira_url = f"{jira_api_base_url}/rest/api/2/search"
        auth = (jira_user_email, jira_api_token)
        start_at = 0
        page_size = 100
        total_tickets = []
        severity_mapping = {
            'Critical': 1,  # Severity Level ID in your database
            'High': 2,
            'Medium': 3,
            'Low': 4
        }

        try:
            # Start a database transaction
            with transaction.atomic():
                while True:
                    params = {
                        'jql': f'project={jira_project_name} AND status IS NOT EMPTY',
                        'fields': 'summary,description,status,priority,created',
                        'maxResults': page_size,
                        'startAt': start_at,
                    }
                    response = requests.get(jira_url, auth=auth, params=params)
                    if response.status_code != 200:
                        return Response({
                            "error": f"Failed to fetch Jira issues: {response.status_code}",
                            "details": response.text
                        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

                    data = response.json()
                    issues = data.get('issues', [])
                    total_tickets.extend(issues)

                    # Save tickets and incidents in batches
                    for issue in issues:
                        issue_key = issue['key']
                        summary = issue['fields']['summary']
                        description = issue['fields']['description']
                        created_at = issue['fields']['created']
                        priority_name = issue['fields']['priority']['name']  # 'High', 'Low', etc.
                        severity_level_id = severity_mapping.get(priority_name, 3)  # Default to Medium if not found
                        severity = Severity.objects.get(id=severity_level_id)

                        # Ensure the issue_key is unique per user
                        if JiraTicket.objects.filter(user=user['user'], issue_key=issue_key).exists():
                            continue  # Skip saving if ticket already exists for this user

                        # Create the JiraTicket object
                        jira_ticket = JiraTicket.objects.create(
                            issue_key=issue_key,
                            project=jira_project_name,
                            summary=summary,
                            description=description or "",
                            created_at=created_at,
                            status=issue['fields']['status']['name'],
                            priority=priority_name,
                            user=user['user']  # Associate the ticket with the user profile
                        )

                        # if created:
                        # Fetch or create required related objects
                        integration_type, _ = IntegrationType.objects.update_or_create(name='Jira')
                        msp_instance, _ = IntegrationMSPConfig.objects.get_or_create(user=user['user'], type=integration_type)
                        client, _ = Client.objects.get_or_create(msp=msp_instance)
                        device, _ = Device.objects.get_or_create(client=client, name="Default Device", device_type="Unknown")

                        # Create Incident
                        Incident.objects.create(
                            title=summary,
                            description=description or "",
                            device=device,
                            severity=severity,
                            jira_ticket=jira_ticket,
                            resolved=False,
                            created_at=created_at,
                            assigned_at=None,
                        )

                    # Check if there are more tickets to fetch
                    if len(total_tickets) >= data.get('total', 0):
                        break
                    start_at += page_size

            return Response({
                "status": "success",
                "message": f"Successfully fetched and stored {len(total_tickets)} Jira issues.",
                "fetched_count": len(total_tickets)
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "error": f"An error occurred while processing Jira issues: {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class ValidateAndSaveJiraDetails(APIView):
    def post(self, request, token):
        print(token)
        if not token:
            return Response({"error": "Token is required"}, status=status.HTTP_400_BAD_REQUEST)

        # Validate user from token
        user = token_verification(token)
        if user['status'] != 200:
            return Response({'message': user['error']}, status=status.HTTP_400_BAD_REQUEST)

        # Extract Jira details from the request
        jira_api_base_url = request.data.get('jira_api_base_url')
        jira_user_email = request.data.get('jira_user_email')
        jira_api_token = request.data.get('jira_api_token')
        jira_project_key = request.data.get('jira_project_key')
        jira_project_name = request.data.get("jira_project_name")

        # Validate inputs
        if not all([jira_api_base_url, jira_user_email, jira_api_token, jira_project_key]):
            return Response({"error": "All Jira details are required."}, status=status.HTTP_400_BAD_REQUEST)

        # Test Jira API connection
        test_url = f"{jira_api_base_url}/rest/api/2/project/{jira_project_key}"
        auth = (jira_user_email, jira_api_token)

        try:
            response = requests.get(test_url, auth=auth)
            if response.status_code == 200:
                # Save details in IntegrationMSPConfig
                integration_type, _ = IntegrationType.objects.get_or_create(name='Jira')
                IntegrationMSPConfig.objects.update_or_create(
                    user=user['user'],
                    type=integration_type,
                    defaults={
                        'jira_api_base_url': jira_api_base_url,
                        'jira_user_email': jira_user_email,
                        'jira_api_token': jira_api_token,
                        'jira_project_key': jira_project_key,
                        'jira_project_name' : jira_project_name
                    }
                )
                return Response({"message": "Jira details validated and saved successfully."}, status=status.HTTP_200_OK)
            else:
                return Response({
                    "error": "Failed to validate Jira details.",
                    "details": response.json()
                }, status=response.status_code)
        except Exception as e:
            return Response({"error": f"An error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
def fetch_jira_predictions(request, token):
    # Token verification
    user = token_verification(token)
    if user['status'] == 200:
        user = user
    else:
        return Response({'message': user['error']}, status=status.HTTP_400_BAD_REQUEST)

    user_role = user['user'].role
    user_instance = user['user']

    print(request.query_params.get('status',None))

    # Get query parameters for filtering and sorting
    status_filter = request.GET.get('status', '')
    priority_filter = request.GET.get('priority', '')
    sort_by = request.GET.get('sort_by', 'id')  # Default sort by id
    order = request.GET.get('order', 'asc')  # Default order is ascending


    # Build filter conditions
    filter_conditions = Q()

    if status_filter:
        filter_conditions &= Q(status=status_filter)
    if priority_filter:
        filter_conditions &= Q(priority=priority_filter)

    # Determine sort order
    if order == 'desc':
        order_by = f'-{sort_by}'  # Descending order
    else:
        order_by = sort_by  # Ascending order

    if user_role in ['gl', 'admin']:
        # If user is admin or gl, fetch all tickets
        tickets = JiraTicket.objects.filter(filter_conditions).values(
            'issue_key', 'project', 'summary', 'description', 
            'status', 'priority', 'predicted_agent', 'confidence_score'
        ).order_by(order_by)
    else:
        # If user is not admin or gl, fetch tickets associated with the user
        tickets = JiraTicket.objects.filter(
            filter_conditions, user=user_instance
        ).values(
            'issue_key', 'project', 'summary', 'description', 
            'status', 'priority', 'predicted_agent', 'confidence_score'
        ).order_by(order_by)

    return Response({"jira_tickets": list(tickets)})

class IntegrationStatusView(APIView):
    def get(self, request, token):
        """Get status of all integrations"""
        user_verification = token_verification(token)
        if user_verification['status'] != 200:
            return Response(
                {'message': user_verification['error']}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        user = user_verification['user']
        
        try:
            # Get all available integration types
            all_integrations = IntegrationType.objects.all()
            
            # Get user's connected integrations
            connected_integrations = IntegrationMSPConfig.objects.filter(user=user)
            
            # Get IDs of connected integration types
            connected_integration_types = connected_integrations.values_list('type_id', flat=True)
            
            # Get available (not yet connected) integration types
            available_integrations = all_integrations.exclude(id__in=connected_integration_types)
            
            response_data = {
                'connected_integrations': ConnectedIntegrationSerializer(
                    connected_integrations, 
                    many=True
                ).data,
                'available_integrations': IntegrationStatusSerializer(
                    available_integrations, 
                    many=True
                ).data
            }
            
            # Add integration-specific details
            for integration in response_data['connected_integrations']:
                integration['details'] = self.get_integration_details(
                    integration['integration_type'],
                    user,
                    connected_integrations
                )
            
            return Response(response_data, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response(
                {'error': f'Failed to fetch integration status: {str(e)}'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def get_integration_details(self, integration_type, user, connected_integrations):
        """Get specific details for each integration type"""
        details = {}
        
        if integration_type == 'Jira':
            jira_config = connected_integrations.filter(type__name='Jira').first()
            if jira_config:
                details.update({
                    'project_count': JiraTicket.objects.filter(
                        user=user
                    ).values('project').distinct().count(),
                    'ticket_count': JiraTicket.objects.filter(user=user).count(),
                    'last_sync': getattr(jira_config, 'updated_at', None),
                    'sync_enabled': getattr(jira_config, 'jira_sync_enabled', True)
                })
        
        elif integration_type == 'ConnectWise':
            connectwise_config = connected_integrations.filter(type__name='ConnectWise').first()
            if connectwise_config:
                details.update({
                    'client_count': Client.objects.filter(
                        msp__user=user, 
                        msp__type__name='ConnectWise'
                    ).count(),
                    'last_sync': getattr(connectwise_config, 'updated_at', None)
                })
        
        elif integration_type == 'HaloPSA':
            halopsa_config = connected_integrations.filter(type__name='HaloPSA').first()
            if halopsa_config:
                details.update({
                    'client_count': Client.objects.filter(
                        msp__user=user, 
                        msp__type__name='HaloPSA'
                    ).count(),
                    'last_sync': getattr(halopsa_config, 'updated_at', None)
                })
        
        return details

class IntegrationDeleteView(APIView):
    def delete(self, request, integration_id, token):
        """Delete an integration configuration"""
        user_verification = token_verification(token)
        if user_verification['status'] != 200:
            return Response(
                {'message': user_verification['error']}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        user = user_verification['user']
        
        try:
            with transaction.atomic():
                # Get the integration
                integration = IntegrationMSPConfig.objects.get(
                    id=integration_id,
                    user=user
                )
                
                integration_type = integration.type.name
                
                # Perform integration-specific cleanup
                if integration_type == 'Jira':
                    # Delete associated Jira tickets
                    JiraTicket.objects.filter(user=user).delete()
                elif integration_type == 'ConnectWise':
                    # Delete associated clients and their devices
                    Client.objects.filter(
                        msp__user=user,
                        msp__type__name='ConnectWise'
                    ).delete()
                
                # Delete the integration configuration
                integration.delete()
                
                return Response({
                    'message': f'{integration_type} integration deleted successfully'
                }, status=status.HTTP_200_OK)
                
        except IntegrationMSPConfig.DoesNotExist:
            return Response({
                'error': 'Integration not found'
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                'error': f'Failed to delete integration: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def perform_integration_cleanup(self, integration_type, user):
        """Perform cleanup tasks specific to each integration type"""
        cleanup_handlers = {
            'Jira': self._cleanup_jira,
            'ConnectWise': self._cleanup_connectwise,
            'HaloPSA': self._cleanup_halopsa
        }
        
        handler = cleanup_handlers.get(integration_type)
        if handler:
            handler(user)

    def _cleanup_jira(self, user):
        """Clean up Jira-specific data"""
        # Delete Jira tickets
        JiraTicket.objects.filter(user=user).delete()
        
        # Delete any Jira-related incidents
        Incident.objects.filter(
            jira_ticket__user=user
        ).update(jira_ticket=None)

    def _cleanup_connectwise(self, user):
        """Clean up ConnectWise-specific data"""
        # Delete associated clients and their devices
        Client.objects.filter(
            msp__user=user,
            msp__type__name='ConnectWise'
        ).delete()

    def _cleanup_halopsa(self, user):
        """Clean up HaloPSA-specific data"""
        # Add HaloPSA-specific cleanup logic
        pass

def get_user_role(request, token):
    if not token:
            return Response({"error": "Token is required"}, status=status.HTTP_400_BAD_REQUEST)
    # Validate user from token
    user = token_verification(token)
    if user['status'] != 200:
        return Response({'message': user['error']}, status=status.HTTP_400_BAD_REQUEST)
    return JsonResponse({"role": user['user'].role}, status = status.HTTP_200_OK)


# @csrf_exempt
# def get_model_parameters(request):
#     model_name = request.GET.get("model")
#     if model_name == "Device Incident Response":
#         params = joblib.load("device_model_params.pkl")
#         metrics = joblib.load("device_model_metrics.pkl")
#     elif model_name == "JIRA Ticket Classification":
#         params = joblib.load("jira_model_params.pkl")
#         metrics = joblib.load("jira_model_metrics.pkl")
#     else:
#         return JsonResponse({"error": "Invalid model name"}, status=400)
#     return JsonResponse({"parameters": params, "metrics": metrics})

# @csrf_exempt
# def update_model_parameters(request):
#     data = json.loads(request.body)
#     model_name = data.get("model")
#     new_params = data.get("parameters")

#     if model_name == "Device Incident Response":
#         joblib.dump(new_params, "device_model_params.pkl")
#     elif model_name == "JIRA Ticket Classification":
#         joblib.dump(new_params, "jira_model_params.pkl")
#     else:
#         return JsonResponse({"error": "Invalid model name"}, status=400)
    
#     return JsonResponse({"message": "Parameters updated successfully!"})

# @csrf_exempt
# def retrain_model(request):
#     data = json.loads(request.body)
#     model_name = data.get("model")

#     if model_name == "Device Incident Response":
#         retrain_device_model()
#     elif model_name == "JIRA Ticket Classification":
#         retrain_jira_model()
#     else:
#         return JsonResponse({"error": "Invalid model name"}, status=400)
    
#     return JsonResponse({"message": "Model re-training completed successfully!"})