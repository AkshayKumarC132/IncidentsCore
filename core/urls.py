from django.urls import path, include
from core import views
from .views import RegisterViewAPI, LoginViewAPI
from rest_framework.routers import DefaultRouter
from . import views1
from .views import (
    ClientViewSet,
    DeviceViewSet,
    SeverityViewSet,
    IncidentViewSet,
    AgentViewSet,
    TaskViewSet,
    dashboard_summary,
    UserProfileViewSet,
    TeamViewSet,
    register,
    LogoutViewAPI,
    MspViewSet
)
from incidentmanagement import settings
from django.conf.urls.static import static
# from . import human_tickets, recording

router = DefaultRouter()
# router.register(r'customers', ClientViewSet)
# router.register(r'devices', DeviceViewSet)
# router.register(r'severities', SeverityViewSet)
# router.register(r'incidents', IncidentViewSet)
# router.register(r'agents', AgentViewSet)
# router.register(r'tasks', TaskViewSet)
router.register(r'users', UserProfileViewSet)
# router.register(r'teams', TeamViewSet)
router.register(r'msps', MspViewSet, basename='msps')

urlpatterns = [
    path('', include(router.urls)),
    # path('register/', register, name='Signup'),
    # # path('register/', RegisterViewAPI.as_view(), name='Signup'),
    # path('login/', LoginViewAPI.as_view(), name='Login'),
    # path('logout/', LogoutViewAPI.as_view(), name='logout'),  # Logout
    path('select-integration-type/', views.select_integration_type,
         name='select_integration_type'),  # Select integration type view
    path('integration-config/<int:type_id>/', views.integration_config,
         name='integration_config'),  # Configuration view for specific integration type
    path('save-integration-config/', views.save_integration_config,
         name='save_integration_config'),  # Save configuration endpoint
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('dashboard-summary/', views.dashboard_data_, name='dashboard_summary'),

    path('register/', views1.register, name='register'),

    path('login/', views1.LoginViewAPI.as_view(), name='login'),
    path('logout/', views1.LogoutViewAPI.as_view(), name='logout'),

    path('integration/types/', views1.IntegrationTypeView.as_view(),
         name='integration_types'),
    path('integration/msp-config/', views1.IntegrationMSPConfigView.as_view(),
         name='integration_msp_config'),

    path('teams/', views1.TeamManagementAPI.as_view(),
         name='team_management'),  # For creating and viewing teams
    path('teams/<int:team_id>/', views1.TeamManagementAPI.as_view(),
         name='team_detail'),  # For updating and deleting teams

    path('customers/', views1.ClientManagementAPI.as_view(),
         name='client-management'),  # For creating and listing clients
    path('customers/<int:client_id>/', views1.ClientManagementAPI.as_view(),
         name='client-detail'),  # For retrieving, updating, and deleting specific clients

    path('devices/', views1.DeviceManagementAPI.as_view(),
         name='device-management'),  # For listing and creating devices
    path('devices/<int:device_id>/', views1.DeviceManagementAPI.as_view(),
         name='device-detail'),  # For retrieving, updating, and deleting a specific device

    path('incidents/', views1.IncidentManagementAPI.as_view(),
         name='incident-management'),  # For listing and creating incidents
    path('incidents/<int:incident_id>/', views1.IncidentManagementAPI.as_view(),
         name='incident-detail'),  # For retrieving, updating, and deleting a specific incident

    path('api/assign-clients/',
         views1.AssignClientsToTeamMembers.as_view(), name='assign_clients'),
    path('api/team-members/', views1.get_team_members, name='get_team_members'),

    path('severities/', views1.SeverityAPI.as_view(),
         name='severity-list'),  # Add this line

    path('connectwise/setup/', views1.connectwise_setup, name='connectwise_setup'),
    path('halopsa/setup/', views1.halopsa_setup, name='halopsa_setup'),
    path('fetch-data/', views1.fetch_data, name='fetch_data'),

    path('incidents/status/<str:status>/',
         views1.IncidentsByStatus.as_view(), name='incidents_by_status'),

    path('incidents/severity/<str:severity>/',
         views1.IncidentsBySeverity.as_view(), name='incidents_by_severity'),
    path('incidents/device/<str:device>/',
         views1.IncidentsByDevice.as_view(), name='incidents_by_device'),

    # GET request to retrieve preferences
    path('user/preferences/', views1.get_preferences, name='get_preferences'),
    path('user/preferences/update/', views1.update_preferences,
         name='update_preferences'),  # POST request to update preferences

    path('orchestration/<int:incident_id>/',
         views1.RunOrchestrationView.as_view(), name='run-orchestration'),
    
    path('incident/<int:incident_id>/logs/', views1.get_incident_logs, name='get_incident_logs'),
    
    path('incident-logs/', views1.get_all_incident_logs, name='incident_logs'),
    
    path('incident-log-details/', views1.get_incident_log_details, name='incident-log-details'),

    path('get_assigned_tickets/',views1.get_assigned_tickets, name='get assigned tickets'),

#     path('record', recording.record_screen,name='record'),

    path('overview/', views1.dashboard_n, name='dashboard'),

    path('upload/', views1.upload_page, name='upload_page'),
    
#     path('upload_recording_file/', views1.upload_recording, name='upload_recording'),

    path('start_recording/',views1.start_recording, name='start recording'),

    path('stop_recording/',views1.stop_recording, name='stop recording'),

    ##########
    path('upload_recording_chunk/', views1.upload_recording_chunk, name='upload_recording_chunk'),
    path('finalize_recording/', views1.finalize_recording, name='finalize_recording'),

] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
