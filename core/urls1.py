from django.urls import path, include
from core import views
from .the_new import *
from rest_framework.routers import DefaultRouter
from . import views1
from .views import (
    ClientViewSet,
    DeviceViewSet,
    SeverityViewSet,
    IncidentViewSet,
    AgentViewSet,
    TaskViewSet,
    # dashboard_summary,
    UserProfileViewSet,
    TeamViewSet,
    # register,
    # LogoutViewAPI,
    # MspViewSet
)
from incidentmanagement import settings
from django.conf.urls.static import static
# from . import human_tickets, recording
from .gl_view import *
from .model_management import *


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
    path('select-integration-type/', select_integration_type,
         name='select_integration_type'),  # Select integration type view
    path('integration-config/<int:type_id>/', integration_config,
         name='integration_config'),  # Configuration view for specific integration type
    path('save-integration-config/<str:token>', save_integration_config,
         name='save_integration_config'),  # Save configuration endpoint
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('dashboard-summary/<str:token>', dashboard_data_, name='dashboard_summary'),

    path('register/', register, name='register'),

    path('login/', LoginViewAPI.as_view(), name='login'),
    path('logout/<str:token>', LogoutViewAPI.as_view(), name='logout'),

    path('integration/types/', views1.IntegrationTypeView.as_view(),
         name='integration_types'),
    path('integration/msp-config/', views1.IntegrationMSPConfigView.as_view(),
         name='integration_msp_config'),

    path('teams/<str:token>', TeamManagementAPI.as_view(),
         name='team_management'),  # For creating and viewing teams
    path('teams/<int:team_id>/<str:token>', TeamManagementAPI.as_view(),
         name='team_detail'),  # For updating and deleting teams

    path('customers/<str:token>', ClientManagementAPI.as_view(),
         name='client-management'),  # For creating and listing clients
    path('customers/<int:client_id>/<str:token>', ClientManagementAPI.as_view(),
         name='client-detail'),  # For retrieving, updating, and deleting specific clients

    path('devices/<str:token>', DeviceManagementAPI.as_view(),
         name='device-management'),  # For listing and creating devices
    path('devices/<int:device_id>/<str:token>', DeviceManagementAPI.as_view(),
         name='device-detail'),  # For retrieving, updating, and deleting a specific device

    path('incidents/<str:token>', IncidentManagementAPI.as_view(),
         name='incident-management'),  # For listing and creating incidents
    path('incidents/<int:incident_id>/<str:token>', IncidentManagementAPI.as_view(),
         name='incident-detail'),  # For retrieving, updating, and deleting a specific incident

    path('api/assign-clients/<str:token>',
        AssignClientsToTeamMembers.as_view(), name='assign_clients'),
    path('api/team-members/<str:token>', get_team_members, name='get_team_members'),

    path('severities/<str:token>', SeverityAPI.as_view(),
         name='severity-list'),  # Add this line

    path('connectwise/setup/<str:token>', connectwise_setup, name='connectwise_setup'),
    path('halopsa/setup/<str:token>', halopsa_setup, name='halopsa_setup'),
    path('fetch-data/<str:token>', fetch_data, name='fetch_data'),

    path('incidents/status/<str:status>/<str:token>',
         IncidentsByStatus.as_view(), name='incidents_by_status'),

    path('incidents/severity/<str:severity>/<str:token>',
         IncidentsBySeverity.as_view(), name='incidents_by_severity'),
    path('incidents/device/<str:device>/<str:token>',
         IncidentsByDevice.as_view(), name='incidents_by_device'),

    # GET request to retrieve preferences
    path('user/preferences/<str:token>', get_preferences, name='get_preferences'),
    path('user/preferences/update/<str:token>', update_preferences,
         name='update_preferences'),  # POST request to update preferences

    path('orchestration/<int:incident_id>/<str:token>',
         RunOrchestrationView.as_view(), name='run-orchestration'),
    
    path('incident/<int:incident_id>/logs/<str:token>', get_incident_logs, name='get_incident_logs'),
    
    path('incident-logs/<str:token>', get_all_incident_logs, name='incident_logs'),
    
    path('incident-log-details/<str:token>', get_incident_log_details, name='incident-log-details'),

    path('get_assigned_tickets/<str:token>',get_assigned_tickets, name='get assigned tickets'),

#     path('record', recording.record_screen,name='record'),

    path('overview/', views1.dashboard_n, name='dashboard'),

    path('upload/', views1.upload_page, name='upload_page'),
    
#     path('upload_recording_file/', views1.upload_recording, name='upload_recording'),

    path('start_recording/<str:token>',start_recording, name='start recording'),

    path('stop_recording/<str:token>',stop_recording, name='stop recording'),

    ##########
    path('upload_recording_chunk/<str:token>', upload_recording_chunk, name='upload_recording_chunk'),
    path('finalize_recording/<str:token>', finalize_recording, name='finalize_recording'),

    path('incident/<int:incident_id>/post-resolution',PostResolutionClassification.as_view(), name ='human agent post resolution'),
#     path('generate_workflow/', GenerateWorkflowView.as_view(), name='generate_workflow'),
     path('gl-dashboard/<str:token>', GLDashboardView.as_view(), name='gl-dashboard'),
     path('update-role/<str:token>', UpdateUserRoleAPIView.as_view(), name='update user role'),

     path('validate-and-save-jira/<str:token>', ValidateAndSaveJiraDetails.as_view(), name='validate_and_save_jira'),
     path('fetch-jira-issues/<str:token>', FetchJiraIssues.as_view(), name='fetch_jira_issues'),

     path('fetch_jira_predictions/<str:token>',fetch_jira_predictions, name='fetch jira predictions'),

     path('integrations/status/<str:token>', IntegrationStatusView.as_view(), name='integration_status'),
     path('integrations/<int:integration_id>/<str:token>', IntegrationDeleteView.as_view(), name='integration_delete'),

     # get_user_role
     path("get_user_role/<str:token>", get_user_role, name=''),


     path('upload-model/', upload_model, name='upload_model'),
     path('set-active/<int:model_id>/', set_active_model, name='set_active_model'),
     path('delete-model/<int:model_id>/', delete_model, name='delete_model'),
     path('edit-model/<int:model_id>/', edit_model, name='edit_model'),
     path('fetch-models/', fetch_models, name='fetch_models'),


] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
