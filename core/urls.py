from django.urls import path,include
from core import views
from .views import RegisterViewAPI, LoginViewAPI
from rest_framework.routers import DefaultRouter
from .views import (
    ClientViewSet, 
    DeviceViewSet, 
    SeverityViewSet, 
    IncidentViewSet, 
    AgentViewSet, 
    TaskViewSet,
    dashboard_summary
)

router = DefaultRouter()
router.register(r'customers', ClientViewSet)
router.register(r'devices', DeviceViewSet)
router.register(r'severities', SeverityViewSet)
router.register(r'incidents', IncidentViewSet)
router.register(r'agents', AgentViewSet)
router.register(r'tasks', TaskViewSet)

urlpatterns = [
    path('', include(router.urls)),
    path('register/', RegisterViewAPI.as_view(), name='Signup'),
    path('login/', LoginViewAPI.as_view(), name='Login'),
    path('select-integration-type/', views.select_integration_type, name='select_integration_type'),  # Select integration type view
    path('integration-config/<int:type_id>/', views.integration_config, name='integration_config'),  # Configuration view for specific integration type
    path('save-integration-config/', views.save_integration_config, name='save_integration_config'),  # Save configuration endpoint
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('dashboard-summary/', dashboard_summary, name='dashboard_summary'),
]