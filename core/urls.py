from django.urls import path
from core import views
from .views import RegisterViewAPI, LoginViewAPI

urlpatterns = [
    path('register/', RegisterViewAPI.as_view(), name='Signup'),
    path('login/', LoginViewAPI.as_view(), name='Login'),
    path('select-integration-type/', views.select_integration_type, name='select_integration_type'),  # Select integration type view
    path('integration-config/<int:type_id>/', views.integration_config, name='integration_config'),  # Configuration view for specific integration type
    path('save-integration-config/', views.save_integration_config, name='save_integration_config'),  # Save configuration endpoint
    path('dashboard/', views.dashboard_view, name='dashboard'),
]