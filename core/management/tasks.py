# tasks.py
# Example background tasks for incident management

from celery import shared_task
from incident_management.django_model.model import Incident

@shared_task
def resolve_incident(incident_id):
    try:
        incident = Incident.objects.get(id=incident_id)
        # Simulate resolution
        incident.resolved = True
        incident.recommended_solution = "Resolved automatically by background task"
        incident.save()
        return f"Incident {incident_id} resolved."
    except Incident.DoesNotExist:
        return f"Incident {incident_id} does not exist."

# Example usage (within the app)
# resolve_incident.delay(incident_id)