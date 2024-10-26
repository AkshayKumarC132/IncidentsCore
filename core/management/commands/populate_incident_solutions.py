# myapp/management/commands/populate_incident_solutions.py

from django.core.management.base import BaseCommand
from core.models import Incident

class Command(BaseCommand):
    help = 'Populate recommended solutions and predicted resolution times for incidents'

    def handle(self, *args, **kwargs):
        incidents = Incident.objects.filter(resolved=False)  # Get unresolved incidents

        for incident in incidents:
            title = incident.title.lower()
            description = incident.description.lower()

            if 'onboarding' in title or 'training' in title:
                incident.recommended_solution = "Conduct user training sessions to ensure proper onboarding."
                incident.predicted_resolution_time = 2.0  # Estimated time in hours
            
            elif 'install' in title or 'configuration' in title:
                incident.recommended_solution = "Install necessary software or configure devices as per requirements."
                incident.predicted_resolution_time = 4.0  # Estimated time in hours
            
            elif 'not opening' in title or 'login' in title:
                incident.recommended_solution = "Check user credentials and system status; reset passwords if necessary."
                incident.predicted_resolution_time = 1.0  # Estimated time in hours
            
            elif 'downtime' in title:
                incident.recommended_solution = "Communicate downtime schedule to affected users and ensure backups are available."
                incident.predicted_resolution_time = 3.0  # Estimated time in hours
            
            elif 'error' in title:
                incident.recommended_solution = "Investigate the error logs and troubleshoot the application."
                incident.predicted_resolution_time = 1.5  # Estimated time in hours
            
            elif 'hardware' in title or 'laptop' in title or 'server' in title:
                incident.recommended_solution = "Inspect hardware components for issues; consider replacement if necessary."
                incident.predicted_resolution_time = 2.5  # Estimated time in hours
            
            else:
                incident.recommended_solution = "Review the issue further to determine appropriate actions."
                incident.predicted_resolution_time = None

            # Save changes to the database
            incident.save()
            self.stdout.write(self.style.SUCCESS(f'Successfully updated Incident: {incident.title}'))
