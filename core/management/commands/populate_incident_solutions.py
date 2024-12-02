# myapp/management/commands/populate_incident_solutions.py

from django.core.management.base import BaseCommand
from core.models import Incident

class Command(BaseCommand):
    help = 'Populate recommended solutions, predicted resolution times, and agents for incidents'

    def handle(self, *args, **kwargs):
        incidents = Incident.objects.filter(resolved=False)  # Get unresolved incidents
        for incident in incidents:
            # Convert title and description to lowercase for case-insensitive keyword matching
            title = incident.title.lower() if incident.title else ''
            description = incident.description.lower() if incident.description else ''

            # Combine title and description for keyword matching
            content = f"{title} {description}"

            if 'onboarding' in content or 'training' in content:
                incident.recommended_solution = (
                    "Conduct user training sessions to ensure proper onboarding. "
                    "Agent: human."
                )
                incident.predicted_resolution_time = 2.0  # Estimated time in hours
                
            
            elif 'install' in content or 'configuration' in content:
                incident.recommended_solution = (
                    "Install necessary software or configure devices as per requirements. "
                    "Agent: software."
                )
                incident.predicted_resolution_time = 4.0  # Estimated time in hours
            
            elif 'not opening' in content or 'login' in content:
                incident.recommended_solution = (
                    "Check user credentials and system status; reset passwords if necessary. "
                    "Agent: security."
                )
                incident.predicted_resolution_time = 1.0  # Estimated time in hours
            
            elif 'downtime' in content:
                incident.recommended_solution = (
                    "Communicate downtime schedule to affected users and ensure backups are available. "
                    "Agent: network."
                )
                incident.predicted_resolution_time = 3.0  # Estimated time in hours
            
            elif 'error' in content:
                incident.recommended_solution = (
                    "Investigate the error logs and troubleshoot the application. "
                    "Agent: software."
                )
                incident.predicted_resolution_time = 1.5  # Estimated time in hours
            
            elif 'hardware' in content or 'laptop' in content or 'server' in content:
                incident.recommended_solution = (
                    "Inspect hardware components for issues; consider replacement if necessary. "
                    "Agent: hardware."
                )
                incident.predicted_resolution_time = 2.5  # Estimated time in hours
            
            elif 'exchange server' in content or 'migration' in content:
                incident.recommended_solution = (
                    "Perform the necessary steps for server migration or exchange configuration. "
                    "Agent: network."
                )
                incident.predicted_resolution_time = 6.0  # Estimated time in hours
            
            else:
                incident.recommended_solution = (
                    "Review the issue further to determine appropriate actions. "
                    "Agent: human."
                )
                incident.predicted_resolution_time = None

            # Save changes to the database
            incident.description = incident.title
            incident.save()
            self.stdout.write(
                self.style.SUCCESS(f'Successfully updated Incident: {incident.title}')
            )