from django.core.management.base import BaseCommand
from core.orchestration.OrchestrationLayer import OrchestrationLayer  # Adjust the import path as necessary

class Command(BaseCommand):
    help = 'Run the Orchestration Layer to process unresolved incidents'

    def handle(self, *args, **kwargs):
        # Create an instance of OrchestrationLayer
        orchestrator = OrchestrationLayer()
        
        # Fetch and dispatch unresolved incidents
        orchestrator.process_unresolved_incidents()
        
        # Start listening for messages from RabbitMQ
        orchestrator.start_listening()
        
        
# python manage.py run_orchestration