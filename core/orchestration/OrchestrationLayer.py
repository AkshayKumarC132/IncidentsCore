import pika
import json
from core.agents.network_agent import NetworkAgent
from core.agents.security_agent import SecurityAgent
from core.agents.hardware_agent import HardwareAgent
from core.agents.software_agent import SoftwareAgent
from core.agents.human_agent import HumanAgent
from core.models import Incident, IncidentLog
from core.management.ml_model.MLModel import IncidentMLModel
from django.utils import timezone
from django.core.exceptions import ObjectDoesNotExist

class OrchestrationLayer:
    def __init__(self):
        self.agents = {
            'network': NetworkAgent(),
            'security': SecurityAgent(),
            'hardware': HardwareAgent(),
            'software': SoftwareAgent(),
            'human': HumanAgent()
        }
        self.connection = pika.BlockingConnection(
            pika.ConnectionParameters(host='localhost'))
        self.channel = self.connection.channel()
        self.channel.queue_declare(queue='task_queue', durable=True)
        self.ml_model = IncidentMLModel()
        
    def get_unresolved_incidents(self):
        """Fetch unresolved incidents from the database using Django ORM."""
        return Incident.objects.filter(resolved=False).select_related('severity')

    def map_incident_to_agent(self, incident):
        incident_data = {
            'severity_id': incident.severity.id,
            'device_id': incident.device.id,
            'description': incident.description
        }

        recommended_solution = self.ml_model.predict_solution(incident_data)
        incident.human_intervention_needed = recommended_solution == "Human Intervention Needed"
        incident.save()

        if "network" in incident.title.lower() or "network" in incident.description.lower():
            return 'network'
        elif "security" in incident.title.lower() or "security" in incident.description.lower():
            return 'security'
        elif "hardware" in incident.title.lower() or "hardware" in incident.description.lower():
            return 'hardware'
        else:
            return 'software'

    def dispatch_incident(self, incident):
        agent_type = self.map_incident_to_agent(incident)

        # Create the log entry
        log_entry = IncidentLog.objects.create(
            incident=incident,
            assigned_agent=agent_type,
            assigned_at=timezone.now()
        )

        # Prepare task data
        task_data = {
            'incident_id': incident.id,
            'title': incident.title,
            'description': incident.description,
            'severity': incident.severity.level,
            'agent_type': agent_type,
            'task_description': f"Resolve incident: {incident.title}",
            'log_id': log_entry.id,  # Store the actual log ID
            'human_intervention_needed': agent_type == 'human'
        }

        # Debugging log for task_data before publishing
        print(f"Publishing Task Data: {task_data} with log_id {log_entry.id}")
        
        # Publish task data to queue
        self.channel.basic_publish(
            exchange='',
            routing_key='task_queue',
            body=json.dumps(task_data),
            properties=pika.BasicProperties(
                delivery_mode=2,
            )
        )
        print(f"Dispatched incident '{incident.title}' to {agent_type} agent.")
        return agent_type
    def process_unresolved_incidents(self):
        """Fetch unresolved incidents from the database and dispatch them to agents."""
        incidents = self.get_unresolved_incidents()
        for incident in incidents:
            self.dispatch_incident(incident)

    def on_message(self, ch, method, properties, body):
        # Deserialize the message
        task_data = json.loads(body)
        print(f"Deserialized Task Data in on_message: {task_data}")

        agent_type = task_data.get('agent_type')
        log_id = task_data.get('log_id')  # Retrieve the log ID

        # Debugging log for verification
        print(f"Processing Task Data with log_id {log_id} in on_message")

        # Check if log_id is missing
        if not log_id:
            print("Warning: 'log_id' not found in task_data, skipping this message.")
            ch.basic_ack(delivery_tag=method.delivery_tag)
            return

        try:
            log_entry = IncidentLog.objects.get(id=log_id)
            print(log_entry)
        except ObjectDoesNotExist:
            print(f"IncidentLog with id {log_id} not found, skipping log update.")
            ch.basic_ack(delivery_tag=method.delivery_tag)
            return

        if agent_type in self.agents:
            agent = self.agents[agent_type]
            print(f"Assigned agent: {agent}")

            agent.process_task(task_data)
            log_entry.resolved_at = timezone.now()
            log_entry.resolution_time = (log_entry.resolved_at - log_entry.assigned_at).total_seconds() / 3600.0
            log_entry.save()
            print(f"Task for incident {task_data['incident_id']} processed by {agent_type} agent.")
        print("Here")
        ch.basic_ack(delivery_tag=method.delivery_tag)
        print("COmpleted")

    def start_listening(self):
        self.channel.basic_consume(
            queue='task_queue', on_message_callback=self.on_message)
        print(' [*] Waiting for messages. To exit press CTRL+C')
        self.channel.start_consuming()


# To start the orchestration layer
if __name__ == '__main__':
    orchestrator = OrchestrationLayer()
    # Fetch and dispatch unresolved incidents
    orchestrator.process_unresolved_incidents()
    orchestrator.start_listening()  # Start listening for agent processing
