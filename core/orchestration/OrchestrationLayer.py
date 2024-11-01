import pika
import json
from core.agents.network_agent import NetworkAgent
from core.agents.security_agent import SecurityAgent
from core.agents.hardware_agent import HardwareAgent
from core.agents.software_agent import SoftwareAgent
from core.agents.human_agent import HumanAgent  # Add HumanAgent import
from core.models import Incident
# Import the prediction model
from core.management.ml_model.MLModel import IncidentMLModel


class OrchestrationLayer:
    def __init__(self):
        # Initialize agents, including a human agent
        self.agents = {
            'network': NetworkAgent(),
            'security': SecurityAgent(),
            'hardware': HardwareAgent(),
            'software': SoftwareAgent(),
            'human': HumanAgent()  # New human agent for low-confidence incidents
        }
        self.connection = pika.BlockingConnection(
            pika.ConnectionParameters(host='localhost'))
        self.channel = self.connection.channel()
        self.channel.queue_declare(queue='task_queue', durable=True)
        self.ml_model = IncidentMLModel()  # Initialize the ML model for predictions

    def get_unresolved_incidents(self):
        """Fetch unresolved incidents from the database using Django ORM."""
        return Incident.objects.filter(resolved=False).select_related('severity')

    def map_incident_to_agent(self, incident):
        """Map an incident to the appropriate agent based on the model prediction or keywords."""
        # Use the prediction model to get a recommended solution
        incident_data = {
            'severity_id': incident.severity.id,
            'device_id': incident.device.id,
            'description': incident.description
        }

        recommended_solution = self.ml_model.predict_solution(incident_data)

        # If human intervention is needed, map it to the human agent and set the field
        if recommended_solution == "Human Intervention Needed":
            incident.human_intervention_needed = True  # Set the flag
            incident.save()  # Save to update in the database
            return 'human'

        # Reset the flag if not needed
        incident.human_intervention_needed = False
        incident.save()

        # Map to agent type based on keywords in title/description/recommended_solution
        if "network" in incident.title.lower() or "network" in incident.description.lower() or "network" in incident.recommended_solution.lower():
            return 'network'
        elif "security" in incident.title.lower() or "security" in incident.description.lower() or "security" in incident.recommended_solution.lower():
            return 'security'
        elif "hardware" in incident.title.lower() or "hardware" in incident.description.lower() or "hardware" in incident.recommended_solution.lower():
            return 'hardware'
        else:
            return 'software'  # Default to software if no match found

    def dispatch_incident(self, incident):
        """Send the incident to the appropriate agent using RabbitMQ."""
        agent_type = self.map_incident_to_agent(incident)

        # Ensure task_description is added
        task_data = {
            'incident_id': incident.id,
            'title': incident.title,
            'description': incident.description,
            'severity': incident.severity.level,
            'agent_type': agent_type,
            'task_description': f"Resolve incident: {incident.title}",
            # New field in task data
            'human_intervention_needed': incident.human_intervention_needed
        }
        print(f"Dispatching task to agent: {agent_type}")
        print(f"Task Data: {task_data}")

        self.channel.basic_publish(
            exchange='',
            routing_key='task_queue',
            body=json.dumps(task_data),
            properties=pika.BasicProperties(
                delivery_mode=2,  # Make the message persistent
            ))
        print(f"Dispatched incident {incident.title} to {agent_type} agent.")
        return agent_type

    def process_unresolved_incidents(self):
        """Fetch unresolved incidents from the database and dispatch them to agents."""
        incidents = self.get_unresolved_incidents()
        for incident in incidents:
            self.dispatch_incident(incident)

    def on_message(self, ch, method, properties, body):
        """Process the message from RabbitMQ and send it to the appropriate agent."""
        task_data = json.loads(body)
        agent_type = task_data.get('agent_type')
        if agent_type in self.agents:
            agent = self.agents[agent_type]
            agent.process_task(task_data)
        ch.basic_ack(delivery_tag=method.delivery_tag)

    def start_listening(self):
        """Start listening for tasks from RabbitMQ."""
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