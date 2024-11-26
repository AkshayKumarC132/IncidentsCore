import pika
import json
from core.agents.network_agent import NetworkAgent
from core.agents.security_agent import SecurityAgent
from core.agents.hardware_agent import HardwareAgent
from core.agents.software_agent import SoftwareAgent
from core.agents.human_agent import HumanAgent
from core.models import Incident, IncidentLog, UserProfile
from core.management.ml_model.MLModel import IncidentMLModel
from django.utils import timezone
from django.core.exceptions import ObjectDoesNotExist
from django.core.mail import send_mail

class OrchestrationLayer():

    def __init__(self):
        try:
        # Initialize agents
            self.agents = {
                'network': NetworkAgent(),
                'security': SecurityAgent(),
                'hardware': HardwareAgent(),
                'software': SoftwareAgent(),
                'human': HumanAgent()  # Human agent for unhandled incidents
            }
            self.connection = pika.BlockingConnection(pika.ConnectionParameters(host='localhost'))
            self.channel = self.connection.channel()
            self.channel.queue_declare(queue='task_queue', durable=True)
            self.ml_model = IncidentMLModel()
        except Exception as e:

            print(str(e))
            # return str(e)

    def send_email_notification(self, agent_type, incident):
        """Send an email notification when a ticket is assigned to a human agent."""
        if agent_type == "human":
            # Email details
            subject = f"New Ticket Assigned: {incident.title}"
            message = f"""
            Dear Human Agent,

            A new ticket has been assigned to you:
            - Title: {incident.title}
            - Description: {incident.description or "No description provided"}
            - Severity: {incident.severity.level}
            - Assigned At: {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}

            Please log in to the system to resolve the issue.

            Thank you,
            Automated Incident Response System
            """
            recipient_list = ["human.agent@example.com"]  # Replace with dynamic recipient(s)
            
            try:
                send_mail(
                    subject,
                    message,
                    "pakshay@stratapps.com",  # From email
                    recipient_list,
                    fail_silently=False,
                )
                print("Email notification sent to Human Agent.")
            except:
                pass
            
    def get_unresolved_incidents(self):
        """Fetch unresolved incidents from the database."""
        return Incident.objects.filter(resolved=False).select_related('severity')

    def map_incident_to_agent(self, incident):
        try:
            print("This is Incident Data=========", incident)
            """Map an incident to the appropriate agent based on prediction or keywords."""
            # Prepare data for the ML model
            incident_data = {
                'severity_id': incident.severity.id,
                'device_id': incident.device.id,
                'description': incident.description
            }
            recommended_solution = self.ml_model.predict_solution(incident_data)

            if recommended_solution == "Human Intervention Needed":
                incident.human_intervention_needed = True
                incident.save()
                return 'human'

            # Reset if not needed
            incident.human_intervention_needed = False
            incident.save()

            # Determine agent type
            if "network" in incident.title.lower() or "network" in incident.description.lower():
                return 'network'
            elif "security" in incident.title.lower() or "security" in incident.description.lower():
                return 'security'
            elif "hardware" in incident.title.lower() or "hardware" in incident.description.lower():
                return 'hardware'
            else:
                return 'software'
        except Exception as e:
            return str(e)

    def dispatch_incident(self, incident):
        try:
            """Dispatch the incident to the appropriate agent and log the action."""
            agent_type = self.map_incident_to_agent(incident)

            # Find or assign an agent
            assigned_agent = None
            if agent_type == 'human':
                # Example: Fetch the first available human agent (modify as per your logic)
                assigned_agent = UserProfile.objects.filter(role='human_agent', is_active=True).first()
                if assigned_agent:
                    incident.assigned_agent = assigned_agent
                    incident.assigned_at = timezone.now()
                    incident.save()

            # Log the assignment
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
                'log_id': log_entry.id,
                'human_intervention_needed': True if agent_type == 'human' else False,
                'assigned_agent_id': assigned_agent.id if assigned_agent else None
            }
            # Send task to RabbitMQ
            self.channel.basic_publish(
                exchange='',
                routing_key='task_queue',
                body=json.dumps(task_data),
                properties=pika.BasicProperties(delivery_mode=2)  # Persistent message
            )
            print(f"Dispatched incident {incident.title} to {agent_type} agent.")

            # Notify human agent if applicable
            # if agent_type == 'human' and assigned_agent:
            #     send_email_notification(assigned_agent.email, incident.title)  # Replace with dynamic email fetching
            return agent_type
        except Exception as e:
             return str(e)
        
    def process_unresolved_incidents(self):
        """Fetch and dispatch unresolved incidents."""
        incidents = self.get_unresolved_incidents()
        for incident in incidents:
            self.dispatch_incident(incident)

    def on_message(self, ch, method, properties, body):
        task_data = json.loads(body)
        log_id = task_data.get('log_id')
        # agent_type = task_data.get('agent_type')

        if log_id:
            log_entry = IncidentLog.objects.get(id=log_id)
            log_entry.resolved_at = timezone.now()
            log_entry.save()
        ch.basic_ack(delivery_tag=method.delivery_tag)
        
    # def on_message(self, ch, method, properties, body):
    #     """Process the message from RabbitMQ and log resolution details."""
    #     task_data = json.loads(body)
    #     print(f"Received Task Data: {task_data}")

    #     agent_type = task_data.get('agent_type')
    #     log_id = task_data.get('log_id')

    #     if agent_type in self.agents:
    #         agent = self.agents[agent_type]
    #         agent.process_task(task_data)

    #         # Update log entry
    #         if log_id:
    #             log_entry = IncidentLog.objects.get(id=log_id)
    #             log_entry.resolution_started_at = log_entry.resolution_started_at or timezone.now()
    #             log_entry.resolved_at = timezone.now()
    #             log_entry.resolution_time = (
    #                 log_entry.resolved_at - log_entry.assigned_at
    #             ).total_seconds() / 3600.0  # Resolution time in hours
    #             log_entry.save()
    #         else:
    #             print("Error: log_id not found in task_data")

    #     ch.basic_ack(delivery_tag=method.delivery_tag)

    def start_listening(self):
        """Start listening for tasks from RabbitMQ."""
        self.channel.basic_consume(queue='task_queue', on_message_callback=self.on_message)
        print(' [*] Waiting for messages. To exit press CTRL+C')
        self.channel.start_consuming()

if __name__ == '__main__':
    orchestrator = OrchestrationLayer()
    orchestrator.process_unresolved_incidents()
    orchestrator.start_listening()