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
            recipient_list = ["pakshay@stratapps.com","sudhir.nambiar@stratapps.com"]  # Replace with dynamic recipient(s)
            
            try:
                send_mail(
                    subject,
                    message,
                    "pakshay@stratapps.com",  # From email
                    recipient_list,
                    fail_silently=False,
                )
                print("Email notification sent to Human Agent.")
            except Exception as e:
                print(f"Error sending email notification: {str(e)}")
                pass
            
    def get_unresolved_incidents(self):
        """Fetch unresolved incidents from the database."""
        return Incident.objects.filter(resolved=False).select_related('severity')

    def map_incident_to_agent(self, incident):
        try:
            """Map an incident to the appropriate agent based on prediction or keywords."""
            # Prepare data for the ML model
            incident_data = {
                'severity_id': incident.severity.id,
                'device_id': incident.device.id,
                'description': incident.description
            }
            
            # Get predictions with confidence scores
            predicted_time, time_confidence = self.ml_model.predict_time(incident_data)
            recommended_solution, solution_confidence = self.ml_model.predict_solution(incident_data)

            # Update incident with predictions and confidence scores
            incident.predicted_resolution_time = predicted_time
            incident.recommended_solution = recommended_solution
            
            # Use the higher confidence score between time and solution predictions
            confidence_score = max(filter(None, [time_confidence, solution_confidence])) if any([time_confidence, solution_confidence]) else None
            incident.confidence_score = confidence_score * 100

            if recommended_solution == "Human Intervention Needed" or (confidence_score and confidence_score < 0.6):
                incident.human_intervention_needed = True
                incident.save()
                return 'human'

            # Reset if not needed
            incident.human_intervention_needed = False
            incident.save()

            # Determine agent type based on predictions and keywords
            if ("network" in self.safe_lower(incident.title) or 
                "network" in self.safe_lower(incident.description) or 
                "network" in self.safe_lower(recommended_solution) or
                "network" in self.safe_lower(incident.pagent)):
                return 'network'
            elif ("security" in self.safe_lower(incident.title) or 
                "security" in self.safe_lower(incident.description) or 
                "security" in self.safe_lower(recommended_solution) or
                "security" in self.safe_lower(incident.pagent)):
                return 'security'
            elif ("hardware" in self.safe_lower(incident.title) or 
                "hardware" in self.safe_lower(incident.description) or 
                "hardware" in self.safe_lower(recommended_solution) or
                "hardware" in self.safe_lower(incident.pagent)):
                return 'hardware'
            else:
                return 'software'
        except Exception as e:
            print(f"Error in map_incident_to_agent: {str(e)}")
            return 'human'  # Default to human agent in case of errors

    def safe_lower(self, value):
        return value.lower() if value else ""

    def dispatch_incident(self, incident):
        try:
            """Dispatch the incident to the appropriate agent and log the action."""
            agent_type = self.map_incident_to_agent(incident)

            # Find or assign an agent
            assigned_agent = None
            if agent_type == 'human':
                assigned_agent = UserProfile.objects.filter(role='human_agent', is_active=True).first()
                if assigned_agent:
                    incident.assigned_agent = assigned_agent
                    incident.assigned_at = timezone.now()
                    incident.pagent = agent_type
                    incident.save()
            else:
                incident.assigned_agent = assigned_agent
                incident.assigned_at = timezone.now()
                incident.pagent = agent_type
                incident.save()

            # Log the assignment
            log_entry = IncidentLog.objects.create(
                incident=incident,
                assigned_agent=agent_type,
                assigned_at=timezone.now()
            )

            # Convert numpy values to Python native types
            confidence_score = float(incident.confidence_score) if incident.confidence_score is not None else None
            predicted_resolution_time = float(incident.predicted_resolution_time) if incident.predicted_resolution_time is not None else None

            # Prepare task data
            task_data = {
                'incident_id': incident.id,
                'title': incident.title,
                'description': incident.description or '',
                'severity': incident.severity.level if incident.severity else '',
                'agent_type': agent_type,
                'task_description': f"Resolve incident: {incident.title}",
                'log_id': log_entry.id,  # Use the actual log entry ID
                'human_intervention_needed': True if agent_type == 'human' else False,
                'assigned_agent_id': assigned_agent.id if assigned_agent else None,
                'confidence_score': confidence_score,
                'predicted_resolution_time': predicted_resolution_time
            }

            # Send task to RabbitMQ with proper JSON serialization
            self.channel.basic_publish(
                exchange='',
                routing_key='task_queue',
                body=json.dumps(task_data, default=str),  # Use default=str for JSON serialization
                properties=pika.BasicProperties(
                    delivery_mode=2,  # Make message persistent
                    content_type='application/json'
                )
            )
            print(f"Dispatched incident {incident.title} to {agent_type} agent (Confidence: {confidence_score})")
            print(f"Task data sent to queue: {task_data}")  # Debug log
            if not agent_type == 'human':
                self.agents[agent_type].process_task(task_data)
            return agent_type
        except Exception as e:
            print(f"Error in dispatch_incident: {str(e)}")
            return str(e)

    def process_task(self, task_data):
        """Process the task based on the agent type."""
        agent_type = task_data.get('agent_type')
        if agent_type in self.agents:
            agent = self.agents[agent_type]
            agent.process_task(task_data)
        else:
            print(f"No agent found for type: {agent_type}")

    def process_unresolved_incidents(self):
        """Fetch and dispatch unresolved incidents."""
        incidents = self.get_unresolved_incidents()
        for incident in incidents:
            self.dispatch_incident(incident)

    def on_message(self, ch, method, properties, body):
        """Process the message from RabbitMQ and log resolution details."""
        try:
            task_data = json.loads(body)
            print(f"Received task data: {task_data}")  # Debug log

            log_id = task_data.get('log_id')
            if log_id:
                try:
                    log_entry = IncidentLog.objects.get(id=log_id)
                    log_entry.resolved_at = timezone.now()
                    log_entry.save()
                    print(f"Updated log entry {log_id}")  # Debug log
                except IncidentLog.DoesNotExist:
                    print(f"Log entry {log_id} not found")
                except Exception as e:
                    print(f"Error updating log entry: {str(e)}")
            
            self.process_task(task_data)
            ch.basic_ack(delivery_tag=method.delivery_tag)
        except json.JSONDecodeError as e:
            print(f"Error decoding message: {str(e)}")
            ch.basic_ack(delivery_tag=method.delivery_tag)
        except Exception as e:
            print(f"Error processing message: {str(e)}")
            ch.basic_ack(delivery_tag=method.delivery_tag)

    def start_listening(self):
        """Start listening for tasks from RabbitMQ."""
        try:
            self.channel.basic_qos(prefetch_count=1)  # Process one message at a time
            self.channel.basic_consume(
                queue='task_queue',
                on_message_callback=self.on_message
            )
            print(' [*] Waiting for messages. To exit press CTRL+C')
            self.channel.start_consuming()
        except Exception as e:
            print(f"Error in start_listening: {str(e)}")

if __name__ == '__main__':
    try:
        orchestrator = OrchestrationLayer()
        orchestrator.process_unresolved_incidents()
        orchestrator.start_listening()
    except KeyboardInterrupt:
        print("Shutting down...")
    except Exception as e:
        print(f"Error in main: {str(e)}")