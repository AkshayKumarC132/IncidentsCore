import pika
import json
from core.management.django_model.model import IncidentLog
from django.utils import timezone
from django.core.mail import send_mail
from incidentmanagement import settings

class NetworkAgent:
    def __init__(self, queue_name='task_queue'):
        self.connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
        self.channel = self.connection.channel()
        self.queue_name = queue_name
        self.channel.queue_declare(queue=queue_name, durable=True)

    def callback(self, ch, method, properties, body):
        task_data = json.loads(body)
        print(f"Received task_data: {task_data}")

        if task_data['agent_type'] == 'network':
            self.process_task(task_data)
            ch.basic_ack(delivery_tag=method.delivery_tag)

    def process_task(self, task_data):
        print(f"Performing task: {task_data['task_description']} for incident {task_data['incident_id']}")

        # Severity handling
        severity = task_data.get('severity')
        if severity == "Critical":
            print(f"Critical network task detected! Prioritizing task for incident {task_data['incident_id']}")
        elif severity == "High":
            print(f"High priority network task for incident {task_data['incident_id']}")
        elif severity == "Medium":
            print(f"Medium priority network task for incident {task_data['incident_id']}")
        else:
            print(f"Low priority network task for incident {task_data['incident_id']}")

        resolution_message = ""
        resolved = False
        next_steps = "No further action required."

        # Network-specific task processing logic
        if "restart" in task_data['task_description'].lower():
            print(f"Restarting network device for incident {task_data['incident_id']}")
            resolution_message = "Network device restarted successfully."
            resolved = True
            next_steps = """
                1. Verify if the device is functioning correctly after restart.
                2. Check log files for any errors or issues during the restart process.
                3. Inform users about the device's availability post-restart.
                4. Schedule routine maintenance check for the device.
            """
        elif "connectivity" in task_data['task_description'].lower():
            print(f"Resolving connectivity issue for incident {task_data['incident_id']}")
            # Simulate a connectivity troubleshooting
            resolution_message = "Connectivity issue resolved successfully."
            resolved = True
            next_steps = """
                1. Monitor network performance to ensure stability.
                2. Communicate with affected users to confirm service restoration.
                3. Review network configurations to identify potential vulnerabilities.
                4. Update network documentation from the issue encountered.
            """
        elif "diagnostic" in task_data['task_description'].lower():
            print(f"Running network diagnostics for incident {task_data['incident_id']}")
            resolution_message = "Network diagnostics completed. No issues found."
            resolved = True
            next_steps = """
                1. Review the diagnostic report for any recommendations.
                2. Conduct periodic network scans to identify any emerging issues.
                3. Share findings with the IT team for further investigation, if necessary.
                4. Update the incident report with diagnostic results.
            """
        elif "configure" in task_data['task_description'].lower():
            print(f"Configuring network device for incident {task_data['incident_id']}")
            resolution_message = "Network device configured successfully."
            resolved = True
            next_steps = """
                1. Test the new configuration to ensure it meets operational requirements.
                2. Document the configuration changes made for future reference.
                3. Inform users about the changes and potential impacts.
                4. Schedule monitoring for the next 24 hours to ensure stability.
            """
        else:
            print(f"Performing general network maintenance for incident {task_data['incident_id']}")
            resolution_message = "General network maintenance performed."
            resolved = True
            next_steps = """
                1. Review all system logs for any anomalies during maintenance.
                2. Ensure firmware and software updates are applied to all devices.
                3. Schedule follow-up maintenance checks as necessary.
                4. Document maintenance activities and any issues encountered.
            """

        # Update log entry in the database
        log_id = task_data.get('log_id')
        if log_id:
            try:
                log_entry = IncidentLog.objects.get(id=log_id)
                log_entry.resolution_started_at = timezone.now()
                log_entry.resolution_message = resolution_message
                log_entry.resolved_at = timezone.now() if resolved else None
                log_entry.resolved = resolved
                log_entry.save()
                print("Log entry updated successfully")
            except IncidentLog.DoesNotExist:
                print(f"Log entry {log_id} not found")
            except Exception as e:
                print(f"Error updating log entry: {str(e)}")

        # **Send Email Notification**
        email_subject = f"Incident Resolution Update: {task_data.get('title', 'Network Incident')}"
        email_body = f"""
        Incident ID: {task_data['incident_id']}
        Title: {task_data.get('title', 'N/A')}
        Description: {task_data['task_description']}
        Severity: {severity}

        Resolution Attempted:
        {resolution_message}

        Next Steps:
        {next_steps}

        Incident Status: {'Resolved' if resolved else 'Pending Resolution'}
        """
        try:
            send_mail(
                subject=email_subject,
                message=email_body,
                from_email = settings.EMAIL_HOST_USER,
                recipient_list=["pakshay@stratapps.com","sudhir.nambiar@stratapps.com"],
                fail_silently=False,
            )
        except Exception as e:
            print(f"Error sending email notification: {str(e)}")

    def start_listening(self):
        print("Network Agent waiting for tasks...")
        self.channel.basic_qos(prefetch_count=1)
        self.channel.basic_consume(queue=self.queue_name, on_message_callback=self.callback)
        self.channel.start_consuming()

    def close_connection(self):
        self.connection.close()

# Example usage
if __name__ == '__main__':
    network_agent = NetworkAgent()
    try:
        network_agent.start_listening()
    except KeyboardInterrupt:
        network_agent.close_connection()