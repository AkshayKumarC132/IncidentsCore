import pika
import json
from core.management.django_model.model import IncidentLog
from django.utils import timezone
from django.core.mail import send_mail
from incidentmanagement import settings

class HardwareAgent:
    def __init__(self, queue_name='task_queue'):
        self.connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
        self.channel = self.connection.channel()
        self.queue_name = queue_name
        self.channel.queue_declare(queue=queue_name, durable=True)

    def callback(self, ch, method, properties, body):
        task_data = json.loads(body)
        print(f"Received task_data: {task_data}")
        
        if task_data['agent_type'] == 'hardware':
            self.process_task(task_data)
            ch.basic_ack(delivery_tag=method.delivery_tag)

    def process_task(self, task_data):
        print(f"Performing task: {task_data['task_description']} for incident {task_data['incident_id']}")
        
        # Severity handling
        severity = task_data.get('severity')
        
        if severity in ["Critical", "High", "Medium", "Low"]:
            print(f"{severity} hardware task detected for incident {task_data['incident_id']}")
        
        resolution_message = ""
        resolved = False
        next_steps = "No further action required."
        
        # Hardware-specific task processing logic
        if "replace" in task_data['task_description'].lower():
            print(f"Replacing hardware for incident {task_data['incident_id']}")
            resolution_message = "Hardware replacement completed successfully."
            resolved = True
            next_steps = """
                1. Verify the new hardware is functioning correctly.
                2. Dispose of the old hardware according to company policies.
                3. Monitor the affected systems for any anomalies for 48 hours.
                4. Update inventory records to reflect the hardware change.
            """

        elif "repair" in task_data['task_description'].lower():
            print(f"Repairing hardware for incident {task_data['incident_id']}")
            resolution_message = "Hardware repair completed successfully."
            resolved = True
            next_steps = """
                1. Test the repaired hardware to ensure it meets operational standards.
                2. Document the repair process and any parts replaced.
                3. Communicate with users about the repair status.
                4. Schedule a follow-up check to monitor the repaired hardware.
            """
            
        elif "install" in task_data['task_description'].lower() or "install" in task_data['title'].lower():
            print(f"Installing hardware for incident {task_data['incident_id']}")
            resolution_message = "Hardware installation completed successfully."
            resolved = True
            next_steps = """
                1. Validate the installation by running necessary tests.
                2. Inform users of the new hardware capabilities and any changes in procedure.
                3. Update system documentation to include the new hardware.
                4. Monitor the system performance to ensure stability post-installation.
            """
            
        elif "diagnose" in task_data['task_description'].lower():
            print(f"Running hardware diagnostics for incident {task_data['incident_id']}")
            resolution_message = "Hardware diagnostics completed. No issues found."
            resolved = True
            next_steps = """
                1. Review diagnostic reports for recommendations or potential concerns.
                2. Schedule periodic diagnostics to preemptively catch potential issues.
                3. Maintain logs of diagnostic results for future reference.
                4. Share findings with the relevant team members.
            """
            
        else:
            print(f"Performing general hardware maintenance for incident {task_data['incident_id']}")
            resolution_message = "General hardware maintenance performed."
            resolved = True
            next_steps = """
                1. Review all hardware logs for any unusual activity.
                2. Ensure firmware is up to date across all hardware components.
                3. Document any maintenance activities performed.
                4. Establish a schedule for regular hardware maintenance checks.
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
        email_subject = f"Incident Resolution Update: {task_data.get('title', 'Hardware Incident')}"
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
        print("Hardware Agent waiting for tasks...")
        self.channel.basic_qos(prefetch_count=1)
        self.channel.basic_consume(queue=self.queue_name, on_message_callback=self.callback)
        self.channel.start_consuming()

    def close_connection(self):
        self.connection.close()

# Example usage
if __name__ == '__main__':
    hardware_agent = HardwareAgent()
    try:
        hardware_agent.start_listening()
    except KeyboardInterrupt:
        hardware_agent.close_connection()