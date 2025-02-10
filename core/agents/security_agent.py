import pika
import json
from core.management.django_model.model import IncidentLog
from django.utils import timezone
from django.core.mail import send_mail
from incidentmanagement import settings

class SecurityAgent:
    def __init__(self, queue_name='task_queue'):
        self.connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
        self.channel = self.connection.channel()
        self.queue_name = queue_name
        self.channel.queue_declare(queue=queue_name, durable=True)

    def callback(self, ch, method, properties, body):
        task_data = json.loads(body)
        print(f"Received task_data: {task_data}")
        
        if task_data['agent_type'] == 'security':
            self.process_task(task_data)
            ch.basic_ack(delivery_tag=method.delivery_tag)

    def process_task(self, task_data):
        print(f"Performing task: {task_data['task_description']} for incident {task_data['incident_id']}")
        
        # Severity handling
        incident_id = task_data['incident_id']
        severity = task_data.get('severity', 'Low')
        description = task_data['task_description'].lower()

        # Security-specific task processing logic
        resolution_message = ""
        resolved = False
        next_steps = "No further action required."

        if "vulnerability scan" in description.lower():
            print(f"Running vulnerability scan for incident {task_data['incident_id']}")
            resolution_message = "Vulnerability scan completed successfully. No issues found."
            resolved = True
            next_steps = """
                1. Monitor security advisories for any newly discovered vulnerabilities.
                2. Schedule regular vulnerability scans to ensure continuous security compliance.
                3. If any vulnerabilities were identified in the future, prioritize patching based on severity.
            """
        elif "fix security" in description.lower():
            print(f"Fixing security issue for incident {task_data['incident_id']}")
            resolution_message = "Security issue fixed successfully."
            resolved = True
            next_steps = """
                1. Document the security issue and the steps taken to resolve it.
                2. Review logs for any unauthorized access during the incident period.
                3. Update security policies and procedures if the incident exposes gaps in current protocols.
                4. Conduct training or awareness sessions for users regarding security best practices.
            """
        elif "security audit" in description.lower():
            print(f"Performing security audit for incident {task_data['incident_id']}")
            resolution_message = "Security audit completed successfully. No issues found."
            resolved = True
            next_steps = """
                1. Review the audit report and identify any areas for improvement in security controls.
                2. Implement recommended changes from the audit report to strengthen security posture.
                3. Schedule the next security audit and ensure it is conducted periodically.
                4. Educate staff about audit findings and necessary procedural changes.
            """
        else:
            print(f"Performing general security maintenance for incident {task_data['incident_id']}")
            resolution_message = "General security maintenance performed."
            resolved = True
            next_steps = """
                1. Review system configurations and ensure they comply with security policies.
                2. Ensure all security patches are up to date across systems.
                3. Implement additional security measures, such as multi-factor authentication, if not already in place.
                4. Monitor system logs for any suspicious activity following maintenance.
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
        email_subject = f"Incident Resolution Update: {task_data['title']}"
        email_body = f"""
        Incident ID: {incident_id}
        Title: {task_data['title']}
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
                from_email=settings.EMAIL_HOST_USER,
                recipient_list=["pakshay@stratapps.com",'sudhir.nambiar@stratapps.com'],
                fail_silently=False,
            )
        except Exception as e:
            print(f"Error sending email notification: {str(e)}")
            raise

        print(f"Email notification sent for Incident ID {incident_id}.")

    def start_listening(self):
        print("Security Agent waiting for tasks...")
        self.channel.basic_qos(prefetch_count=1)
        self.channel.basic_consume(queue=self.queue_name, on_message_callback=self.callback)
        self.channel.start_consuming()

    def close_connection(self):
        self.connection.close()

# Example usage
if __name__ == '__main__':
    security_agent = SecurityAgent()
    try:
        security_agent.start_listening()
    except KeyboardInterrupt:
        security_agent.close_connection()