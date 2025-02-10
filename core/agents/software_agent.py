import pika
import json
from core.management.django_model.model import IncidentLog
from django.utils import timezone
import subprocess
from django.core.mail import send_mail
import platform
import os
from incidentmanagement import settings

class SoftwareAgent:
    def __init__(self, queue_name='task_queue'):
        self.connection = pika.BlockingConnection(
            pika.ConnectionParameters('localhost'))
        self.channel = self.connection.channel()
        self.queue_name = queue_name
        self.channel.queue_declare(queue=queue_name, durable=True)

    def get_software_manager(self):
        if platform.system() != 'Windows':
            return subprocess.run(["apt-get", "update"], capture_output=True)
        return subprocess.run(["powershell", "Get-Package"], capture_output=True)

    def install_software(self, package_name):
        if platform.system() != 'Windows':
            try:
                subprocess.run(["apt-get", "install", package_name, "-y"], check=True)
                return True
            except subprocess.CalledProcessError:
                return False
        return False

    def update_software(self):
        if platform.system() != 'Windows':
            try:
                subprocess.run(["apt-get", "update"], check=True)
                return True
            except subprocess.CalledProcessError:
                return False
        raise NotImplementedError("Software update is not supported on Windows")

    def process_task(self, task_data):
        print(f"Processing task: {task_data['task_description']} for incident {task_data['incident_id']}")

        incident_id = task_data['incident_id']
        severity = task_data.get('severity', 'Low')
        description = task_data['task_description'].lower()
        
        resolution_message = ""
        resolved = False
        next_steps = "No further action required."

        if "install" in description or "setup" in description:
            package_name = "some-software"
            if self.install_software(package_name):
                resolution_message = f"Software {package_name} installed successfully."
                resolved = True
            else:
                resolution_message = f"Failed to install software {package_name}. Possible reasons: network issues, insufficient permissions, or incompatible system."
                next_steps = "Ensure network connectivity, verify permissions, and check system compatibility. Attempt manual installation following the official documentation."

        elif "update" in description or "patch" in description:
            if self.update_software():
                resolution_message = "System updated successfully."
                resolved = True
            else:
                resolution_message = "Update failed. Possible causes: outdated repositories, network issues, or insufficient permissions."
                next_steps = "Verify repository sources, ensure network access, and check permissions. Retry the update or consult the system administrator."

        elif "reset password" in description:
            resolution_message = "Password reset link has been sent to the user."
            resolved = True
            next_steps = "User should follow the reset link in their email and create a new password as per the guidelines provided."

        elif "troubleshoot" in description:
            resolution_message = "Diagnostic script executed, logs analyzed for errors and warnings."
            resolved = True
            next_steps = "Review the diagnostic logs for issues. Consult the troubleshooting guide for further analysis and resolution steps."

        else:
            resolution_message = "Manual intervention required."
            next_steps = "Assign this incident to an engineer for manual resolution. Provide all relevant details and logs for efficient troubleshooting."

        # **Updating Incident in Database**
        log_id = task_data.get('log_id')
        if log_id:
            try:
                log_entry = IncidentLog.objects.get(id=log_id)
                log_entry.resolution_started_at = timezone.now()
                log_entry.resolution_message = resolution_message
                log_entry.resolved_at = timezone.now() if resolved else None
                log_entry.resolved = resolved
                log_entry.save()
                print("Incident log updated successfully.")
            except IncidentLog.DoesNotExist:
                print(f"Log entry {log_id} not found.")

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
                from_email = settings.EMAIL_HOST_USER,
                recipient_list=["pakshay@stratapps.com","sudhir.nambiar@stratapps.com"],
                fail_silently=False,
            )
        except Exception as e:
            print(f"Error sending email notification: {str(e)}")
            raise

        print(f"Email notification sent for Incident ID {incident_id}.")

    def start_listening(self):
        print("Software Agent waiting for tasks...")
        self.channel.basic_qos(prefetch_count=1)
        self.channel.basic_consume(
            queue=self.queue_name, on_message_callback=self.callback)
        self.channel.start_consuming()

    def close_connection(self):
        self.connection.close()

    def callback(self, ch, method, properties, body):
        try:
            task_data = json.loads(body)
            print(f"Received task_data: {task_data}")

            if task_data['agent_type'] == 'software':
                if 'task_description' in task_data:
                    print(f"Software agent processing task: {task_data}")
                    self.process_task(task_data)
                else:
                    print("Error: 'task_description' not found in task_data")
                ch.basic_ack(delivery_tag=method.delivery_tag)
            else:
                print(f"Error: 'agent_type' mismatch. Expected 'software', got {task_data['agent_type']}")
                ch.basic_reject(delivery_tag=method.delivery_tag, requeue=False)
        except Exception as e:
            print(f"Error processing task: {str(e)}")
            ch.basic_reject(delivery_tag=method.delivery_tag, requeue=False)

# Example usage
if __name__ == '__main__':
    software_agent = SoftwareAgent()
    try:
        software_agent.start_listening()
    except KeyboardInterrupt:
        software_agent.close_connection()