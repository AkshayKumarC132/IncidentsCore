import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from core.management.django_model.model import IncidentLog
from django.utils import timezone
from incidentmanagement import settings


class HumanAgent:
    def __init__(self):
        self.email_host = 'smtp.gmail.com'
        self.email_port = 587
        self.email_user = settings.EMAIL_HOST_USER
        self.email_password = settings.EMAIL_HOST_PASSWORD

    def send_email_notification(self, incident_details):
        """Send an email notification for human intervention."""
        msg = MIMEMultipart()
        msg['From'] = self.email_user
        msg['To'] = settings.EMAIL_HOST_USER
        msg['Subject'] = f"Human Intervention Needed for Incident {incident_details['incident_id']}"

        body = f"""\
        Incident ID: {incident_details['incident_id']}
        Title: {incident_details['title']}
        Description: {incident_details['description']}
        Severity: {incident_details['severity']}
        Task: {incident_details['task_description']}

        Next Steps:
        1. Review the incident details above.
        2. Assess the situation and decide on the appropriate intervention.
        3. Take necessary actions as per the established protocols.
        4. Update the incident log with actions taken and resolution status.
        """

        msg.attach(MIMEText(body, 'plain'))
        with smtplib.SMTP(self.email_host, self.email_port) as server:
            server.starttls()
            server.login(self.email_user, self.email_password)
            server.send_message(msg)
        print("Notification sent for human intervention.")

    def process_task(self, task_data):
        """Process tasks that need human intervention."""
        print(f"Processing task for human intervention: {task_data}")
        try:
            self.send_email_notification(task_data)
            log_id = task_data.get('log_id')
            log_entry = IncidentLog.objects.get(id=log_id)
            log_entry.resolution_started_at = timezone.now()
            log_entry.save()
        except:
            pass
