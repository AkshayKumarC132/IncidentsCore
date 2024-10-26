import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

class HumanAgent:
    def __init__(self):
        self.email_host = 'smtp.gmail.com'
        self.email_port = 587
        self.email_user = 'your_email@example.com'
        self.email_password = 'your_password'

    def send_email_notification(self, incident_details):
        """Send an email notification for human intervention."""
        msg = MIMEMultipart()
        msg['From'] = self.email_user
        msg['To'] = 'support_team@example.com'
        msg['Subject'] = f"Human Intervention Needed for Incident {incident_details['incident_id']}"

        body = f"""\
        Incident ID: {incident_details['incident_id']}
        Title: {incident_details['title']}
        Description: {incident_details['description']}
        Severity: {incident_details['severity']}
        Task: {incident_details['task_description']}
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
        self.send_email_notification(task_data)