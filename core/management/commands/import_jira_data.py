import pandas as pd
from django.core.management.base import BaseCommand
from django.db import transaction
from core.models import UserProfile, JiraTicket, Incident, Severity, IntegrationType, IntegrationMSPConfig, Client, Device

class Command(BaseCommand):
    help = "Import Jira tickets and incidents from a CSV file."

    def add_arguments(self, parser):
        parser.add_argument(
            'file_path', type=str, help="Path to the CSV file containing Jira ticket data."
        )
        parser.add_argument(
            '--user_id', type=int, help="ID of the user to associate the Jira tickets with."
        )

    def handle(self, *args, **kwargs):
        file_path = kwargs['file_path']
        user_id = kwargs['user_id']

        try:
            # Load the CSV file
            data = pd.read_csv(file_path)

            # Get the user instance
            user = UserProfile.objects.get(id=user_id)

            # Define severity mapping
            severity_mapping = {
                'Critical': 1,  # Severity Level ID in your database
                'High': 2,
                'Medium': 3,
                'Low': 4
            }

            # Process and save data
            self.process_csv_and_save_to_db(data, user, severity_mapping)
            self.stdout.write(self.style.SUCCESS("Data imported successfully."))
        except UserProfile.DoesNotExist:
            self.stderr.write(self.style.ERROR(f"User with ID {user_id} does not exist."))
        except FileNotFoundError:
            self.stderr.write(self.style.ERROR(f"File at path '{file_path}' not found."))
        except Exception as e:
            self.stderr.write(self.style.ERROR(f"Error occurred: {e}"))

    def process_csv_and_save_to_db(self, data, user, severity_mapping):
        for _, row in data.iterrows():
            try:
                issue_key = row['issue_key']
                summary = row['summary']
                predicted_agent = row['predicted_agent']
                description = row.get('description', '')
                # created_at = row['created_at']
                priority_name = row['priority']  # 'High', 'Low', etc.
                severity_level_id = severity_mapping.get(priority_name, 3)  # Default to Medium if not found
                severity = Severity.objects.get(id=severity_level_id)

                # Ensure the issue_key is unique per user
                if JiraTicket.objects.filter(user=user, issue_key=issue_key).exists():
                    jira_ticket = JiraTicket.objects.get(user=user, issue_key=issue_key)
                    jira_ticket.project = row.get('jira_project_name', 'Default Project')
                    jira_ticket.summary = summary
                    jira_ticket.description = description or ""
                    jira_ticket.status = row['status']
                    jira_ticket.priority = priority_name
                    jira_ticket.predicted_agent = predicted_agent
                    jira_ticket.save()

                    #     issue_key=issue_key,
                    #     project=row.get('jira_project_name', 'Default Project'),
                    #     summary=summary,
                    #     description=description or "",
                    #     # created_at=created_at,
                    #     status=row['status'],
                    #     priority=priority_name,
                    #     predicted_agent = predicted_agent,
                    #     user=user
                    # )
                    continue  # Skip saving if ticket already exists for this user

                with transaction.atomic():  # Ensure atomicity
                    # Create the JiraTicket object
                    jira_ticket = JiraTicket.objects.create(
                        issue_key=issue_key,
                        project=row.get('jira_project_name', 'Default Project'),
                        summary=summary,
                        description=description or "",
                        # created_at=created_at,
                        status=row['status'],
                        priority=priority_name,
                        predicted_agent = predicted_agent,
                        user=user
                    )

                    # Fetch or create required related objects
                    integration_type, _ = IntegrationType.objects.update_or_create(name='Jira')
                    msp_instance, _ = IntegrationMSPConfig.objects.get_or_create(user=user, type=integration_type)
                    client, _ = Client.objects.get_or_create(msp=msp_instance)
                    device, _ = Device.objects.get_or_create(client=client, name="Default Device", device_type="Unknown")

                    # Create Incident
                    Incident.objects.create(
                        title=summary,
                        description=description or "",
                        device=device,
                        severity=severity,
                        jira_ticket=jira_ticket,
                        resolved=False,
                        # created_at=created_at,
                        assigned_at=None,
                    )
            except Exception as e:
                self.stderr.write(self.style.ERROR(f"Error processing row with issue_key '{issue_key}': {e}"))

# User 7 is : Akshay(paksay@stratapps.com)
# python manage.py import_jira_data synthetic_jira_tickets.csv --user_id 7
