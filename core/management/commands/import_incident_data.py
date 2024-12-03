import os
import csv
from django.core.management.base import BaseCommand
from core.management.django_model.model import Incident, Device, Severity, UserProfile,Client


class Command(BaseCommand):
    help = "Import incidents from a CSV file into the Incident table."

    def add_arguments(self, parser):
        parser.add_argument(
            'file_path', type=str, help='The path to the CSV file to import.'
        )

    def handle(self, *args, **kwargs):
        file_path = kwargs['file_path']

        # Check if the file exists
        if not os.path.exists(file_path):
            self.stdout.write(self.style.ERROR(f"File '{file_path}' does not exist."))
            return

        try:
            # Open and read the CSV file
            with open(file_path, mode='r', encoding='utf-8') as file:
                csv_reader = csv.DictReader(file)

                for row in csv_reader:
                    try:
                        # Extract data from the row
                        title = row.get('title')
                        description = row.get('description')
                        severity_id = row.get('severity')
                        # assigned_agent_username = row.get('assigned_agent')
                        device_name = row.get('device')

                        # Resolve related fields
                        # Handle device and client relationship
                        client = Client.objects.get(id=26)  # Use a default client (adjust as needed)
                        if not client:
                            self.stdout.write(self.style.ERROR("No default Client found. Please add a Client."))
                            continue

                        device, _ = Device.objects.get_or_create(name=device_name, client=client)

                        severity = Severity.objects.get(id=severity_id)
                        # assigned_agent = UserProfile.objects.filter(username=assigned_agent_username).first()

                        # Create Incident object
                        incident = Incident.objects.create(
                            title=title,
                            description=description,
                            device=device,
                            severity=severity,
                            # assigned_agent=assigned_agent,
                        )

                        self.stdout.write(self.style.SUCCESS(f"Incident '{incident.title}' imported successfully."))

                    except Exception as e:
                        self.stdout.write(self.style.ERROR(f"Error importing row {row}: {e}"))

            self.stdout.write(self.style.SUCCESS("Import process completed!"))

        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Failed to process the file: {e}"))
