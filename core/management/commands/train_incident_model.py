# myapp/management/commands/train_incident_model.py

"""
Summary:
The `train_incident_model.py` script is a Django management command that trains a machine learning model for incident recommendations. It performs the following actions:

- Initialization: It imports necessary modules and defines a command class that extends `BaseCommand`.
- Data Retrieval: The command retrieves all incidents from the database using the `Incident` model.
- Data Validation: It checks each incident for missing data in the fields `recommended_solution` and `predicted_resolution_time`, printing warnings for any incidents that lack this information.
- Model Training: If there are valid incidents available, it trains the machine learning model by invoking the `train()` method on an instance of `IncidentMLModel` and subsequently saves the trained model.
- Output Messages: The command provides feedback on its progress, indicating whether models were successfully saved or if no incidents were available for training.

Overall, this command facilitates the training process of an ML model by ensuring data integrity and providing user feedback throughout the execution.
"""

from django.core.management.base import BaseCommand
from core.management.ml_model.MLModel import IncidentMLModel  # Replace with actual ML model location
from django.core.management.base import BaseCommand
from core.models import *

class Command(BaseCommand):
    help = 'Train the ML model for incident recommendations'

    def handle(self, *args, **kwargs):
        ml_model = IncidentMLModel()

        # Load existing incidents from the database
        incidents = Incident.objects.all()
        for incident in incidents:
            if incident.recommended_solution is None or incident.predicted_resolution_time is None:
                print(f"Missing data in incident {incident.id}")

        if incidents.exists():
            incidents = Incident.objects.all()

            # Train the models and save them
            ml_model.train()
            ml_model.save_model()

            print("Models saved successfully.")
        else:
            print("No incidents available for training.")
# python manage.py train_incident_model