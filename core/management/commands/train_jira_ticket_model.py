# myapp/management/commands/train_jira_ticket_model.py

"""
Summary:
The `train_jira_ticket_model.py` script is a Django management command that trains a machine learning model for predicting the agent and confidence score for Jira tickets. It performs the following actions:

- Initialization: It imports necessary modules and defines a command class that extends `BaseCommand`.
- Data Retrieval: The command retrieves all Jira tickets from the database using the `JiraTicket` model.
- Data Validation: It checks each Jira ticket for missing data in the fields `predicted_agent` and `confidence_score`, printing warnings for any tickets that lack this information.
- Model Training: If there are valid Jira tickets available, it trains the machine learning model by invoking the `train()` method on an instance of `JiraTicketMLModel` and subsequently saves the trained model.
- Output Messages: The command provides feedback on its progress, indicating whether models were successfully saved or if no Jira tickets were available for training.

Overall, this command facilitates the training process of an ML model by ensuring data integrity and providing user feedback throughout the execution.
"""

from django.core.management.base import BaseCommand
from core.management.ml_model.JiraMLMode import JiraTicketMLModel  # Replace with actual ML model location
from core.models import JiraTicket

class Command(BaseCommand):
    help = 'Train the ML model for Jira ticket agent and confidence prediction'

    def handle(self, *args, **kwargs):
        ml_model = JiraTicketMLModel()

        # Load existing Jira tickets from the database
        tickets = JiraTicket.objects.all()

        for ticket in tickets:
            if ticket.predicted_agent is None or ticket.confidence_score is None:
                print(f"Missing data in Jira ticket {ticket.id}")

        if tickets.exists():
            # Train the models and save them
            ml_model.train()
            ml_model.save_model()

            print("Models saved successfully.")
        else:
            print("No Jira tickets available for training.")
