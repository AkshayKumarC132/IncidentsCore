from django.core.management.base import BaseCommand
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent.parent.parent))
from ml.jira_classifier import update_predictions

class Command(BaseCommand):
    help = "Update predictions in JiraTicket table"

    def handle(self, *args, **kwargs):
        update_predictions()
