from django.core.management.base import BaseCommand
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent.parent.parent))
from ml.jira_classifier import train_classifier

# from core.ml.jira_classifier import train_classifier

class Command(BaseCommand):
    help = "Train the Jira classifier"

    def handle(self, *args, **kwargs):
        train_classifier()
