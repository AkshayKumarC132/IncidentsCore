from django.core.management.base import BaseCommand
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent.parent.parent))
from ml.jira_classifier import validate_classifier

class Command(BaseCommand):
    help = "Validate the Jira classifier"

    def handle(self, *args, **kwargs):
        validate_classifier()
