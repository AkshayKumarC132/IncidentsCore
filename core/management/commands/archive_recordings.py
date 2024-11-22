
from django.core.management.base import BaseCommand
from core.models import ScreenRecording
from django.utils import timezone

class Command(BaseCommand):
    help = "Archive screen recordings older than 90 days"

    def handle(self, *args, **kwargs):
        recordings = ScreenRecording.objects.filter(archived_at__isnull=True)
        for recording in recordings:
            if recording.is_archivable():
                recording.archived_at = timezone.now()
                recording.save()
                print(f"Archived: {recording.file_path}")
        print("Archiving task completed.")


# python manage.py archive_recordings