from django.core.management.base import BaseCommand
from core.models import Incident  # Use the actual app name
from core.management.ml_model.MLModel import IncidentMLModel  # Replace with actual ML model location

class Command(BaseCommand):
    help = 'Process incident predictions'

    def handle(self, *args, **kwargs):
        process_incident_predictions()

def process_incident_predictions():
    # Fetch incidents one by one in a loop
    for incident in Incident.objects.filter(device__in=[86, 87, 88, 89]):
        # Prepare incident data for predictions
        incident_data = {
            'title': incident.title,
            'description': incident.description,
            'device_id': incident.device.id if incident.device else None,
            'severity_id': incident.severity.id if incident.severity else None,
        }

        # Initialize the ML model
        ml_model = IncidentMLModel()

        # Make predictions using the trained model
        try:
            if ml_model.time_model and ml_model.solution_model:  # Ensure models are trained
                predicted_time = ml_model.predict_time(incident_data)
                predicted_desc = ml_model.predict_solution(incident_data)
            else:
                predicted_time = 1.0  # Default resolution time if model is not trained
                predicted_desc = "No prediction available"

            # Log the predictions
            print(f"Predicted Resolution Time: {predicted_time} hours")
            print(f"Predicted Description: {predicted_desc}")

        except Exception as e:
            predicted_time = 1.0  # Default on error
            predicted_desc = "Prediction error occurred"

        # Update incident with predictions
        incident.predicted_resolution_time = predicted_time
        incident.recommended_solution = predicted_desc
        incident.save()

        print(f"Incident {incident.id} updated with predictions.")
