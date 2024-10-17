# tests.py
# Example unit tests for incident management

from django.test import TestCase
from incident_management.django_model.model import MSP, Client, Device, Incident

class IncidentTests(TestCase):
    def setUp(self):
        # Setup MSP, Client, Device, and Incident for testing
        msp = MSP.objects.create(name="Test MSP")
        client = Client.objects.create(name="Test Client", msp=msp)
        device = Device.objects.create(client=client, name="Test Device", device_type="Server")
        Incident.objects.create(title="Test Incident", description="Test incident description", device=device, severity=2)

    def test_incident_creation(self):
        incident = Incident.objects.get(title="Test Incident")
        self.assertEqual(incident.description, "Test incident description")

    def test_resolve_incident(self):
        incident = Incident.objects.get(title="Test Incident")
        incident.resolved = True
        incident.save()
        self.assertTrue(incident.resolved)