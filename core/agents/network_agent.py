# Network Agent.py (for a Network Agent example)

import pika
import json
from core.management.django_model.model import IncidentLog
from django.utils import timezone


class NetworkAgent:
    def __init__(self, queue_name='task_queue'):
        self.connection = pika.BlockingConnection(
            pika.ConnectionParameters('localhost'))
        self.channel = self.connection.channel()
        self.queue_name = queue_name
        self.channel.queue_declare(queue=queue_name, durable=True)

    def callback(self, ch, method, properties, body):
        task_data = json.loads(body)
        print(f"Received task_data: {task_data}")

        if task_data['agent_type'] == 'network':
            self.process_task(task_data)
            ch.basic_ack(delivery_tag=method.delivery_tag)

    def process_task(self, task_data):

        print(
            f"Performing task: {task_data['task_description']} for incident {task_data['incident_id']}")

        # Severity handling
        severity = task_data.get('severity')

        if severity == "Critical":
            print(
                f"Critical network task detected! Prioritizing task for incident {task_data['incident_id']}")
            # Handle critical tasks differently if needed
        elif severity == "High":
            print(
                f"High priority network task for incident {task_data['incident_id']}")
        elif severity == "Medium":
            print(
                f"Medium priority network task for incident {task_data['incident_id']}")
        else:
            print(
                f"Low priority network task for incident {task_data['incident_id']}")

        # Network-specific task processing logic
        if "restart" in task_data['task_description'].lower():
            print(
                f"Restarting network device for incident {task_data['incident_id']}")
            # Simulate restarting a network device
        elif "connectivity" in task_data['task_description'].lower():
            print(
                f"Resolving connectivity issue for incident {task_data['incident_id']}")
            # Simulate resolving a network connectivity issue
        else:
            print(
                f"Performing general network maintenance for incident {task_data['incident_id']}")

        log_id = task_data.get('log_id')
        log_entry = IncidentLog.objects.get(id=log_id)
        log_entry.resolution_started_at = timezone.now()
        log_entry.save()

    def start_listening(self):
        print("Network Agent waiting for tasks...")
        self.channel.basic_qos(prefetch_count=1)
        self.channel.basic_consume(
            queue=self.queue_name, on_message_callback=self.callback)
        self.channel.start_consuming()

    def close_connection(self):
        self.connection.close()


# Example usage
if __name__ == '__main__':
    network_agent = NetworkAgent()
    try:
        network_agent.start_listening()
    except KeyboardInterrupt:
        network_agent.close_connection()
