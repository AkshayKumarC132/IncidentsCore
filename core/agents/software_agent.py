# software_agent.py

import pika
import json
from core.management.django_model.model import IncidentLog
from django.utils import timezone


class SoftwareAgent:
    def _init_(self, queue_name='task_queue'):
        self.connection = pika.BlockingConnection(
            pika.ConnectionParameters('localhost'))
        self.channel = self.connection.channel()
        self.queue_name = queue_name
        self.channel.queue_declare(queue=queue_name, durable=True)

    def callback(self, ch, method, properties, body):
        task_data = json.loads(body)
        print(f"Received task_data: {task_data}")

        if task_data['agent_type'] == 'software':
            if 'task_description' in task_data:
                print(f"Software agent processing task: {task_data}")
                self.process_task(task_data)
            else:
                print("Error: 'task_description' not found in task_data")
            ch.basic_ack(delivery_tag=method.delivery_tag)

    def process_task(self, task_data):
        print(
            f"Performing task: {task_data['task_description']} for incident {task_data['incident_id']}")

        # Severity handling
        severity = task_data.get('severity')

        if severity == "Critical":
            print(
                f"Critical task detected! Prioritizing task for incident {task_data['incident_id']}")
            # Handle critical tasks differently, if needed
        elif severity == "High":
            print(
                f"High priority task for incident {task_data['incident_id']}")
        elif severity == "Medium":
            print(
                f"Medium priority task for incident {task_data['incident_id']}")
        else:
            print(f"Low priority task for incident {task_data['incident_id']}")

        # Software-specific task processing logic (based on description or title)
        if "install" in task_data['task_description'].lower():
            print(
                f"Installing software for incident {task_data['incident_id']}")
        elif "troubleshoot" in task_data['task_description'].lower():
            print(
                f"Troubleshooting software for incident {task_data['incident_id']}")
        else:
            print(
                f"Performing general software maintenance for incident {task_data['incident_id']}")
        print("----------Software---------",task_data)
        log_id = task_data.get('log_id')
        print(log_id)
        log_entry = IncidentLog.objects.get(id=log_id)
        print(log_entry)
        print(timezone.now())
        log_entry.resolution_started_at = timezone.now()
        log_entry.save()
        print("Success")

    def start_listening(self):
        print("Software Agent waiting for tasks...")
        self.channel.basic_qos(prefetch_count=1)
        self.channel.basic_consume(
            queue=self.queue_name, on_message_callback=self.callback)
        self.channel.start_consuming()

    def close_connection(self):
        self.connection.close()


# Example usage
if __name__ == '__main__':
    software_agent = SoftwareAgent()
    try:
        software_agent.start_listening()
    except KeyboardInterrupt:
        software_agent.close_connection()
