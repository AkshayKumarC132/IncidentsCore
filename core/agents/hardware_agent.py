import pika
import json

class HardwareAgent:
    def __init__(self, queue_name='task_queue'):
        self.connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
        self.channel = self.connection.channel()
        self.queue_name = queue_name
        self.channel.queue_declare(queue=queue_name, durable=True)

    def callback(self, ch, method, properties, body):
        task_data = json.loads(body)
        print(f"Received task_data: {task_data}")
        
        if task_data['agent_type'] == 'hardware':
            self.process_task(task_data)
            ch.basic_ack(delivery_tag=method.delivery_tag)

    def process_task(self, task_data):
        print(f"Performing task: {task_data['task_description']} for incident {task_data['incident_id']}")
        
        # Severity handling
        severity = task_data.get('severity')
        
        if severity == "Critical":
            print(f"Critical hardware task detected! Prioritizing task for incident {task_data['incident_id']}")
            # Handle critical tasks differently if needed
        elif severity == "High":
            print(f"High priority hardware task for incident {task_data['incident_id']}")
        elif severity == "Medium":
            print(f"Medium priority hardware task for incident {task_data['incident_id']}")
        else:
            print(f"Low priority hardware task for incident {task_data['incident_id']}")
        
        # Hardware-specific task processing logic
        if "replace" in task_data['task_description'].lower():
            print(f"Replacing hardware for incident {task_data['incident_id']}")
            # Simulate hardware replacement
        elif "repair" in task_data['task_description'].lower():
            print(f"Repairing hardware for incident {task_data['incident_id']}")
            # Simulate hardware repair
        else:
            print(f"Performing general hardware maintenance for incident {task_data['incident_id']}")

    def start_listening(self):
        print("Hardware Agent waiting for tasks...")
        self.channel.basic_qos(prefetch_count=1)
        self.channel.basic_consume(queue=self.queue_name, on_message_callback=self.callback)
        self.channel.start_consuming()

    def close_connection(self):
        self.connection.close()

# Example usage
if __name__ == '__main__':
    hardware_agent = HardwareAgent()
    try:
        hardware_agent.start_listening()
    except KeyboardInterrupt:
        hardware_agent.close_connection()
