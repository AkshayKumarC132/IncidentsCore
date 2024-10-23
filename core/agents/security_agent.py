# security_agent.py

import pika
import json

class SecurityAgent:
    def __init__(self, queue_name='task_queue'):
        self.connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
        self.channel = self.connection.channel()
        self.queue_name = queue_name
        self.channel.queue_declare(queue=queue_name, durable=True)

    def callback(self, ch, method, properties, body):
        task_data = json.loads(body)
        if task_data['agent_type'] == 'security':
            print(f"Security agent processing task: {task_data}")
            self.process_task(task_data)
            ch.basic_ack(delivery_tag=method.delivery_tag)

    def process_task(self, task_data):
        print(f"Performing task: {task_data['task_description']} for incident {task_data['incident_id']}")
        # Implement security-specific task processing logic here

    def start_listening(self):
        print("Security Agent waiting for tasks...")
        self.channel.basic_qos(prefetch_count=1)
        self.channel.basic_consume(queue=self.queue_name, on_message_callback=self.callback)
        self.channel.start_consuming()

    def close_connection(self):
        self.connection.close()

# Example usage
if __name__ == '__main__':
    security_agent = SecurityAgent()
    try:
        security_agent.start_listening()
    except KeyboardInterrupt:
        security_agent.close_connection()
