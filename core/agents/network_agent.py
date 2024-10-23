# Network Agent.py (for a Network Agent example)

import pika
import json

class NetworkAgent:
    def __init__(self, queue_name='task_queue'):
        self.connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
        self.channel = self.connection.channel()
        self.queue_name = queue_name
        self.channel.queue_declare(queue=queue_name, durable=True)

    def callback(self, ch, method, properties, body):
        task_data = json.loads(body)
        if task_data['agent_type'] == 'network':
            print(f"Network agent processing task: {task_data}")
            # Perform task (e.g., restart network device)
            self.process_task(task_data)
            ch.basic_ack(delivery_tag=method.delivery_tag)
            
    def process_task(self, task_data):
        print(f"Performing task: {task_data['task_description']} for incident {task_data['incident_id']}")

    def start_listening(self):
        print("Network Agent waiting for tasks...")
        self.channel.basic_qos(prefetch_count=1)
        self.channel.basic_consume(queue=self.queue_name, on_message_callback=self.callback)
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