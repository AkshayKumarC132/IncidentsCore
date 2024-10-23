# # orchestration.py
# import pika
# import json
# class OrchestrationLayer:
#     def __init__(self, queue_name='task_queue'):
#         self.queue_name = queue_name
#         self.connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
#         self.channel = self.connection.channel()
#         self.channel.queue_declare(queue=queue_name, durable=True)

#     def send_task(self, task_data):
#         self.channel.basic_publish(
#             exchange='',
#             routing_key=self.queue_name,
#             body=json.dumps(task_data),
#             properties=pika.BasicProperties(
#                 delivery_mode=2,  # Make message persistent
#             )
#         )
#         print(f"Sent task: {task_data}")

#     def close_connection(self):
#         self.connection.close()

# # Example usage
# if __name__ == '__main__':
#     orchestrator = OrchestrationLayer()
#     task = {
#         'agent_type': 'network',
#         'incident_id': 123,
#         'task_description': 'Restart network device',
#     }
#     orchestrator.send_task(task)
#     orchestrator.close_connection()

import pika
import json
from core.agents.network_agent import NetworkAgent
from core.agents.security_agent import SecurityAgent
from core.agents.hardware_agent import HardwareAgent
from core.agents.software_agent import SoftwareAgent

class OrchestrationLayer:
    def __init__(self):
        # Initialize agents
        self.agents = {
            'network': NetworkAgent(),
            'security': SecurityAgent(),
            'hardware': HardwareAgent(),
            'software': SoftwareAgent()
        }
        self.connection = pika.BlockingConnection(pika.ConnectionParameters(host='localhost'))
        self.channel = self.connection.channel()
        self.channel.queue_declare(queue='task_queue', durable=True)
    
    def on_message(self, ch, method, properties, body):
        task_data = json.loads(body)
        agent_type = task_data.get('agent_type')
        if agent_type in self.agents:
            agent = self.agents[agent_type]
            agent.process_task(task_data)
        ch.basic_ack(delivery_tag=method.delivery_tag)

    def start_listening(self):
        self.channel.basic_consume(queue='task_queue', on_message_callback=self.on_message)
        print(' [*] Waiting for messages. To exit press CTRL+C')
        self.channel.start_consuming()

# To start the orchestration
if __name__ == '__main__':
    orchestrator = OrchestrationLayer()
    orchestrator.start_listening()
