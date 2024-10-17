# OrchestrationLayer.py
# Example orchestration layer for coordinating agents

class OrchestrationLayer:
    def _init_(self, agents):
        self.agents = agents

    def dispatch_incident(self, incident):
        for agent in self.agents:
            result = agent.handle()
            if "Resolved" in result:
                return result
        return "No agent could handle the incident"

# Example usage
from NetworkAgent import NetworkAgent
from HardwareAgent import HardwareAgent

incident_data = {'type': 'network_outage', 'details': 'Router failure'}
network_agent = NetworkAgent(incident_data)
hardware_agent = HardwareAgent(incident_data)
orchestration = OrchestrationLayer([network_agent, hardware_agent])

print(orchestration.dispatch_incident(incident_data))