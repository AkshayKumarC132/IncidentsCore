import random

# Placeholder pools for dynamic generation
subjects = ["Users", "Admins", "A specific department"]
problems = ["unable to access", "facing errors in", "reporting issues with"]
systems = ["CRM system", "ERP platform", "network printer", "email server"]
reasons = ["due to connectivity issues", "because of a configuration error", "as a result of a server outage"]

# Generate dynamic descriptions
def generate_dynamic_description():
    subject = random.choice(subjects)
    problem = random.choice(problems)
    system = random.choice(systems)
    reason = random.choice(reasons)
    return f"{subject} are {problem} the {system} {reason}."

# Generate unique titles and descriptions
unique_titles = set()
unique_descriptions = set()

for _ in range(500):
    title = f"Incident {random.randint(1000, 9999)}"
    description = generate_dynamic_description()
    unique_titles.add(title)
    unique_descriptions.add(description)

print("Generated Titles:", list(unique_titles))
print("Generated Descriptions:", list(unique_descriptions))


import pandas as pd
import random

# Base pools for dynamic incident generation
incident_types = ["Network", "Hardware", "Software", "Security", "User"]
issues = {
    "Network": ["Connectivity issue", "DNS resolution error", "Firewall misconfiguration"],
    "Hardware": ["Printer offline", "Server down", "Disk failure"],
    "Software": ["Application crash", "Login error", "Data export failed"],
    "Security": ["Unauthorized access", "Phishing attempt", "Malware detected"],
    "User": ["Password reset request", "Account locked", "Permission issue"]
}
details = {
    "Network": ["Router not responding", "DNS server unreachable", "Firewall blocked a trusted source"],
    "Hardware": ["Printer driver unavailable", "Server failed to boot", "Disk space exceeded"],
    "Software": ["Application throws a runtime error", "Login credentials rejected", "Export function times out"],
    "Security": ["Suspicious login attempt detected", "Malicious email reported", "Antivirus flagged a process"],
    "User": ["User requested password reset", "Account locked after multiple attempts", "User lacks necessary permissions"]
}

# Generate incidents dynamically
def generate_incident(record_id):
    category = random.choice(incident_types)
    return {
        "id": record_id,
        "title": random.choice(issues[category]),
        "description": random.choice(details[category]),
        "severity": random.choice(["Low", "Medium", "High", "Critical"]),
        # "device_id": f"Device_{random.randint(1, 50)}",
        "created_at": pd.Timestamp.now() - pd.to_timedelta(random.randint(1, 30), unit="d"),
        # "predicted_agent": None,
        # "predicted_resolution_time": None,
        # "assigned_agent": None
    }

# Generate dataset
data = [generate_incident(i) for i in range(1, 501)]
df = pd.DataFrame(data)

# Save to Excel
df.to_csv("realistic_incidents.csv", index=False)
print("Generated dataset saved as 'realistic_incidents.csv'")
