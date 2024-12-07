import random
import pandas as pd

# Define categories and sample data for augmentation
categories = {
    "Bug Tracking": [
        "Login page throws 500 error on incorrect password.",
        "Unable to save form data after multiple attempts.",
        "API returns null value for valid parameters."
    ],
    "Feature Request": [
        "Add dark mode support for the dashboard.",
        "Implement SSO for better user authentication.",
        "Create export functionality for reports."
    ],
    "Task": [
        "Complete project setup documentation.",
        "Verify integration with third-party APIs.",
        "Migrate existing users to the new system."
    ],
    "Improvement": [
        "Optimize database queries for faster load times.",
        "Redesign the user profile page for better UX.",
        "Improve error messages with detailed information."
    ],
    "Support": [
        "Assist customer with resetting their account password.",
        "Troubleshoot network connectivity for office setup.",
        "Help with configuring email notifications."
    ]
}

# Generate synthetic data
def generate_synthetic_tickets(num_records=500):
    tickets = []
    for _ in range(num_records):
        category = random.choice(list(categories.keys()))
        summary = random.choice(categories[category])
        description = f"{summary} Additional context and details about the {category.lower()} issue."
        tickets.append({
            "project": f"Project-{random.randint(1, 10)}",
            "issue_key": f"ISSUE-{random.randint(1000, 9999)}",
            "summary": summary,
            "description": description,
            "status": random.choice(["Open", "In Progress", "Closed"]),
            "priority": random.choice(["Low", "Medium", "High", "Critical"]),
            "predicted_agent": category,
            "confidence_score": None  # Leave empty for testing predictions
        })
    return pd.DataFrame(tickets)

# Generate dataset and save to CSV
synthetic_data = generate_synthetic_tickets()
synthetic_data.to_csv("synthetic_jira_tickets.csv", index=False)
print("Synthetic dataset created and saved to 'synthetic_jira_tickets.csv'")
