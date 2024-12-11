import pandas as pd
from core.models import JiraTicket

def load_jira_data():
    """
    Load Jira ticket data from the database and prepare it for training.
    """
    tickets = JiraTicket.objects.all().values('summary', 'description', 'predicted_category')
    df = pd.DataFrame(tickets)

    if df.empty:
        raise ValueError("No data found in the JiraTicket model.")

    # Concatenate summary and description as the input text
    df['text'] = df['summary'] + " " + df['description']
    df = df.dropna(subset=['predicted_category'])  # Drop rows without categories

    if df.empty:
        raise ValueError("No data found after filtering for non-null predicted_category.")
    return df
