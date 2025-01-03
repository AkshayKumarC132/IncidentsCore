import pandas as pd
from core.models import JiraTicket

def load_data():
    """
    Load JiraTicket data into a Pandas DataFrame.
    """
    data = JiraTicket.objects.all().values('summary', 'description', 'predicted_agent')
    return pd.DataFrame(data)


import pandas as pd

def load_jira_data():
    # Fetch data from JiraTicket model
    tickets = JiraTicket.objects.all().values('summary', 'description', 'predicted_category')
    df = pd.DataFrame(tickets)

    # Concatenate summary and description as the input text
    df['text'] = df['summary'] + " " + df['description']
    df = df.dropna(subset=['predicted_category'])  # Drop rows without categories
    return df
