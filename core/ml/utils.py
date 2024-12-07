import pandas as pd
from core.models import JiraTicket

def load_data():
    """
    Load JiraTicket data into a Pandas DataFrame.
    """
    data = JiraTicket.objects.all().values('summary', 'description', 'predicted_agent')
    return pd.DataFrame(data)
