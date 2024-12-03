import pandas as pd

# Load the original CSV file (uploaded by the user)
file_path = 'realistic_incidents.csv'

# Read the CSV file
try:
    data = pd.read_csv(file_path)
    
    # Map severity names to IDs
    severity_mapping = {
        "Critical": 1,
        "High": 2,
        "Medium": 3,
        "Low": 4
    }
    data['severity'] = data['severity'].map(severity_mapping)
    
    # Add a new column 'device' with placeholder values
    data['device'] = 'Unknown'  # Replace with actual device values if necessary

    # Save the updated CSV file
    updated_file_path = 'Updated_.csv'
    data.to_csv(updated_file_path, index=False)
    updated_file_path

except Exception as e:
    str(e)
