import pandas as pd
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier, RandomForestRegressor
from sklearn.preprocessing import LabelEncoder
from sklearn.feature_extraction.text import TfidfVectorizer
from django.utils import timezone
from core.models import JiraTicket
import joblib
import os
from sklearn.utils.validation import NotFittedError
from incidentmanagement import settings
from sklearn.preprocessing import LabelEncoder


class JiraTicketMLModel():
    def __init__(self):
        self.agent_model = None
        self.confidence_model = None
        self.le_agent = None  # Label encoder for predicted_agent
        self.vectorizer = None  # TF-IDF vectorizer for text data
        self.model_dir = os.path.join(settings.BASE_DIR, 'trained_models')  # Define the model directory
        self.load_model()  # Load saved models and encoders if available


    def train(self):
        # Load Jira tickets from the database
        tickets = JiraTicket.objects.all()
        if not tickets.exists():
            print("No Jira tickets available for training.")
            return

        # Convert tickets to a DataFrame
        data = pd.DataFrame(list(tickets.values()))
        data['created_at'] = pd.to_datetime(data['created_at'])
        data['created_hour'] = data['created_at'].dt.hour
        data['created_dayofweek'] = data['created_at'].dt.dayofweek
        data['created_month'] = data['created_at'].dt.month

        # Fill missing values for features if necessary
        data['predicted_agent'].fillna('Unknown', inplace=True)
        data['confidence_score'].fillna(data['confidence_score'].mean(), inplace=True)

        # Drop rows with NaN in the target variables
        data = data.dropna(subset=['predicted_agent', 'confidence_score'])

        print(f"Missing 'predicted_agent' values: {data['predicted_agent'].isna().sum()}")
        print(f"Missing 'confidence_score' values: {data['confidence_score'].isna().sum()}")

        # Encode categorical columns
        le_priority = LabelEncoder()
        data['priority'] = le_priority.fit_transform(data['priority'])

        le_status = LabelEncoder()
        data['status'] = le_status.fit_transform(data['status'])

        # Prepare data for agent prediction
        features_agent = data[['priority', 'status', 'created_hour', 'created_dayofweek', 'created_month']]
        target_agent = data['predicted_agent']

        # Check if there is enough data for agent prediction
        if target_agent.isna().sum() > 0:
            data = data.dropna(subset=['predicted_agent'])

        if data.shape[0] == 0:
            print("No data left for agent prediction after dropping NaNs.")
            return

        # Prepare data for confidence prediction
        features_confidence = data[['priority', 'status', 'created_hour', 'created_dayofweek', 'created_month']]
        target_confidence = data['confidence_score']

        # Check if there is enough data for confidence prediction
        if target_confidence.isna().sum() > 0:
            data = data.dropna(subset=['confidence_score'])

        if data.shape[0] == 0:
            print("No data left for confidence prediction after dropping NaNs.")
            return

        # Train-test split for agent prediction
        X_train_agent, X_test_agent, y_train_agent, y_test_agent = train_test_split(
            features_agent, target_agent, test_size=0.2, random_state=42)

        # Hyperparameter tuning and model training for agent prediction
        param_grid_agent = {
            'n_estimators': [50, 100, 200],
            'max_depth': [None, 10, 20, 30],
            'min_samples_split': [2, 5, 10]
        }
        rf_agent = RandomForestClassifier(random_state=42)
        grid_search_agent = GridSearchCV(
            estimator=rf_agent, param_grid=param_grid_agent,
            cv=3, scoring='accuracy', n_jobs=-1, error_score='raise')
        grid_search_agent.fit(X_train_agent, y_train_agent)
        self.agent_model = grid_search_agent.best_estimator_

        # Train-test split for confidence prediction
        X_train_confidence, X_test_confidence, y_train_confidence, y_test_confidence = train_test_split(
            features_confidence, target_confidence, test_size=0.2, random_state=42)

        # Hyperparameter tuning and model training for confidence prediction
        param_grid_confidence = {
            'n_estimators': [50, 100, 200],
            'max_depth': [None, 10, 20, 30],
            'min_samples_split': [2, 5, 10]
        }
        rf_confidence = RandomForestRegressor(random_state=42)
        grid_search_confidence = GridSearchCV(
            estimator=rf_confidence, param_grid=param_grid_confidence,
            cv=3, scoring='neg_mean_absolute_error', n_jobs=-1, error_score='raise')
        grid_search_confidence.fit(X_train_confidence, y_train_confidence)
        self.confidence_model = grid_search_confidence.best_estimator_

        # Save the models and encoders
        self.save_model()



    def save_model(self):
        os.makedirs(self.model_dir, exist_ok=True)  # Create the model directory if it doesn't exist
        joblib.dump(self.agent_model, os.path.join(self.model_dir, 'jira_agent_model.pkl'))
        joblib.dump(self.confidence_model, os.path.join(self.model_dir, 'jira_confidence_model.pkl'))
        joblib.dump(self.le_agent, os.path.join(self.model_dir, 'jira_le_agent.pkl'))
        joblib.dump(self.vectorizer, os.path.join(self.model_dir, 'jira_vectorizer.pkl'))
        print("Models and encoders saved successfully.")

    def load_model(self):
        if os.path.exists(os.path.join(self.model_dir, 'jira_agent_model.pkl')):
            self.agent_model = joblib.load(os.path.join(self.model_dir, 'jira_agent_model.pkl'))
        else:
            print("jira_agent_model.pkl not found. Please train the model.")
        
        if os.path.exists(os.path.join(self.model_dir, 'jira_confidence_model.pkl')):
            self.confidence_model = joblib.load(os.path.join(self.model_dir, 'jira_confidence_model.pkl'))
        else:
            print("jira_confidence_model.pkl not found. Please train the model.")
        
        if os.path.exists(os.path.join(self.model_dir, 'jira_le_agent.pkl')):
            self.le_agent = joblib.load(os.path.join(self.model_dir, 'jira_le_agent.pkl'))
        else:
            print("jira_le_agent.pkl not found. Please train the model.")
        
        if os.path.exists(os.path.join(self.model_dir, 'jira_vectorizer.pkl')):
            self.vectorizer = joblib.load(os.path.join(self.model_dir, 'jira_vectorizer.pkl'))
        else:
            print("jira_vectorizer.pkl not found. Please train the model.")

    def predict_agent(self, ticket_data):
        data = pd.DataFrame([{
            'priority': ticket_data['priority'],
            'status': ticket_data['status'],
            'created_hour': timezone.now().hour,
            'created_dayofweek': timezone.now().weekday(),
            'created_month': timezone.now().month
        }])

        data = data.astype({
            'priority': 'str',
            'status': 'str',
            'created_hour': 'int',
            'created_dayofweek': 'int',
            'created_month': 'int'
        })

        expected_columns = ['priority', 'status', 'created_hour', 'created_dayofweek', 'created_month']
        data = data[expected_columns]

        try:
            prediction = self.agent_model.predict(data)
            return self.le_agent.inverse_transform([prediction])[0]
        except Exception as e:
            print(f"Prediction error: {e}")
            return "Unknown"

    def predict_confidence(self, ticket_data):
        data = pd.DataFrame([{
            'priority': ticket_data['priority'],
            'status': ticket_data['status'],
            'created_hour': timezone.now().hour,
            'created_dayofweek': timezone.now().weekday(),
            'created_month': timezone.now().month
        }])

        data = data.astype({
            'priority': 'str',
            'status': 'str',
            'created_hour': 'int',
            'created_dayofweek': 'int',
            'created_month': 'int'
        })

        expected_columns = ['priority', 'status', 'created_hour', 'created_dayofweek', 'created_month']
        data = data[expected_columns]

        try:
            confidence = self.confidence_model.predict(data)
            return confidence[0]
        except Exception as e:
            print(f"Prediction error: {e}")
            return 0.0
