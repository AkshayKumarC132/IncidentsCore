import pandas as pd
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier, RandomForestRegressor
from sklearn.preprocessing import LabelEncoder
from sklearn.feature_extraction.text import TfidfVectorizer
from django.utils import timezone
from core.models import *
import joblib
import os

class IncidentMLModel:
    def __init__(self):
        self.time_model = None
        self.solution_model = None
        self.le_solution = None  # For encoding solutions
        self.vectorizer = None  # For vectorizing text data
        self.load_model()  # Attempt to load saved models and encoders

    def train(self):
        # Load incidents from the database
        incidents = Incident.objects.all()
        if not incidents.exists():
            print("No incidents available for training.")
            return

        data = pd.DataFrame(list(incidents.values()))
        data['created_at'] = pd.to_datetime(data['created_at'])
        data['created_hour'] = data['created_at'].dt.hour
        data['created_dayofweek'] = data['created_at'].dt.dayofweek
        data['created_month'] = data['created_at'].dt.month

        # Check for missing values
        data = data.dropna()

        # Prepare data for time prediction
        features_time = data[['severity_id', 'device_id', 'created_hour', 'created_dayofweek', 'created_month']]
        target_time = data['predicted_resolution_time']

        # Train-test split for time prediction
        X_train_time, X_test_time, y_train_time, y_test_time = train_test_split(
            features_time, target_time, test_size=0.2, random_state=42)

        # Hyperparameter tuning and model training for time prediction
        param_grid_time = {
            'n_estimators': [50, 100, 200],
            'max_depth': [None, 10, 20, 30],
            'min_samples_split': [2, 5, 10]
        }
        rf_time = RandomForestRegressor(random_state=42)
        grid_search_time = GridSearchCV(estimator=rf_time, param_grid=param_grid_time,
                                        cv=3, scoring='neg_mean_absolute_error', n_jobs=-1, error_score='raise')
        grid_search_time.fit(X_train_time, y_train_time)
        self.time_model = grid_search_time.best_estimator_

        # Prepare data for solution prediction
        if 'recommended_solution' not in data or data['recommended_solution'].isnull().all():
            print("No valid solutions for encoding.")
            return

        # Vectorize 'description' column
        descriptions = data['description'].fillna('')
        self.vectorizer = TfidfVectorizer()
        description_vectors = self.vectorizer.fit_transform(descriptions)

        # Concatenate vectorized descriptions with other numeric features
        features_solution = pd.concat([
            data[['severity_id', 'device_id']].reset_index(drop=True), 
            pd.DataFrame(description_vectors.toarray())
        ], axis=1)

        # Convert all column names to strings
        features_solution.columns = features_solution.columns.astype(str)
        
        self.le_solution = LabelEncoder()
        target_solution = self.le_solution.fit_transform(data['recommended_solution'])

        # Train-test split for solution prediction
        X_train_solution, X_test_solution, y_train_solution, y_test_solution = train_test_split(
            features_solution, target_solution, test_size=0.2, random_state=42)

        # Hyperparameter tuning and model training for solution prediction
        param_grid_solution = {
            'n_estimators': [50, 100, 200],
            'max_depth': [None, 10, 20, 30],
            'min_samples_split': [2, 5, 10]
        }

        rf_solution = RandomForestClassifier(random_state=42)
        grid_search_solution = GridSearchCV(estimator=rf_solution, param_grid=param_grid_solution,
                                            cv=3, scoring='accuracy', n_jobs=-1, error_score='raise')
        grid_search_solution.fit(X_train_solution, y_train_solution)
        self.solution_model = grid_search_solution.best_estimator_

        # Save the models and encoders
        self.save_model()

    def save_model(self):
        joblib.dump(self.time_model, 'time_model.pkl')
        joblib.dump(self.solution_model, 'solution_model.pkl')
        joblib.dump(self.le_solution, 'le_solution.pkl')
        joblib.dump(self.vectorizer, 'vectorizer.pkl')
        print("Models and encoders saved successfully.")

    def load_model(self):
        if os.path.exists('time_model.pkl'):
            self.time_model = joblib.load('time_model.pkl')
        if os.path.exists('solution_model.pkl'):
            self.solution_model = joblib.load('solution_model.pkl')
        if os.path.exists('le_solution.pkl'):
            self.le_solution = joblib.load('le_solution.pkl')
        if os.path.exists('vectorizer.pkl'):
            self.vectorizer = joblib.load('vectorizer.pkl')

    def predict_time(self, incident_data):
        # Ensure the column order and data types match what the model was trained on
        data = pd.DataFrame([{
            'severity_id': incident_data['severity_id'],
            'device_id': incident_data['device_id'],
            'created_hour': timezone.now().hour,
            'created_dayofweek': timezone.now().weekday(),
            'created_month': timezone.now().month
        }])

        # Check if the data types and columns align with the trained model
        data = data.astype({
            'severity_id': 'int',
            'device_id': 'int',
            'created_hour': 'int',
            'created_dayofweek': 'int',
            'created_month': 'int'
        })

        # Ensure the column order matches the training data
        expected_columns = ['severity_id', 'device_id', 'created_hour', 'created_dayofweek', 'created_month']
        data = data[expected_columns]

        try:
            prediction = self.time_model.predict(data)
            # print(f"Prediction for resolution time: {prediction}")
            return prediction[0]
        except Exception as e:
            print(f"Prediction error: {e}")
            return 1.0  # Default value if prediction fails


    def predict_solution(self, incident_data):
        data = pd.DataFrame([{
            'severity_id': incident_data['severity_id'],
            'device_id': incident_data['device_id'],
            'description': incident_data.get('description', '')
        }])

        description_vectorized = self.vectorizer.transform(data['description']).toarray()

        prediction_data = pd.concat([
            data[['severity_id', 'device_id']].reset_index(drop=True), 
            pd.DataFrame(description_vectorized)
        ], axis=1)

        prediction_data.columns = prediction_data.columns.astype(str)
        predicted_solution_index = self.solution_model.predict(prediction_data)[0]
        predicted_solution = self.le_solution.inverse_transform([predicted_solution_index])[0]
        return predicted_solution
