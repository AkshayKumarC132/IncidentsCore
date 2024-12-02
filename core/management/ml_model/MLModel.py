import pandas as pd
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier, RandomForestRegressor
from sklearn.preprocessing import LabelEncoder
from sklearn.feature_extraction.text import TfidfVectorizer
from django.utils import timezone
from core.models import Incident
import joblib
import os
from sklearn.utils.validation import NotFittedError
from incidentmanagement import settings

class IncidentMLModel():
    def __init__(self):
        self.time_model = None
        self.solution_model = None
        self.le_solution = None  # Label encoder for solutions
        self.vectorizer = None  # TF-IDF vectorizer for text data
        self.model_dir = os.path.join(settings.BASE_DIR, 'trained_models')  # Define the model directory
        self.load_model()  # Load saved models and encoders if available

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

        # Drop rows with missing values
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
        grid_search_time = GridSearchCV(
            estimator=rf_time, param_grid=param_grid_time,
            cv=3, scoring='neg_mean_absolute_error', n_jobs=-1, error_score='raise')
        grid_search_time.fit(X_train_time, y_train_time)
        self.time_model = grid_search_time.best_estimator_

        # Prepare data for solution prediction
        if 'recommended_solution' not in data or data['recommended_solution'].isnull().all():
            print("No valid solutions for encoding.")
            return

        # Vectorize the 'description' column
        descriptions = data['description'].fillna("No description provided").replace('', "No description provided")
        self.vectorizer = TfidfVectorizer(min_df=1, stop_words=None)
        description_vectors = self.vectorizer.fit_transform(descriptions)

        # Concatenate vectorized descriptions with other numeric features
        features_solution = pd.concat([
            data[['severity_id', 'device_id']].reset_index(drop=True), 
            pd.DataFrame(description_vectors.toarray())
        ], axis=1)

        # Ensure column names are strings
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
        grid_search_solution = GridSearchCV(
            estimator=rf_solution, param_grid=param_grid_solution,
            cv=3, scoring='accuracy', n_jobs=-1, error_score='raise')
        grid_search_solution.fit(X_train_solution, y_train_solution)
        self.solution_model = grid_search_solution.best_estimator_

        # Save the models and encoders
        self.save_model()

    def save_model(self):
        os.makedirs(self.model_dir, exist_ok=True)  # Create the model directory if it doesn't exist
        joblib.dump(self.time_model, os.path.join(self.model_dir, 'time_model.pkl'))
        joblib.dump(self.solution_model, os.path.join(self.model_dir, 'solution_model.pkl'))
        joblib.dump(self.le_solution, os.path.join(self.model_dir, 'le_solution.pkl'))
        joblib.dump(self.vectorizer, os.path.join(self.model_dir, 'vectorizer.pkl'))
        print("Models and encoders saved successfully.")

    def load_model(self):
        if os.path.exists(os.path.join(self.model_dir, 'time_model.pkl')):
            self.time_model = joblib.load(os.path.join(self.model_dir, 'time_model.pkl'))
        else:
            print("time_model.pkl not found. Please train the model.")
        
        if os.path.exists(os.path.join(self.model_dir, 'solution_model.pkl')):
            self.solution_model = joblib.load(os.path.join(self.model_dir, 'solution_model.pkl'))
        else:
            print("solution_model.pkl not found. Please train the model.")
        
        if os.path.exists(os.path.join(self.model_dir, 'le_solution.pkl')):
            self.le_solution = joblib.load(os.path.join(self.model_dir, 'le_solution.pkl'))
        else:
            print("le_solution.pkl not found. Please train the model.")
        
        if os.path.exists(os.path.join(self.model_dir, 'vectorizer.pkl')):
            self.vectorizer = joblib.load(os.path.join(self.model_dir, 'vectorizer.pkl'))
        else:
            print("vectorizer.pkl not found. Please train the model.")

    def predict_time(self, incident_data):
        # Ensure column order and types match training data
        data = pd.DataFrame([{
            'severity_id': incident_data['severity_id'],
            'device_id': incident_data['device_id'],
            'created_hour': timezone.now().hour,
            'created_dayofweek': timezone.now().weekday(),
            'created_month': timezone.now().month
        }])
        
        data = data.astype({
            'severity_id': 'int',
            'device_id': 'int',
            'created_hour': 'int',
            'created_dayofweek': 'int',
            'created_month': 'int'
        })

        expected_columns = ['severity_id', 'device_id', 'created_hour', 'created_dayofweek', 'created_month']
        data = data[expected_columns]

        try:
            prediction = self.time_model.predict(data)
            return prediction[0]
        except Exception as e:
            print(f"Prediction error: {e}")
            return 1.0  # Default value if prediction fails

    def predict_solution(self, incident_data):
        
        if not self.vectorizer:
            print("Vectorizer is not loaded. Please train the model first.")
            return "Human Intervention Needed"

        data = pd.DataFrame([{
            'severity_id': incident_data['severity_id'],
            'device_id': incident_data['device_id'],
            'description': incident_data.get('description', '')
        }])

        try:
            description_vectorized = self.vectorizer.transform(data['description']).toarray()
        except Exception as e:
            print(f"Error during vectorization: {e}")
            return "Human Intervention Needed"

        prediction_data = pd.concat([
            data[['severity_id', 'device_id']].reset_index(drop=True), 
            pd.DataFrame(description_vectorized)
        ], axis=1)

        prediction_data.columns = prediction_data.columns.astype(str)

        try:
            predicted_solution_index = self.solution_model.predict(prediction_data)[0]
            probabilities = self.solution_model.predict_proba(prediction_data)[0]
            confidence = max(probabilities)

            # Confidence threshold for "Human Intervention Needed"
            threshold = 0.6
            if confidence < threshold:
                print(f"Low confidence ({confidence:.2f}), recommending Human Intervention.")
                return "Human Intervention Needed"

            predicted_solution = self.le_solution.inverse_transform([predicted_solution_index])[0]
            return predicted_solution

        except NotFittedError:
            print("Model not fitted. Please train the model first.")
            return "Human Intervention Needed"
        except Exception as e:
            print(f"Prediction error: {e}")
            return "Human Intervention Needed"