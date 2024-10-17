# ml_model.py
# Machine learning model handling code for incident resolution and prediction

import joblib

class MLModel:
    def _init_(self, model_path, label_encoder_path):
        self.model = joblib.load(model_path)
        self.label_encoder = joblib.load(label_encoder_path)

    def predict_solution(self, incident_data):
        # Prepare data and predict
        features = self.extract_features(incident_data)
        solution_encoded = self.model.predict([features])
        solution = self.label_encoder.inverse_transform(solution_encoded)
        return solution[0]

    def extract_features(self, incident_data):
        # Example feature extraction logic
        return [len(incident_data['details']), incident_data['severity']]

# Example usage
incident_data = {'details': 'Router down', 'severity': 3}
model = MLModel('solution_model.pkl', 'le_solution.pkl')
predicted_solution = model.predict_solution(incident_data)
print(f"Predicted Solution: {predicted_solution}")