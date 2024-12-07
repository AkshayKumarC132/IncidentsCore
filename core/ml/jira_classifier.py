import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
from ml.utils import load_data
from core.models import JiraTicket

def train_classifier():
    """
    Train the Jira classifier and save the model.
    """
    data = load_data()
    data = data.dropna(subset=['predicted_agent'])

    data['text'] = data['summary'] + " " + data['description']
    X = data['text']
    y = data['predicted_agent']

    vectorizer = TfidfVectorizer(max_features=5000)
    X_transformed = vectorizer.fit_transform(X)

    X_train, X_test, y_train, y_test = train_test_split(
        X_transformed, y, test_size=0.2, random_state=42
    )

    classifier = RandomForestClassifier(n_estimators=100, random_state=42)
    classifier.fit(X_train, y_train)

    joblib.dump(classifier, "jira_classifier.pkl")
    joblib.dump(vectorizer, "tfidf_vectorizer.pkl")

    print("Jira Classifier trained and saved.")

def validate_classifier():
    """
    Validate the Jira classifier with test data.
    """
    classifier = joblib.load("jira_classifier.pkl")
    vectorizer = joblib.load("tfidf_vectorizer.pkl")

    data = load_data()
    data = data.dropna(subset=['predicted_agent'])

    data['text'] = data['summary'] + " " + data['description']
    X = data['text']
    y_true = data['predicted_agent']

    X_transformed = vectorizer.transform(X)
    y_pred = classifier.predict(X_transformed)

    print("Classification Report:")
    print(classification_report(y_true, y_pred))
    print(f"Accuracy: {accuracy_score(y_true, y_pred) * 100:.2f}%")

def update_predictions():
    """
    Predict unresolved tickets and update them in the database.
    """
    classifier = joblib.load("jira_classifier.pkl")
    vectorizer = joblib.load("tfidf_vectorizer.pkl")

    unresolved_tickets = JiraTicket.objects.filter(predicted_agent__isnull=True)

    for ticket in unresolved_tickets:
        text = f"{ticket.summary} {ticket.description}"
        transformed_text = vectorizer.transform([text])

        predicted_agent = classifier.predict(transformed_text)[0]
        confidence_score = max(classifier.predict_proba(transformed_text)[0]) * 100

        ticket.predicted_agent = predicted_agent
        ticket.confidence_score = confidence_score
        ticket.save()

    print("Predictions updated in JiraTicket table.")
