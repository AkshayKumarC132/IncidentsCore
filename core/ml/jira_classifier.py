import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split,GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
from ml.utils import load_data
from core.models import JiraTicket
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer
import nltk
import re

# Download NLTK resources
nltk.download('stopwords')
nltk.download('wordnet')

def clean_text(text):
    """
    Preprocess and clean text data.
    """
    stop_words = set(stopwords.words("english"))
    lemmatizer = WordNetLemmatizer()

    # Lowercase, remove special characters and digits
    text = re.sub(r"[^a-zA-Z]", " ", text).lower()
    text = text.split()

    # Remove stop words and apply lemmatization
    text = [lemmatizer.lemmatize(word) for word in text if word not in stop_words]

    return " ".join(text)

def train_classifier():
    """
    Train the Jira classifier and save the model with improvements.
    """
    # Load and clean data
    data = load_data()
    data = data.dropna(subset=['predicted_agent'])
    data['text'] = (data['summary'] + " " + data['description']).apply(clean_text)

    # Features and labels
    X = data['text']
    y = data['predicted_agent']

    # TF-IDF Vectorizer with bigrams and optimized parameters
    vectorizer = TfidfVectorizer(
        max_features=5000, 
        ngram_range=(1, 2),  # Unigrams and bigrams
        stop_words="english"
    )
    X_transformed = vectorizer.fit_transform(X)

    # Split data into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(
        X_transformed, y, test_size=0.2, random_state=42
    )

    # Hyperparameter tuning for RandomForestClassifier
    param_grid = {
        'n_estimators': [50, 100, 200],
        'max_depth': [None, 10, 20, 30],
        'min_samples_split': [2, 5, 10],
    }

    rf_classifier = RandomForestClassifier(random_state=42)
    grid_search = GridSearchCV(
        estimator=rf_classifier,
        param_grid=param_grid,
        cv=3,
        scoring='accuracy',
        verbose=1,
        n_jobs=-1
    )
    grid_search.fit(X_train, y_train)

    # Best classifier from grid search
    best_rf = grid_search.best_estimator_

    # Evaluate on test data
    y_pred = best_rf.predict(X_test)
    print("Classification Report:")
    print(classification_report(y_test, y_pred))
    print("Accuracy:", accuracy_score(y_test, y_pred))

    # Save the best classifier and vectorizer
    joblib.dump(best_rf, "jira_classifier.pkl")
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
