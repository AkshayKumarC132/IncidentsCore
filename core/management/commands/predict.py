import joblib
from django.core.management.base import BaseCommand

class Command(BaseCommand):
    help = 'Predict the agent based on summary and description'

    def add_arguments(self, parser):
        parser.add_argument('summary', type=str, help='Summary of the issue')
        parser.add_argument('description', type=str, help='Description of the issue')

    def handle(self, *args, **kwargs):
        # Load model and vectorizer
        model = joblib.load('jira_classifier.pkl')
        vectorizer = joblib.load('tfidf_vectorizer.pkl')

        summary = kwargs['summary']
        description = kwargs['description']

        # combined_text = f"{summary} {description}"
        # print(combined_text)
        # vectorizer = joblib.load('tfidf_vectorizer.pkl')
        # print(vectorizer.vocabulary_)

        # vectorized_text = vectorizer.transform([combined_text])
        # agent = model.predict(vectorized_text)[0]
        # print(agent)
        # confidence = max(model.predict_proba(vectorized_text)[0]) * 100
        # print(confidence)
        combined_text = f"{summary} {description}"
        vectorized_text = vectorizer.transform([combined_text])
        probabilities = model.predict_proba(vectorized_text)[0]
        max_confidence = max(probabilities)
        agent = model.classes_[probabilities.argmax()]

        if max_confidence < 0.7:
            return "unknown", max_confidence * 100
        return agent, max_confidence * 100

        # self.stdout.write(self.style.SUCCESS(f'Predicted agent: {agent} with confidence: {confidence:.2f}%'))