from django.core.management.base import BaseCommand
from core.utils.jira_data_loader import load_jira_data
from core.utils.jira_model_utils import train_model, save_model_and_tokenizer

class Command(BaseCommand):
    help = "Train a DistilBERT model on Jira ticket data"

    def handle(self, *args, **kwargs):
        self.stdout.write("Loading Jira data...")
        data = load_jira_data()

        X = data['text']
        y = data['predicted_category']

        self.stdout.write("Splitting data into training and test sets...")
        from sklearn.model_selection import train_test_split
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

        self.stdout.write("Training the model...")
        model, tokenizer, label_encoder = train_model(X_train, y_train, X_test, y_test)

        self.stdout.write("Saving the model and encoders...")
        save_model_and_tokenizer(model, tokenizer, label_encoder, "./jira_model")

        self.stdout.write(self.style.SUCCESS("Model training and saving complete."))
