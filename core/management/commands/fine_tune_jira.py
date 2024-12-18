# from django.core.management.base import BaseCommand

# class Command(BaseCommand):
#     help = "Fine-tune DistilBERT for Jira ticket classification"

#     def handle(self, *args, **kwargs):
#         """
#         Main logic for fine-tuning DistilBERT on Jira ticket data.
#         """
#         import pandas as pd
#         from transformers import DistilBertTokenizer, DistilBertForSequenceClassification, Trainer, TrainingArguments
#         from sklearn.model_selection import train_test_split
#         from sklearn.preprocessing import LabelEncoder
#         from sklearn.metrics import accuracy_score
#         from torch.utils.data import Dataset
#         import torch
#         import joblib
#         import os

#         # Load Jira ticket data
#         def load_data():
#             from core.models import JiraTicket  # Replace 'core' with the correct app name
#             tickets = JiraTicket.objects.all().values('summary', 'description', 'predicted_category')
#             df = pd.DataFrame(tickets)
#             df['text'] = df['summary'] + " " + df['predicted_category'] + " " + df['description'] 
#             df = df.dropna(subset=['predicted_category'])
#             return df

#         print("Loading Jira ticket data...")
#         data = load_data()
#         X = data['text']
#         y = data['predicted_category']

#         # Encode labels
#         print("Encoding labels...")
#         label_encoder = LabelEncoder()
#         y_encoded = label_encoder.fit_transform(y)

#         # Save label encoder
#         output_dir = "./jira_model"
#         if not os.path.exists(output_dir):
#             os.makedirs(output_dir)
#         joblib.dump(label_encoder, os.path.join(output_dir, "label_encoder.pkl"))

#         # Split data
#         print("Splitting data...")
#         X_train, X_test, y_train, y_test = train_test_split(X, y_encoded, test_size=0.2, random_state=42)

#         # Tokenize data
#         print("Tokenizing data...")
#         tokenizer = DistilBertTokenizer.from_pretrained("distilbert-base-uncased")
#         train_encodings = tokenizer(X_train.tolist(), truncation=True, padding=True, max_length=512, return_tensors="pt")
#         test_encodings = tokenizer(X_test.tolist(), truncation=True, padding=True, max_length=512, return_tensors="pt")

#         # Dataset definition
#         class JiraDataset(Dataset):
#             def __init__(self, encodings, labels):
#                 self.encodings = encodings
#                 self.labels = labels

#             def __len__(self):
#                 return len(self.labels)

#             def __getitem__(self, idx):
#                 item = {key: val[idx] for key, val in self.encodings.items()}
#                 item["labels"] = self.labels[idx]
#                 return item

#         train_dataset = JiraDataset(train_encodings, torch.tensor(y_train))
#         test_dataset = JiraDataset(test_encodings, torch.tensor(y_test))
        

#         # Define compute_metrics function
#         def compute_metrics(pred):
#             predictions, labels = pred
#             predictions = predictions.argmax(axis=-1)
#             acc = accuracy_score(labels, predictions)
#             return {"accuracy": acc}

#         # Load pre-trained model
#         print("Loading pre-trained DistilBERT model...")
#         model = DistilBertForSequenceClassification.from_pretrained(
#             "distilbert-base-uncased", num_labels=len(label_encoder.classes_)
#         )

#         # Training arguments
#         print("Setting up training arguments...")
#         # training_args = TrainingArguments(
#         #     output_dir=output_dir,
#         #     evaluation_strategy="epoch",
#         #     save_strategy="epoch",
#         #     logging_dir="./logs",
#         #     logging_steps=10,
#         #     per_device_train_batch_size=4,
#         #     per_device_eval_batch_size=16,
#         #     num_train_epochs=1,
#         #     gradient_accumulation_steps=4,
#         #     fp16=True,
#         #     load_best_model_at_end=True,
#         #     metric_for_best_model="accuracy",
#         #     greater_is_better=True,
#         #     save_steps=500,
#         #     save_total_limit=3,
#         # )
#         training_args = TrainingArguments(
#             output_dir="jira_model",
#             evaluation_strategy="steps",
#             save_strategy="steps",
#             num_train_epochs=4,
#             per_device_train_batch_size=16,
#             learning_rate=5e-5,
#             weight_decay=0.01,
#             logging_dir="logs",
#         )

#         # Trainer
#         print("Initializing Trainer...")
#         trainer = Trainer(
#             model=model,
#             args=training_args,
#             train_dataset=train_dataset,
#             eval_dataset=test_dataset,
#             tokenizer=tokenizer,
#             compute_metrics=compute_metrics,
#         )

#         # Train and save model
#         print("Training the model...")
#         trainer.train()
#         print("Saving the fine-tuned model and tokenizer...")
#         model.save_pretrained(output_dir)
#         tokenizer.save_pretrained(output_dir)

#         self.stdout.write(self.style.SUCCESS("Fine-tuning completed. Model and tokenizer saved in 'jira_model'."))

from django.core.management.base import BaseCommand

class Command(BaseCommand):
    help = "Fine-tune DistilBERT for Jira ticket classification"

    def handle(self, *args, **kwargs):
        """
        Main logic for fine-tuning DistilBERT on Jira ticket data.
        """
        import pandas as pd
        from transformers import DistilBertTokenizer, DistilBertForSequenceClassification, Trainer, TrainingArguments
        from sklearn.model_selection import train_test_split
        from sklearn.preprocessing import LabelEncoder
        from sklearn.metrics import accuracy_score
        from torch.utils.data import Dataset
        import torch
        import joblib
        import os

        # Load Jira ticket data
        def load_data():
            from core.models import JiraTicket  # Replace 'core' with the correct app name
            tickets = JiraTicket.objects.all().values('summary', 'description', 'predicted_category')
            df = pd.DataFrame(tickets)
            df['text'] = df['summary'] + " " + df['predicted_category'] + " " + df['description'] 
            df = df.dropna(subset=['predicted_category'])
            return df

        print("Loading Jira ticket data...")
        data = load_data()
        X = data['text']
        y = data['predicted_category']

        # Encode labels
        print("Encoding labels...")
        label_encoder = LabelEncoder()
        y_encoded = label_encoder.fit_transform(y)

        # Save label encoder
        output_dir = "./jira_model"
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        joblib.dump(label_encoder, os.path.join(output_dir, "label_encoder.pkl"))

        # Split data
        print("Splitting data...")
        X_train, X_test, y_train, y_test = train_test_split(X, y_encoded, test_size=0.2, random_state=42)

        # Tokenize data
        print("Tokenizing data...")
        tokenizer = DistilBertTokenizer.from_pretrained("distilbert-base-uncased")
        train_encodings = tokenizer(X_train.tolist(), truncation=True, padding=True, max_length=512, return_tensors="pt")
        test_encodings = tokenizer(X_test.tolist(), truncation=True, padding=True, max_length=512, return_tensors="pt")

        # Dataset definition
        class JiraDataset(Dataset):
            def __init__(self, encodings, labels):
                self.encodings = encodings
                self.labels = labels

            def __len__(self):
                return len(self.labels)

            def __getitem__(self, idx):
                item = {key: val[idx] for key, val in self.encodings.items()}
                item["labels"] = self.labels[idx]
                return item

        train_dataset = JiraDataset(train_encodings, torch.tensor(y_train))
        test_dataset = JiraDataset(test_encodings, torch.tensor(y_test))
        

        # Define compute_metrics function
        def compute_metrics(pred):
            predictions, labels = pred
            predictions = predictions.argmax(axis=-1)
            acc = accuracy_score(labels, predictions)
            return {"accuracy": acc}

        # Load pre-trained model
        print("Loading pre-trained DistilBERT model...")
        model = DistilBertForSequenceClassification.from_pretrained(
            "distilbert-base-uncased", num_labels=len(label_encoder.classes_)
        )

        # Training arguments
        print("Setting up training arguments...")
        training_args = TrainingArguments(
            output_dir="jira_model",
            evaluation_strategy="steps",
            save_strategy="steps",
            num_train_epochs=4,
            per_device_train_batch_size=16,
            learning_rate=5e-5,
            weight_decay=0.01,
            logging_dir="logs",
        )

        # Trainer
        print("Initializing Trainer...")
        trainer = Trainer(
            model=model,
            args=training_args,
            train_dataset=train_dataset,
            eval_dataset=test_dataset,
            tokenizer=tokenizer,
            compute_metrics=compute_metrics,
        )

        # Train and save model
        print("Training the model...")
        trainer.train()
        print("Saving the fine-tuned model and tokenizer...")
        model.save_pretrained(output_dir)
        tokenizer.save_pretrained(output_dir)

        self.stdout.write(self.style.SUCCESS("Fine-tuning completed. Model and tokenizer saved in 'jira_model'."))

# Prediction Logic
from sklearn.preprocessing import LabelEncoder
import joblib

def make_prediction(text):
    """
    Make predictions and decode the agent label.
    """
    from transformers import DistilBertTokenizer, DistilBertForSequenceClassification
    import torch

    # Load the encoder
    label_encoder = joblib.load("./jira_model/label_encoder.pkl")

    # Load the fine-tuned model and tokenizer
    model = DistilBertForSequenceClassification.from_pretrained("./jira_model")
    tokenizer = DistilBertTokenizer.from_pretrained("./jira_model")

    # Tokenize the input text
    inputs = tokenizer(text, truncation=True, padding=True, max_length=512, return_tensors="pt")

    # Perform prediction
    model.eval()
    with torch.no_grad():
        outputs = model(**inputs)
        logits = outputs.logits
        predicted_class_id = logits.argmax(axis=-1).item()

    # Decode the numeric prediction to its original label
    decoded_prediction = label_encoder.inverse_transform([predicted_class_id])[0]

    return decoded_prediction
