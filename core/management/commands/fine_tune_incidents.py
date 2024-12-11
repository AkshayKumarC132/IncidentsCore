import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from transformers import DistilBertTokenizer, DistilBertForSequenceClassification, Trainer, TrainingArguments
from torch.utils.data import Dataset
import torch
from django.core.management.base import BaseCommand
import os


# Import Incident model
from core.models import Incident  # Replace 'core' with your app name

class Command(BaseCommand):
    help = "Fine-tune DistilBERT for Incident classification"

    def load_incident_data(self):
        """Load incident data from the database."""
        incidents = Incident.objects.all().values('title', 'description', 'pagent')
        df = pd.DataFrame(incidents)

        # Combine title and description
        df['text'] = df['title'] + " " + df['description']
        df = df.dropna(subset=['pagent'])  # Drop rows without predicted agents
        return df

    def handle(self, *args, **options):
        """Main method for fine-tuning the model."""
        # Step 1: Prepare Data
        print("Loading incident data...")
        incident_data = self.load_incident_data()
        X_incident = incident_data['text']
        y_incident = incident_data['pagent']

        # Split data
        print("Splitting data into training and testing sets...")
        X_train, X_test, y_train, y_test = train_test_split(
            X_incident, y_incident, test_size=0.2, random_state=42
        )

        # Encode labels
        print("Encoding labels...")
        label_encoder = LabelEncoder()
        y_train_encoded = label_encoder.fit_transform(y_train)
        y_test_encoded = label_encoder.transform(y_test)

        # Save label encoder
        output_dir = "./incident_model"
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        joblib.dump(label_encoder, os.path.join(output_dir, "label_encoder.pkl"))

        # Tokenize
        print("Tokenizing data...")
        tokenizer = DistilBertTokenizer.from_pretrained("distilbert-base-uncased")
        train_encodings = tokenizer(X_train.tolist(), truncation=True, padding=True, max_length=512, return_tensors="pt")
        test_encodings = tokenizer(X_test.tolist(), truncation=True, padding=True, max_length=512, return_tensors="pt")

        # Dataset class
        class IncidentDataset(Dataset):
            def __init__(self, encodings, labels):
                self.encodings = encodings
                self.labels = labels

            def __len__(self):
                return len(self.labels)

            def __getitem__(self, idx):
                item = {key: val[idx] for key, val in self.encodings.items()}
                item["labels"] = self.labels[idx]
                return item

        # Prepare datasets
        print("Preparing datasets...")
        train_dataset = IncidentDataset(train_encodings, torch.tensor(y_train_encoded))
        test_dataset = IncidentDataset(test_encodings, torch.tensor(y_test_encoded))

        # Load pre-trained model
        print("Loading pre-trained model...")
        model = DistilBertForSequenceClassification.from_pretrained(
            "distilbert-base-uncased", num_labels=len(label_encoder.classes_)
        )

        # Training arguments
        print("Setting up training arguments...")
        # training_args = TrainingArguments(
        #     output_dir="./incident_model",
        #     eval_strategy="epoch",
        #     save_strategy="epoch",
        #     learning_rate=2e-5,
        #     per_device_train_batch_size=8,
        #     per_device_eval_batch_size=8,
        #     num_train_epochs=1,
        #     weight_decay=0.01,
        #     logging_dir="./logs_incident",
        #     logging_steps=10,
        #     fp16=True,  # Mixed precision
        #     load_best_model_at_end=True,
        # )
        training_args = TrainingArguments(
            output_dir="./incident_model",
            evaluation_strategy="epoch",
            save_strategy="epoch",
            logging_dir="./logs",
            logging_steps=10,
            per_device_train_batch_size=16,  # Larger batch size
            per_device_eval_batch_size=16,
            num_train_epochs=1,  # Reduce epochs
            gradient_accumulation_steps=4,  # Simulate larger batch size
            fp16=True,  # Mixed precision
            load_best_model_at_end=True,
            metric_for_best_model="accuracy",
        )

        # Trainer
        print("Initializing trainer...")
        trainer = Trainer(
            model=model,
            args=training_args,
            train_dataset=train_dataset,
            eval_dataset=test_dataset,
            tokenizer=tokenizer,
        )

        # Train and save the model
        print("Training the model...")
        trainer.train()

        print("Saving the fine-tuned model...")
        model.save_pretrained("./incident_model")
        tokenizer.save_pretrained("./incident_model")

        print("Fine-tuning complete. Model and tokenizer saved to './incident_model'.")
