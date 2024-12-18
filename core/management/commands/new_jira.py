from transformers import Trainer, TrainingArguments
from transformers import AutoModelForSequenceClassification, AutoTokenizer
import pandas as pd
from core.models import JiraTicket  # Update with actual app name
from django.core.management.base import BaseCommand
from datasets import Dataset
import logging

class Command(BaseCommand):
    help = 'Train a sequence classification model using Jira ticket data.'

    def handle(self, *args, **options):
        """
        Main entry point for the custom Django management command.
        """
        self.stdout.write(self.style.NOTICE("Starting the training process..."))

        try:
            # Load and preprocess the dataset
            dataset = self.load_data()
            # Check if 'train' and 'validation' exist
            if 'train' not in dataset or 'validation' not in dataset:
                raise ValueError("The dataset does not have the required 'train' and 'validation' splits.")
            self.stdout.write(self.style.SUCCESS("Dataset loaded and preprocessed."))

            # Initialize tokenizer and model
            tokenizer = AutoTokenizer.from_pretrained('distilbert-base-uncased')
            model = AutoModelForSequenceClassification.from_pretrained(
                'distilbert-base-uncased', num_labels=5
            )
            self.stdout.write(self.style.SUCCESS("Tokenizer and model initialized."))

            # Tokenize the dataset
            encoded_dataset = self.tokenize_dataset(dataset, tokenizer)
            self.stdout.write(self.style.SUCCESS("Dataset tokenized."))

            # Define training arguments
            training_args = self.get_training_arguments()

            # Setup the Trainer
            trainer = Trainer(
                model=model,
                args=training_args,
                train_dataset=encoded_dataset["train"],
                eval_dataset=encoded_dataset["validation"],
                tokenizer=tokenizer,
            )
            self.stdout.write(self.style.SUCCESS("Trainer setup completed."))

            # Start training
            trainer.train()
            self.stdout.write(self.style.SUCCESS("Training completed successfully."))

        except Exception as e:
            logging.exception("An error occurred during training:")
            self.stderr.write(self.style.ERROR(f"Error: {e}"))

    def load_data():
        """
        Load data from the JiraTicket model, preprocess it, and return a Dataset object.
        """
        tickets = JiraTicket.objects.all().values('summary', 'description', 'predicted_category')
        df = pd.DataFrame(tickets)
        df['text'] = df['summary'] + " " + df['description']
        df = df.dropna(subset=['predicted_category'])
        
        # Convert DataFrame to Hugging Face Dataset
        dataset = Dataset.from_pandas(df[['text', 'predicted_category']])
        
        # Ensure a train-test split
        if len(dataset) > 1:  # Check that the dataset has enough samples
            dataset = dataset.train_test_split(test_size=0.2)
            print("Dataset successfully split into train and validation.")
            return dataset
        else:
            raise ValueError("Not enough data to split into train and validation sets.")

    def tokenize_dataset(self, dataset, tokenizer):
        """
        Tokenize the text data in the dataset.
        """
        self.stdout.write("Tokenizing the dataset...")
        def preprocess_function(examples):
            return tokenizer(examples["text"], truncation=True, padding=True, max_length=128)

        return dataset.map(preprocess_function, batched=True)

    def get_training_arguments(self):
        """
        Define and return the training arguments for the Trainer.
        """
        self.stdout.write("Setting up training arguments...")
        return TrainingArguments(
            output_dir="./results",
            evaluation_strategy="epoch",
            save_strategy="epoch",
            per_device_train_batch_size=4,  # Lower batch size to fit in memory
            gradient_accumulation_steps=8,  # Simulate a larger batch size
            num_train_epochs=3,
            fp16=True,  # Enable mixed precision training
            save_total_limit=2,  # Save only the last 2 checkpoints
            load_best_model_at_end=True,
            metric_for_best_model="accuracy",  # Specify a valid metric
            logging_dir='./logs',
            logging_steps=50
        )
