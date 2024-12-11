import torch
from transformers import DistilBertTokenizer, DistilBertForSequenceClassification, Trainer, TrainingArguments
from sklearn.preprocessing import LabelEncoder
from torch.utils.data import Dataset
import joblib

class JiraDataset(Dataset):
    def __init__(self, texts, labels, tokenizer):
        self.texts = texts
        self.labels = labels
        self.tokenizer = tokenizer

    def __len__(self):
        return len(self.texts)

    def __getitem__(self, idx):
        text = self.texts[idx]
        label = self.labels[idx]
        encoding = self.tokenizer(
            text,
            truncation=True,
            padding="max_length",
            max_length=512,
            return_tensors="pt",
        )
        return {key: val.squeeze(0) for key, val in encoding.items()}, torch.tensor(label)

def train_model(X_train, y_train, X_test, y_test):
    """
    Train a DistilBERT model on the provided training and test datasets.
    """
    tokenizer = DistilBertTokenizer.from_pretrained("distilbert-base-uncased")

    # Encode labels
    label_encoder = LabelEncoder()
    y_train_encoded = label_encoder.fit_transform(y_train)
    y_test_encoded = label_encoder.transform(y_test)

    # Create datasets
    train_dataset = JiraDataset(X_train.tolist(), y_train_encoded, tokenizer)
    test_dataset = JiraDataset(X_test.tolist(), y_test_encoded, tokenizer)

    # Load the model
    model = DistilBertForSequenceClassification.from_pretrained(
        "distilbert-base-uncased", num_labels=len(label_encoder.classes_)
    )

    # Training arguments
    training_args = TrainingArguments(
        output_dir="./jira_model",
        evaluation_strategy="epoch",
        save_strategy="epoch",
        learning_rate=2e-5,
        per_device_train_batch_size=8,
        per_device_eval_batch_size=8,
        num_train_epochs=5,
        weight_decay=0.01,
        logging_dir="./logs",
        logging_steps=10,
        load_best_model_at_end=True,
    )

    # Trainer
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=test_dataset,
        tokenizer=tokenizer,
    )

    # Train the model
    trainer.train()

    return model, tokenizer, label_encoder

def save_model_and_tokenizer(model, tokenizer, label_encoder, output_dir):
    """
    Save the trained model, tokenizer, and label encoder to the specified directory.
    """
    model.save_pretrained(output_dir)
    tokenizer.save_pretrained(output_dir)
    joblib.dump(label_encoder, f"{output_dir}/label_encoder.pkl")
