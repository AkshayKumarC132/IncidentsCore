import pandas as pd
from transformers import DistilBertTokenizer, DistilBertForSequenceClassification, Trainer, TrainingArguments
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score
from torch.utils.data import Dataset
import torch
import joblib
import os

# Load data (replace with actual database queries)
def load_data():
    from core.models import JiraTicket  # Update with actual app name
    tickets = JiraTicket.objects.all().values('summary', 'description', 'predicted_category')
    df = pd.DataFrame(tickets)
    df['text'] = df['summary'] + " " + df['description']
    df = df.dropna(subset=['predicted_category'])
    return df

data = load_data()
X = data['text']
y = data['predicted_category']

# Encode labels
label_encoder = LabelEncoder()
y_encoded = label_encoder.fit_transform(y)

# Save label encoder
output_dir = "./jira_model"
if not os.path.exists(output_dir):
    os.makedirs(output_dir)
joblib.dump(label_encoder, os.path.join(output_dir, "label_encoder.pkl"))

# Split data
X_train, X_test, y_train, y_test = train_test_split(X, y_encoded, test_size=0.2, random_state=42)

# Tokenize
tokenizer = DistilBertTokenizer.from_pretrained("distilbert-base-uncased")
train_encodings = tokenizer(X_train.tolist(), truncation=True, padding=True, max_length=512, return_tensors="pt")
test_encodings = tokenizer(X_test.tolist(), truncation=True, padding=True, max_length=512, return_tensors="pt")

# Dataset
class JiraDataset(Dataset):
    def __init__(self, encodings, labels):
        self.encodings = encodings
        self.labels = labels

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, idx):
        # Combine input encodings and labels into a single dictionary
        item = {key: val[idx] for key, val in self.encodings.items()}
        item["labels"] = self.labels[idx]
        return item

train_dataset = JiraDataset(train_encodings, torch.tensor(y_train))
test_dataset = JiraDataset(test_encodings, torch.tensor(y_test))

# Define compute_metrics function
def compute_metrics(pred):
    """
    Custom evaluation metrics for accuracy.
    """
    predictions, labels = pred
    predictions = predictions.argmax(axis=-1)  # Get predicted classes
    acc = accuracy_score(labels, predictions)  # Calculate accuracy
    return {"accuracy": acc}  # Match key to metric_for_best_model

# Model and Trainer
model = DistilBertForSequenceClassification.from_pretrained("distilbert-base-uncased", num_labels=len(label_encoder.classes_))

training_args = TrainingArguments(
    output_dir="./jira_model",
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
    metric_for_best_model="accuracy",  # Match the key in compute_metrics
    greater_is_better=True,  # Specify that higher accuracy is better
)

trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=train_dataset,
    eval_dataset=test_dataset,
    tokenizer=tokenizer,
    compute_metrics=compute_metrics,  # Include custom metrics
)

# Train and Save
trainer.train()
model.save_pretrained("./model")
tokenizer.save_pretrained("./model")
