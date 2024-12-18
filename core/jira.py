from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch

# Load the fine-tuned model and tokenizer
model_path = "jira_model"
tokenizer = AutoTokenizer.from_pretrained(model_path)
model = AutoModelForSequenceClassification.from_pretrained(model_path)

def predict_agent(ticket_summary, ticket_description):
    text = f"{ticket_summary} {ticket_description}"
    inputs = tokenizer(text, return_tensors="pt", truncation=True, padding=True, max_length=512)
    outputs = model(**inputs)
    logits = outputs.logits
    predicted_class = torch.argmax(logits, dim=1).item()
    confidence_score = torch.softmax(logits, dim=1).max().item() * 100
    return predicted_class, confidence_score

# Update JiraTicket records
from core.models import JiraTicket

def update_predictions():
    tickets = JiraTicket.objects.filter(id__lt = 610)  # Only predict for unclassified tickets

    for ticket in tickets:
        predicted_class, confidence = predict_agent(ticket.summary, ticket.description)
        ticket.predicted_agent = predicted_class
        ticket.confidence_score = confidence
        ticket.save()
        print(f"Updated Ticket {ticket.issue_key} with Agent {predicted_class} and Confidence {confidence:.2f}%")

# update_predictions()