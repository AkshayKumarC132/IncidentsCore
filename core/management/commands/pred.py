from django.core.management.base import BaseCommand
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch
from core.models import JiraTicket

class Command(BaseCommand):
    help = 'Update JiraTicket records with predicted agent and confidence score.'

    def __init__(self):
        super().__init__()
        # Load the fine-tuned model and tokenizer
        model_path = "jira_model"
        self.tokenizer = AutoTokenizer.from_pretrained(model_path)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_path)

    def predict_agent(self, ticket_summary, ticket_description):
        text = f"{ticket_summary} {ticket_description}"
        inputs = self.tokenizer(text, return_tensors="pt", truncation=True, padding=True, max_length=512)
        outputs = self.model(**inputs)
        logits = outputs.logits
        predicted_class = torch.argmax(logits, dim=1).item()
        confidence_score = torch.softmax(logits, dim=1).max().item() * 100
        return predicted_class, confidence_score

    def handle(self, *args, **kwargs):
        tickets = JiraTicket.objects.filter(id__lt=610)  # Only predict for unclassified tickets

        for ticket in tickets:
            predicted_class, confidence = self.predict_agent(ticket.summary, ticket.description)
            ticket.predicted_agent = predicted_class
            ticket.confidence_score = confidence
            ticket.save()
            self.stdout.write(self.style.SUCCESS(f"Updated Ticket {ticket.issue_key} with Agent {predicted_class} and Confidence {confidence:.2f}%"))