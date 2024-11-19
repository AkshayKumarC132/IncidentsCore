from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from core.models import Incident, Notification,UserProfile,TicketHistory
from django.utils import timezone

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def assign_ticket_to_agent(request):
    try:
        incident_id = request.data.get('incident_id')
        incident = Incident.objects.get(id=incident_id, resolved=False)
        agents = UserProfile.objects.filter(role='human_agent')

        if not agents.exists():
            return Response({"error": "No human agents available."}, status=400)

        # Assign to least busy agent
        least_busy_agent = sorted(agents, key=lambda agent: agent.assigned_incidents.count())[0]
        incident.assigned_agent = least_busy_agent
        incident.assigned_at = timezone.now()
        incident.save()

        # Create notification
        Notification.objects.create(
            user=least_busy_agent,
            message=f"New ticket assigned: {incident.title}"
        )

        # Log the action
        TicketHistory.objects.create(
            incident=incident,
            action="Assigned to human agent",
            performed_by=None  # System action
        )

        return Response({"status": "success", "message": f"Ticket assigned to {least_busy_agent.username}"})

    except Incident.DoesNotExist:
        return Response({"error": "Incident not found or already resolved."}, status=404)
    except Exception as e:
        return Response({"error": str(e)}, status=500)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_assigned_tickets(request):
    user = request.user
    if user.role != 'human_agent':
        return Response({"error": "Unauthorized access."}, status=403)

    # tickets = Incident.objects.filter(human_intervention_needed=True, resolved=False)
    tickets = Incident.objects.filter(
                device__client__msp__user=user,
                human_intervention_needed=True,
                resolved=False
            )
    ticket_data = [
        {
            'id': ticket.id,
            'title': ticket.title,
            'description': ticket.description,
            'severity': ticket.severity.level,
            'assigned_at': ticket.assigned_at,
        } for ticket in tickets
    ]

    return Response(ticket_data)