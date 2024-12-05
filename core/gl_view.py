from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.core.paginator import Paginator
from django.db.models import Q
from django.utils.timezone import now
from .models import UserProfile, Incident, ScreenRecording
from django.contrib.sessions.models import Session
from .the_new import token_verification
from rest_framework.decorators import api_view
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator

class GLDashboardView(APIView):
    """
    API View to display comprehensive dashboard data for users with GL access,
    including role assignment, pagination, and search filters.
    """
    def get(self, request, token):
        # Verify token and get user
        user_response = token_verification(token)
        if user_response['status'] == 200:
            user = user_response['user']
        else:
            return Response({'message': user_response['error']}, status=status.HTTP_400_BAD_REQUEST)
        
        # Ensure the logged-in user has GL access
        if user.role != "gl":
            return Response({"error": "Access denied: Only GL users can access this dashboard"}, status=403)

        # Fetch query parameters for search and pagination
        search_query = request.GET.get('search', '')
        page_number = int(request.GET.get('page', 1))
        page_size = int(request.GET.get('page_size', 10))

        # Filter users based on search query
        users = UserProfile.objects.filter(
            Q(name__icontains=search_query) |
            Q(email__icontains=search_query) |
            Q(role__icontains=search_query)
        ).order_by('id')

        # Paginate users
        paginator = Paginator(users, page_size)
        paginated_users = paginator.get_page(page_number)

        # Construct user data with role assignment option
        user_data = [
            {
                "id": user.id,
                "name": user.name,
                "email": user.email,
                "role": user.role,
                "is_active": user.is_active,
                "created_at": user.created_at,
                "updated_at": user.updated_at,
            }
            for user in paginated_users
        ]

        # Fetch login history
        sessions = Session.objects.filter(expire_date__gte=now())
        active_sessions = [
            {
                "session_key": session.session_key,
                "user_id": session.get_decoded().get("_auth_user_id"),
                "start_time": session.get_decoded().get("start_time"),
            }
            for session in sessions
        ]

        # Fetch incidents
        all_incidents = Incident.objects.all()
        active_incidents = all_incidents.filter(resolved=False)
        resolved_incidents = all_incidents.filter(resolved=True)

        # Fetch videos
        recorded_videos = ScreenRecording.objects.all()  # Assuming a VideoRecording model exists

        # Construct response data
        data = {
            "users": {
                "total_users": users.count(),
                "current_page": page_number,
                "total_pages": paginator.num_pages,
                "results": user_data,
            },
            "search_query": search_query,
            "sessions": {
                "total_sessions": sessions.count(),
                "active_sessions": len(active_sessions),
                "details": active_sessions,
            },
            "incidents": {
                "total_incidents": all_incidents.count(),
                "active_incidents": active_incidents.count(),
                "resolved_incidents": resolved_incidents.count(),
            },
            "videos": {
                "total_recorded_videos": recorded_videos.count(),
                "video_details": [{"id": video.id, "file_path": video.file_path} for video in recorded_videos],
            },
        }

        return Response(data, status=200)

@method_decorator(csrf_exempt, name='dispatch')
class UpdateUserRoleAPIView(APIView):
    """
    API View to update the role of a user using token verification.
    """

    def post(self, request, token):
        # Get token from URL parameters
        # token = request.GET.get('token')
        if not token:
            return Response({"error": "Token is required"}, status=400)

        # Verify the token
        token_verification_result = token_verification(token)
        if token_verification_result['status'] != 200:
            return Response({"error": token_verification_result['error']}, status=400)
        print(token_verification_result)
        requesting_user = token_verification_result['user']
        print(requesting_user)

        # Check if the requesting user has the required role
        if requesting_user.role != "gl":
            return Response({"error": "Access denied: Only GL users can assign roles"}, status=403)

        # Get and validate the request data
        user_id = request.data.get('user_id')
        new_role = request.data.get('role')

        if not user_id or not new_role:
            return Response({"error": "user_id and role are required"}, status=400)

        try:
            user = UserProfile.objects.get(id=user_id)

            # Validate the new role
            if new_role not in [role[0] for role in UserProfile.ROLE_CHOICES]:
                return Response({"error": "Invalid role"}, status=400)

            # Update the user's role
            user.role = new_role
            user.save()

            return Response({"message": f"Role updated to {new_role} for user {user.name}"}, status=200)

        except UserProfile.DoesNotExist:
            return Response({"error": "User not found"}, status=404)