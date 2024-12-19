import os
import joblib
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from incidentmanagement import settings
from django.core.files.storage import default_storage
from .the_new import token_verification
from core.models import JiraTicket, Incident, UserProfile, ActiveModel
from rest_framework.response import Response
from rest_framework import status
import shutil
from django.utils.timezone import now
import json
from rest_framework.decorators import api_view

MODEL_DIR = os.path.join(settings.BASE_DIR, "trained_models")


@api_view(['POST'])
@csrf_exempt
def upload_model(request, token):
    """
    Upload and replace model files for Jira or Incident Models.
    """
    if not token:
        return Response({"error": "Token is required"}, status=status.HTTP_400_BAD_REQUEST)

    # Validate user from token
    user = token_verification(token)
    if user['status'] != 200:
        return Response({'message': user['error']}, status=status.HTTP_400_BAD_REQUEST)
    
    if user['user'].role not in ['admin', 'gl']:  # Only 'admin' and 'gl' roles allowed
        return Response({"error": "Access Denied"}, status=status.HTTP_403_FORBIDDEN)

    try:
        model_type = request.data.get("model_type")  # 'jira' or 'incident'
        file = request.FILES.get("file")

        if not file or not model_type:
            return Response({"error": "Model type and file are required."}, status=status.HTTP_400_BAD_REQUEST)

        # Sanitize file name
        file_name = os.path.basename(file.name)
        model_path = os.path.join(MODEL_DIR, file_name)
        
        # Create models directory if it doesn't exist
        os.makedirs(MODEL_DIR, exist_ok=True)
        
        # Save file directly using file system operations instead of default_storage
        try:
            with open(model_path, 'wb+') as dest:
                for chunk in file.chunks():
                    dest.write(chunk)
            return Response({"message": f"{file_name} successfully uploaded."}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": f"Failed to upload: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@csrf_exempt
def list_models(request, token):
    """
    List all models currently available.
    """
    if not token:
        return Response({"error": "Token is required"}, status=status.HTTP_400_BAD_REQUEST)

    # Validate user from token
    user = token_verification(token)
    if user['status'] != 200:
        return Response({'message': user['error']}, status=status.HTTP_400_BAD_REQUEST)
    
    if user['user'].role not in ['admin', 'gl', 'msp_superuser']:  # Only 'admin', 'gl', and 'msp_superuser' roles allowed
        return Response({"error": "Access Denied"}, status=status.HTTP_403_FORBIDDEN)

    try:
        models = []
        active_models = {m.model_type: m.model_name for m in ActiveModel.objects.all()}

        for file_name in os.listdir(MODEL_DIR):
            file_path = os.path.join(MODEL_DIR, file_name)
            model_type = "jira" if "jira" in file_name else "incident"
            is_active = active_models.get(model_type) == file_name

            models.append({
                "name": file_name,
                "size": os.path.getsize(file_path) // 1024,  # KB
                "uploaded_at": now().strftime('%Y-%m-%d %H:%M:%S'),
                "is_active": is_active
            })

        return Response({"models": models}, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@csrf_exempt
def delete_model(request, token):
    """
    Delete a specific model.
    """
    if not token:
        return Response({"error": "Token is required"}, status=status.HTTP_400_BAD_REQUEST)

    # Validate user from token
    user = token_verification(token)
    if user['status'] != 200:
        return Response({'message': user['error']}, status=status.HTTP_400_BAD_REQUEST)
    
    if user['user'].role not in ['admin', 'gl']:  # Only 'admin' and 'gl' roles allowed
        return Response({"error": "Access Denied"}, status=status.HTTP_403_FORBIDDEN)

    try:
        model_name = request.data.get("model_name")

        if not model_name:
            return Response({"error": "Model name is required."}, status=status.HTTP_400_BAD_REQUEST)

        model_path = os.path.join(MODEL_DIR, model_name)

        if os.path.exists(model_path):
            os.remove(model_path)
            return Response({"message": f"{model_name} deleted successfully."}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Model file not found."}, status=status.HTTP_404_NOT_FOUND)

    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@csrf_exempt
def set_active_model(request, token):
    """
    Set a model as active.
    """
    if not token:
        return Response({"error": "Token is required"}, status=status.HTTP_400_BAD_REQUEST)

    # Validate user from token
    user = token_verification(token)
    if user['status'] != 200:
        return Response({'message': user['error']}, status=status.HTTP_400_BAD_REQUEST)
    
    if user['user'].role not in ['admin', 'gl']:  # Only 'admin' and 'gl' roles allowed
        return Response({"error": "Access Denied"}, status=status.HTTP_403_FORBIDDEN)

    try:
        data = request.data
        model_name = data.get("model_name")
        model_type = data.get("model_type")

        if not model_name or not model_type:
            return Response({"error": "Both model_name and model_type are required."}, status=status.HTTP_400_BAD_REQUEST)

        # Update the active model in the database
        ActiveModel.objects.update_or_create(
            user=user['user'],
            model_type=model_type,
            defaults={"model_name": model_name, "activated_at": now()}
        )
        return Response({"message": f"Model {model_name} set as active."}, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@csrf_exempt
def edit_model_parameters(request, model_name):
    """
    Edit and update existing model parameters dynamically.
    """
    try:
        updated_params = request.data
        file_path = os.path.join(MODEL_DIR, model_name)

        if not os.path.exists(file_path):
            return Response({"error": "Model not found"}, status=status.HTTP_404_NOT_FOUND)

        # Load the existing model
        model = joblib.load(file_path)
        
        # Check for valid parameters
        valid_params = model.get_params()  # Fetch valid params for the model
        invalid_params = [key for key in updated_params if key not in valid_params]

        if invalid_params:
            return Response({
                "error": f"Invalid parameters: {invalid_params}. "
                         f"Valid parameters are: {list(valid_params.keys())}"
            }, status=status.HTTP_400_BAD_REQUEST)

        # Update and save the model with new parameters
        model.set_params(**updated_params)
        joblib.dump(model, file_path)

        return Response({"message": f"Parameters updated for {model_name}"}, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
