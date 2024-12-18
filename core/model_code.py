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

MODEL_DIR = os.path.join(settings.BASE_DIR, "trained_models")

@csrf_exempt
# @admin_required
def upload_model(request, token):
    if not token:
            return Response({"error": "Token is required"}, status=status.HTTP_400_BAD_REQUEST)
    # Validate user from token
    user = token_verification(token)
    if user['status'] != 200:
        return Response({'message': user['error']}, status=status.HTTP_400_BAD_REQUEST)
    
    if user['user'].role not in ['admin','gl']: # ['admin', 'msp_superuser', 'msp_user','gl'
        return Response({"error": "Access Denied"}, status=403)

    """
    Upload and replace model files for Jira or Incident Models.
    """
    try:
        if request.method == "POST":
            model_type = request.POST.get("model_type")  # 'jira' or 'incident'
            file = request.FILES.get("file")

            if not file or not model_type:
                return JsonResponse({"error": "Model type and file are required."}, status=400)

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
                return JsonResponse({"message": f"{file_name} successfully uploaded."}, status=200)
            except Exception as e:
                return JsonResponse({"error": f"Failed to upload: {str(e)}"}, status=500)

        return JsonResponse({"error": "Invalid request method."}, status=405)
    except Exception as e:
        print("^^^^^^", e)
        return JsonResponse({"message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@csrf_exempt
# @admin_required
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
    
    if user['user'].role not in ['admin','gl']: # ['admin', 'msp_superuser', 'msp_user','gl'
        return Response({"error": "Access Denied"}, status=403)
    
    if request.method == "GET":
        models = []
        active_models = {m.model_type: m.model_name for m in ActiveModel.objects.all()}

        try:
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
            return JsonResponse({"models": models}, status=200)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    return JsonResponse({"error": "Invalid request method."}, status=405)


@csrf_exempt
def delete_model(request, token):

    if not token:
        return Response({"error": "Token is required"}, status=status.HTTP_400_BAD_REQUEST)

    # Validate user from token
    user = token_verification(token)
    if user['status'] != 200:
        return Response({'message': user['error']}, status=status.HTTP_400_BAD_REQUEST)
    
    if user['user'].role not in ['admin','gl']: # ['admin', 'msp_superuser', 'msp_user','gl'
        return Response({"error": "Access Denied"}, status=403)
    """
    Delete a specific model.
    """
    if request.method == "POST":
        model_name = request.POST.get("model_name")

        if not model_name:
            return JsonResponse({"error": "Model name is required."}, status=400)

        model_path = os.path.join(MODEL_DIR, model_name)

        if os.path.exists(model_path):
            os.remove(model_path)
            return JsonResponse({"message": f"{model_name} deleted successfully."}, status=200)
        else:
            return JsonResponse({"error": "Model file not found."}, status=404)

    return JsonResponse({"error": "Invalid request method."}, status=405)

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
    
    if user['user'].role not in ['admin','gl']: # ['admin', 'msp_superuser', 'msp_user','gl'
        return Response({"error": "Access Denied"}, status=status.HTTP_403_FORBIDDEN)
    
    if request.method == "POST":
        # Parse JSON payload
        
        data = json.loads(request.body.decode('utf-8'))
        model_name = data.get("model_name")
        model_type = data.get("model_type")

        if not model_name or not model_type:
            return JsonResponse({"error": "Both model_name and model_type are required."}, status=status.HTTP_400_BAD_REQUEST)

        # Update the active model in the database
        ActiveModel.objects.update_or_create(
            user = user['user'],
            model_type=model_type,
            defaults={"model_name": model_name, "activated_at": now()}
        )
        return JsonResponse({"message": f"Model {model_name} set as active."}, status=status.HTTP_200_OK)
    return JsonResponse({"error": "Invalid request."}, status=status.HTTP_400_BAD_REQUEST)



@csrf_exempt
def edit_model_parameters(request, model_name):
    """
    Edit and update existing model parameters dynamically.
    """
    try:
        updated_params = json.loads(request.body)
        file_path = os.path.join(MODEL_DIR, model_name)

        if not os.path.exists(file_path):
            return JsonResponse({"error": "Model not found"}, status=404)

        # Load the existing model
        model = joblib.load(file_path)
        
        # Check for valid parameters
        valid_params = model.get_params()  # Fetch valid params for the model
        invalid_params = [key for key in updated_params if key not in valid_params]

        if invalid_params:
            return JsonResponse({
                "error": f"Invalid parameters: {invalid_params}. "
                         f"Valid parameters are: {list(valid_params.keys())}"
            }, status=400)

        # Update and save the model with new parameters
        model.set_params(**updated_params)
        joblib.dump(model, file_path)

        return JsonResponse({"message": f"Parameters updated for {model_name}"}, status=200)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=400)