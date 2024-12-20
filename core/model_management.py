from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import ModelManagement
from django.core.files.storage import default_storage
import os
from django.db import IntegrityError
from rest_framework.parsers import JSONParser
import joblib
from rest_framework.decorators import api_view

@csrf_exempt
def upload_model(request):
    if request.method == 'POST':
        model_file = request.FILES.get('file')
        print(model_file)
        if not model_file:
            return JsonResponse({'error': 'No file uploaded'}, status=400)

        model_name = request.POST.get('name', model_file.name)
        size = model_file.size / 1024  # Convert bytes to KB

        try:
            model = ModelManagement.objects.create(
                name=model_name,
                file=model_file,
                size=size,
                status="inactive"
            )
            return JsonResponse({'message': f"Model {model_name} uploaded successfully.", "model_id": model.id})
        
        except IntegrityError:
            return JsonResponse({'error': f"A model with the name '{model_name}' already exists."}, status=400)

    return JsonResponse({'error': 'Invalid request method'}, status=400)

@csrf_exempt
def set_active_model(request, model_id):
    if request.method == 'PATCH':
        try:
            model = ModelManagement.objects.get(id=model_id)
            # Deactivate all other models
            ModelManagement.objects.update(status='inactive')
            # Activate this model
            model.status = 'active'
            model.save()
            return JsonResponse({'message': f"Model {model.name} is now active."})
        except ModelManagement.DoesNotExist:
            return JsonResponse({'error': 'Model not found'}, status=404)

    return JsonResponse({'error': 'Invalid request method'}, status=400)


@csrf_exempt
def delete_model(request, model_id):
    if request.method == 'DELETE':
        try:
            model = ModelManagement.objects.get(id=model_id)
            file_path = model.file.path
            model.delete()
            # Delete the actual file
            if os.path.exists(file_path):
                os.remove(file_path)
            return JsonResponse({'message': f"Model {model.name} deleted successfully."})
        except ModelManagement.DoesNotExist:
            return JsonResponse({'error': 'Model not found'}, status=404)

    return JsonResponse({'error': 'Invalid request method'}, status=400)


@api_view(['POST'])
@csrf_exempt
def edit_model(request, model_name):
    """
    Edit an existing model's parameters.
    """
    try:
        get_model = ModelManagement.objects.get(name=model_name)
    except ModelManagement.DoesNotExist:
            return JsonResponse({'error': 'Model not found'}, status=404)

    try:
        data = JSONParser().parse(request)
        model_path = f"models/{model_name}"

        # Load the model
        model = joblib.load(model_path)

        # Check for valid parameters
        for param, value in data.items():
            if hasattr(model, param):
                setattr(model, param, value)
            else:
                return JsonResponse({"error": f"Invalid parameter '{param}' for model {model_name}."}, status=400)

        # Save the updated model
        joblib.dump(model, model_path)
        get_model.parameters = data
        get_model.save()
        return JsonResponse({"message": f"Model '{model_name}' updated successfully."}, status=200)
    except FileNotFoundError:
        return JsonResponse({"error": f"Model '{model_name}' not found."}, status=404)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)


def fetch_models(request):
    """
    Fetch all the models from the database.
    """
    if request.method == 'GET':
        models = ModelManagement.objects.all()
        data = [
            {
                'id': model.id,
                'name': model.name,
                'size': model.size,
                'status': model.status,
                'parameters': model.parameters,
                'uploaded_at': model.uploaded_at,
            }
            for model in models
        ]
        return JsonResponse({'models': data}, safe=False)

    return JsonResponse({'error': 'Invalid request method'}, status=400)