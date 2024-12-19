from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import ModelManagement
from django.core.files.storage import default_storage
import os
from django.db import IntegrityError

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


@csrf_exempt
def edit_model(request, model_id):
    if request.method == 'PATCH':
        try:
            model = ModelManagement.objects.get(id=model_id)
            params = request.POST.get('parameters', '{}')
            model.parameters = params
            model.save()
            return JsonResponse({'message': f"Model {model.name} updated successfully."})
        except ModelManagement.DoesNotExist:
            return JsonResponse({'error': 'Model not found'}, status=404)

    return JsonResponse({'error': 'Invalid request method'}, status=400)

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