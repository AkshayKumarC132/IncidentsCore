from django.utils.deprecation import MiddlewareMixin

class LogHeadersMiddleware(MiddlewareMixin):
    def process_request(self, request):
        print(request.headers)
        return None