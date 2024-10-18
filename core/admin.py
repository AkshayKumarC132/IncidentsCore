from django.contrib import admin
from .models import *

# Register your models here.
admin.site.register(UserProfile)
admin.site.register(IntegrationType)
admin.site.register(IntegrationMSPConfig)
admin.site.register(Client)
admin.site.register(Device)
admin.site.register(Severity)
admin.site.register(Incident)
admin.site.register(AgentType)
admin.site.register(Agent)
admin.site.register(Task)