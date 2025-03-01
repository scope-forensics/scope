from django.contrib import admin
from .models import AzureAccount, AzureResource, AzureLogSource, AzureIdentity

admin.site.register(AzureAccount)
admin.site.register(AzureResource)
admin.site.register(AzureLogSource)
admin.site.register(AzureIdentity)

# Register your models here.
