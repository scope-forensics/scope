from django.contrib import admin
from .models import NormalizedLog, Tag, DetectionResult

# Register your models here.

admin.site.register(NormalizedLog)
admin.site.register(Tag)
admin.site.register(DetectionResult)
