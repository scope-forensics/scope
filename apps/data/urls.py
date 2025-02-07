from django.urls import path
from django.views.generic import TemplateView

from . import views

app_name = 'data'

urlpatterns = [
    path("logs", views.NormalizedLogListView, name="normalized_logs"),
] 