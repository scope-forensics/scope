from django.urls import path
from django.views.generic import TemplateView

from . import views

app_name = 'data'

urlpatterns = [
    path('logs/', views.NormalizedLogListView, name='normalized_logs'),
    path('logs/<int:log_id>/add-tag/', views.add_tag_to_log, name='add_tag_to_log'),
    path('logs/<int:log_id>/edit-tag/<int:tag_id>/', views.edit_log_tag, name='edit_log_tag'),
    path('logs/<int:log_id>/remove-tag/<int:tag_id>/', views.remove_log_tag, name='remove_log_tag'),
] 