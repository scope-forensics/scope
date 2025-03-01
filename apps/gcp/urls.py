from django.urls import path
from . import views

app_name = "gcp"

urlpatterns = [
    path('<slug:slug>/connect/gcp/', views.connect_gcp, name='connect_gcp'),
    path('accounts/<str:project_id>/edit/', views.edit_account, name='edit_account'),
    path('accounts/<str:project_id>/delete/', views.delete_account, name='delete_account'),
    path('accounts/<str:project_id>/resources/', views.account_resources, name='account_resources'),
    path('accounts/<str:project_id>/logs/', views.normalized_logs, name='normalized_logs'),
    path('accounts/<str:project_id>/pull-resources/', views.pull_resources, name='pull_resources'),
    
    # Tag management URLs
    path('resources/<int:resource_id>/tags/add/', views.add_tag_to_resource, name='add_tag_to_resource'),
    path('resources/<int:resource_id>/tags/<int:tag_id>/edit/', views.edit_resource_tag, name='edit_resource_tag'),
    path('resources/<int:resource_id>/tags/<int:tag_id>/remove/', views.remove_tag_from_resource, name='remove_tag_from_resource'),
    path('logsources/<int:logsource_id>/tags/add/', views.add_tag_to_logsource, name='add_tag_to_logsource'),
    path('logsources/<int:logsource_id>/tags/<int:tag_id>/edit/', views.edit_logsource_tag, name='edit_logsource_tag'),
    path('logsources/<int:logsource_id>/tags/<int:tag_id>/remove/', views.remove_tag_from_logsource, name='remove_tag_from_logsource'),
    path('resources/<slug:slug>/', views.resource_details, name='resource_details'),
    path('logsources/<int:logsource_id>/', views.logsource_details, name='logsource_details'),
] 