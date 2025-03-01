from django.urls import path
from django.views.generic import TemplateView

from . import views

app_name = "azure"

urlpatterns = [
    # Basic account management
    path('<slug:slug>/connect/azure/', views.connect_azure, name='connect_azure'),
    path('accounts/<str:subscription_id>/edit/', views.edit_account, name='edit_account'),
    path('accounts/<str:subscription_id>/delete/', views.delete_account, name='delete_account'),
    
    # Resource management
    path('accounts/<str:subscription_id>/pull-resources/', views.pull_resources_view, name='pull_resources'),
    path('resource/<slug:slug>/details/', views.azure_resource_details, name='azure_resource_details'),
    path('accounts/<str:subscription_id>/account-resources/', views.account_resources, name='account_resources'),
    
    # Log sources and activity logs
    path('logsource/<slug:slug>/details/', views.azure_logsource_details, name='azure_logsource_details'),
    path('accounts/<str:subscription_id>/fetch-activity-logs/', views.trigger_activity_log_fetch, name='fetch_activity_logs'),
    path('accounts/<str:subscription_id>/logs/', views.normalized_logs_view, name='normalized_logs'),
    
    # Identity management
    path('identity/<slug:slug>/', views.azure_identity_details, name='azure_identity_details'),
    
    # Tag management for resources
    path('resources/<int:resource_id>/add-tag/', views.add_tag_to_resource, name='add_tag_to_resource'),
    path('resources/<int:resource_id>/edit-tag/<int:tag_id>/', views.edit_resource_tag, name='edit_resource_tag'),
    path('resources/<int:resource_id>/remove-tag/<int:tag_id>/', views.remove_tag_from_resource, name='remove_tag_from_resource'),
    
    # Tag management for identities
    path('identities/<int:identity_id>/add-tag/', views.add_tag_to_identity, name='add_tag_to_identity'),
    path('identities/<int:identity_id>/edit-tag/<int:tag_id>/', views.edit_identity_tag, name='edit_identity_tag'),
    path('identities/<int:identity_id>/remove-tag/<int:tag_id>/', views.remove_tag_from_identity, name='remove_tag_from_identity'),
    
    # Tag management for log sources
    path('logsources/<int:logsource_id>/add-tag/', views.add_tag_to_logsource, name='add_tag_to_logsource'),
    path('logsources/<int:logsource_id>/edit-tag/<int:tag_id>/', views.edit_logsource_tag, name='edit_logsource_tag'),
    path('logsources/<int:logsource_id>/remove-tag/<int:tag_id>/', views.remove_tag_from_logsource, name='remove_tag_from_logsource'),
]
