from django.urls import path
from django.views.generic import TemplateView

from . import views

app_name = "aws"

urlpatterns = [
    path('<slug:slug>/connect/aws/', views.connect_aws, name='connect_aws'),
    path('accounts/<str:account_id>/edit/', views.edit_account, name='edit_account'),
	path('accounts/<str:account_id>/delete/', views.delete_account, name='delete_account'),
    path('accounts/<str:account_id>/pull-resources/', views.pull_resources_view, name='pull_aws_resources'),
    path('resources/<int:resource_id>/details/', views.aws_resource_details, name='aws_resource_details'),
    path('accounts/<str:account_id>/account-resources/', views.account_resources, name='account_resources'),
    path('logsource/<slug:slug>//details/', views.aws_logsource_details, name='aws_logsource_details'),
    path('fetch-management-events/<str:account_id>/', views.trigger_management_event_fetch, name='fetch_management_events'),
    path('browse-s3-structure/', views.browse_s3_structure, name='browse_s3_structure'),
    path('fetch-logs/<str:account_id>/', views.fetch_cloudtrail_logs, name='fetch_cloudtrail_logs'),
    path('accounts/<str:account_id>/logs/', views.normalized_logs_view, name='normalized_logs'),
    path('credential/<slug:slug>/', views.aws_credential_details, name='aws_credential_details'),
    path('resources/<int:resource_id>/add-tag/', views.add_tag_to_resource, name='add_tag_to_resource'),
    path('credentials/<int:credential_id>/add-tag/', views.add_tag_to_credential, name='add_tag_to_credential'),
    path('logsources/<int:logsource_id>/add-tag/', views.add_tag_to_logsource, name='add_tag_to_logsource'),
    path('resources/<int:resource_id>/edit-tag/<int:tag_id>/', views.edit_resource_tag, name='edit_resource_tag'),
    path('credentials/<int:credential_id>/edit-tag/<int:tag_id>/', views.edit_credential_tag, name='edit_credential_tag'),
    path('logsources/<int:logsource_id>/edit-tag/<int:tag_id>/', views.edit_logsource_tag, name='edit_logsource_tag'),
    path('resources/<int:resource_id>/remove-tag/<int:tag_id>/', views.remove_tag_from_resource, name='remove_tag_from_resource'),
    path('credentials/<int:credential_id>/remove-tag/<int:tag_id>/', views.remove_tag_from_credential, name='remove_tag_from_credential'),
    path('logsources/<int:logsource_id>/remove-tag/<int:tag_id>/', views.remove_tag_from_logsource, name='remove_tag_from_logsource'),
    path('suggest-cloudtrail-prefix/', views.suggest_cloudtrail_prefix, name='suggest_cloudtrail_prefix'),
]

