from azure.identity import ClientSecretCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.loganalytics import LogAnalyticsManagementClient
from azure.graphrbac import GraphRbacManagementClient
from msrestazure.azure_active_directory import MSIAuthentication
from .models import AzureResource, AzureLogSource, AzureAccount, AzureIdentity
from apps.data.models import NormalizedLog
from apps.case.models import Case
from datetime import datetime, timedelta
from django.utils import timezone
from django.utils.timezone import make_aware
from django.db import transaction
import logging
import json
import ipaddress

logger = logging.getLogger(__name__)

def parse_azure_datetime(datetime_str):
    """Parse Azure datetime strings into timezone-aware datetime objects"""
    if datetime_str and datetime_str not in ['N/A', 'not_supported']:
        try:
            dt = datetime.strptime(datetime_str, '%Y-%m-%dT%H:%M:%S.%fZ')
            return make_aware(dt, timezone.utc)
        except ValueError:
            try:
                dt = datetime.strptime(datetime_str, '%Y-%m-%dT%H:%M:%SZ')
                return make_aware(dt, timezone.utc)
            except ValueError:
                logger.debug(f"Could not parse datetime: {datetime_str}")
                return None
    return None

def validate_azure_credentials(tenant_id, client_id, client_secret, subscription_id):
    """Validate Azure credentials by attempting to create a credential object and list resources"""
    try:
        # First try to create the credential object
        logger.info(f"Attempting to validate Azure credentials for subscription {subscription_id}")
        credentials = ClientSecretCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret
        )
        
        try:
            # Then try to create a client and list resources
            logger.info("Credentials created, attempting to list resources")
            client = ResourceManagementClient(credentials, subscription_id)
            
            # Add debug logging before the list operation
            logger.info("Created ResourceManagementClient, about to list resources")
            resources = client.resources.list(top=1)
            logger.info("Got resources iterator")
            
            try:
                # Explicitly try to get the first item and log any errors
                first_resource = next(resources)
                logger.info(f"Successfully retrieved first resource: {first_resource.name if first_resource else 'None'}")
            except StopIteration:
                logger.info("No resources found in subscription, but access is valid")
            except Exception as iter_error:
                logger.error(f"Error accessing resource iterator: {str(iter_error)}", exc_info=True)
                raise
                
            logger.info("Successfully validated Azure credentials")
            return True, None
            
        except Exception as resource_error:
            # Handle specific Azure API errors
            error_message = str(resource_error)
            logger.error(f"Full Azure API error: {error_message}", exc_info=True)
            
            if "AuthenticationFailed" in error_message:
                return False, "Authentication failed. Please check your credentials."
            elif "SubscriptionNotFound" in error_message:
                return False, "Subscription not found. Please check your Subscription ID."
            elif "InvalidAuthenticationTokenTenant" in error_message:
                return False, "Invalid tenant. Please check your Tenant ID."
            elif "AuthorizationFailed" in error_message:
                return False, "Authorization failed. The app registration needs Reader role at subscription level."
            else:
                logger.error(f"Unhandled Azure validation error: {error_message}", exc_info=True)
                return False, f"Resource access error: {error_message}"
                
    except Exception as cred_error:
        # Handle credential creation errors
        error_message = str(cred_error)
        logger.error(f"Azure credential creation error: {error_message}", exc_info=True)
        return False, f"Credential error: {error_message}"

def serialize_resource_details(resource):
    """Serialize resource details, handling datetime objects"""
    if isinstance(resource, dict):
        return {key: serialize_resource_details(value) for key, value in resource.items()}
    elif isinstance(resource, list):
        return [serialize_resource_details(item) for item in resource]
    elif isinstance(resource, datetime):
        return resource.isoformat()
    else:
        return resource

def pull_azure_resources(azure_account):
    """Discover and store Azure resources for the account"""
    logger.info(f"Pulling Azure resources for subscription: {azure_account.subscription_id}")
    
    credentials = ClientSecretCredential(
        tenant_id=azure_account.tenant_id,
        client_id=azure_account.client_id,
        client_secret=azure_account.client_secret
    )
    
    # Initialize the resource client
    resource_client = ResourceManagementClient(
        credentials, 
        azure_account.subscription_id
    )

    try:
        # Get all resources
        for resource in resource_client.resources.list():
            try:
                # Extract resource group from ID
                resource_group = resource.id.split('/')[4] if resource.id else None
                
                # Create or update resource record
                AzureResource.objects.update_or_create(
                    account=azure_account,
                    case=azure_account.case,
                    resource_id=resource.id,
                    defaults={
                        'resource_type': resource.type,
                        'resource_name': resource.name,
                        'resource_group': resource_group,
                        'location': resource.location,
                        'resource_details': serialize_resource_details(resource.as_dict())
                    }
                )
                logger.info(f"Saved resource: {resource.name} ({resource.type})")
            except Exception as e:
                logger.error(f"Error processing resource {resource.name}: {e}")
                continue

    except Exception as e:
        logger.error(f"Error pulling Azure resources: {e}")

def discover_log_sources(azure_account):
    """Discover available Azure log sources"""
    logger.info(f"Discovering log sources for subscription: {azure_account.subscription_id}")
    
    credentials = ClientSecretCredential(
        tenant_id=azure_account.tenant_id,
        client_id=azure_account.client_id,
        client_secret=azure_account.client_secret
    )
    
    monitor_client = MonitorManagementClient(
        credentials,
        azure_account.subscription_id
    )

    try:
        # Check Activity Log settings
        activity_log = {
            'service_name': 'ActivityLog',
            'log_name': 'Azure Activity Log',
            'status': 'Enabled',  # Activity Log is always enabled
            'log_details': {'type': 'platform'}
        }
        
        AzureLogSource.objects.update_or_create(
            account=azure_account,
            case=azure_account.case,
            service_name=activity_log['service_name'],
            log_name=activity_log['log_name'],
            defaults={
                'status': activity_log['status'],
                'log_details': activity_log['log_details']
            }
        )

        # Check Diagnostic Settings for resources
        for resource in AzureResource.objects.filter(account=azure_account):
            try:
                diagnostic_settings = monitor_client.diagnostic_settings.list(resource.resource_id)
                for setting in diagnostic_settings:
                    AzureLogSource.objects.update_or_create(
                        account=azure_account,
                        case=azure_account.case,
                        service_name='DiagnosticSettings',
                        log_name=f"{resource.resource_name}-{setting.name}",
                        defaults={
                            'status': 'Enabled' if setting.logs else 'Disabled',
                            'log_details': serialize_resource_details(setting.as_dict()),
                            'location': resource.location
                        }
                    )
            except Exception as e:
                logger.debug(f"Error checking diagnostic settings for {resource.resource_name}: {e}")
                continue

    except Exception as e:
        logger.error(f"Error discovering log sources: {e}")

def normalize_azure_event(raw_event, case, azure_account):
    """Normalize Azure Activity Log events to match the NormalizedLog model"""
    try:
        # Extract common fields
        event_time = parse_azure_datetime(raw_event.get('eventTimestamp'))
        
        # Handle caller identity
        caller = raw_event.get('caller') or 'Unknown'
        if raw_event.get('claims'):
            caller = raw_event['claims'].get('name', caller)
        
        # Extract operation details
        operation_name = raw_event.get('operationName', {}).get('value', 'Unknown')
        operation_type = raw_event.get('operationName', {}).get('localizedValue', 'Unknown')
        
        # Process IP address
        ip_address = None
        if raw_event.get('claims', {}).get('ipaddr'):
            try:
                ip_address = raw_event['claims']['ipaddr']
                ipaddress.ip_address(ip_address)  # Validate IP address
            except ValueError:
                ip_address = None
        
        # Build resources list
        resources = []
        if raw_event.get('resourceId'):
            resources.append({
                'resourceId': raw_event['resourceId'],
                'resourceType': raw_event.get('resourceType', {}).get('value'),
                'resourceGroup': raw_event.get('resourceGroup')
            })
        
        normalized_data = {
            'case': case,
            'azure_account': azure_account,
            'event_source': 'azure',
            'event_id': raw_event.get('eventDataId'),
            'event_time': event_time,
            'event_name': operation_name,
            'event_type': operation_type,
            'user_identity': caller,
            'region': raw_event.get('resourceLocation'),
            'ip_address': ip_address,
            'user_agent': raw_event.get('claims', {}).get('userAgent'),
            'resources': json.dumps(resources),
            'raw_data': json.dumps(raw_event)
        }
        
        return normalized_data
    except Exception as e:
        logger.error(f"Error normalizing Azure event: {e}")
        return None

def fetch_and_normalize_activity_logs(subscription_id, start_date, end_date, case_id):
    """Fetch and normalize Azure Activity Log entries"""
    try:
        azure_account = AzureAccount.objects.get(subscription_id=subscription_id)
        case = Case.objects.get(id=case_id)
    except (AzureAccount.DoesNotExist, Case.DoesNotExist) as e:
        logger.error(f"Error fetching account or case: {e}")
        return

    credentials = ClientSecretCredential(
        tenant_id=azure_account.tenant_id,
        client_id=azure_account.client_id,
        client_secret=azure_account.client_secret
    )
    
    monitor_client = MonitorManagementClient(
        credentials,
        azure_account.subscription_id
    )

    try:
        # Convert dates to datetime objects if they're strings
        if isinstance(start_date, str):
            start_date = datetime.strptime(start_date, '%Y-%m-%d')
        if isinstance(end_date, str):
            end_date = datetime.strptime(end_date, '%Y-%m-%d')

        # Fetch activity logs
        filter_string = f"eventTimestamp ge '{start_date.isoformat()}' and eventTimestamp le '{end_date.isoformat()}'"
        
        normalized_logs = []
        batch_size = 1000

        for activity_log in monitor_client.activity_logs.list(filter=filter_string):
            try:
                normalized_data = normalize_azure_event(activity_log.as_dict(), case, azure_account)
                if normalized_data:
                    normalized_logs.append(NormalizedLog(**normalized_data))
                
                # Batch create when we reach batch_size
                if len(normalized_logs) >= batch_size:
                    with transaction.atomic():
                        NormalizedLog.objects.bulk_create(normalized_logs)
                    normalized_logs = []
                    
            except Exception as e:
                logger.error(f"Error processing activity log entry: {e}")
                continue

        # Create any remaining logs
        if normalized_logs:
            with transaction.atomic():
                NormalizedLog.objects.bulk_create(normalized_logs)

    except Exception as e:
        logger.error(f"Error fetching activity logs: {e}")
