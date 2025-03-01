from google.oauth2 import service_account
from google.cloud.resourcemanager_v3 import ProjectsClient
from google.cloud import storage
from google.cloud import logging
from google.cloud import compute_v1
import logging as python_logging
from .models import GCPResource, GCPLogSource

logger = python_logging.getLogger(__name__)

def validate_gcp_credentials(project_id, service_account_info):
    """Validate GCP credentials by attempting to create a client and list resources"""
    try:
        # Create credentials from service account info
        credentials = service_account.Credentials.from_service_account_info(
            service_account_info,
            scopes=[
                'https://www.googleapis.com/auth/cloud-platform.read-only',
                'https://www.googleapis.com/auth/compute.readonly',
                'https://www.googleapis.com/auth/logging.read'
            ]
        )

        # Verify project access
        client = ProjectsClient(credentials=credentials)
        try:
            project = client.get_project(name=f'projects/{project_id}')
            if not project:
                return False, "Project not found or no access"
        except Exception as e:
            error_str = str(e)
            logger.error(f"Error accessing project: {error_str}")
            
            if "SERVICE_DISABLED" in error_str:
                if "cloudresourcemanager.googleapis.com" in error_str:
                    return False, "Cloud Resource Manager API is not enabled. Please enable it in the Google Cloud Console."
                elif "storage.googleapis.com" in error_str:
                    return False, "Cloud Storage API is not enabled. Please enable it in the Google Cloud Console."
                elif "logging.googleapis.com" in error_str:
                    return False, "Cloud Logging API is not enabled. Please enable it in the Google Cloud Console."
                elif "compute.googleapis.com" in error_str:
                    return False, "Compute Engine API is not enabled. Please enable it in the Google Cloud Console."
                else:
                    return False, f"Required API is not enabled: {error_str}"
            
            return False, f"Project access error: {error_str}"

        # Test Storage access
        try:
            storage_client = storage.Client(credentials=credentials, project=project_id)
            storage_client.list_buckets(max_results=1)
        except Exception as e:
            logger.warning(f"Storage access test failed: {str(e)}")
            # Continue validation even if storage access fails

        # Test Logging access
        try:
            logging_client = logging.Client(credentials=credentials, project=project_id)
            logging_client.list_entries(max_results=1)
        except Exception as e:
            logger.warning(f"Logging access test failed: {str(e)}")
            # Continue validation even if logging access fails

        logger.info(f"Successfully validated GCP credentials for project {project_id}")
        return True, None

    except Exception as e:
        error_message = str(e)
        logger.error(f"GCP credential validation error: {error_message}")
        
        if "invalid_grant" in error_message.lower():
            return False, "Invalid service account key"
        elif "permission denied" in error_message.lower():
            return False, "Permission denied. Please check the service account roles"
        elif "project not found" in error_message.lower():
            return False, "Project not found. Please check the Project ID"
        else:
            return False, f"Validation error: {error_message}"

def serialize_resource_details(resource):
    """Serialize resource details, handling non-serializable objects"""
    if hasattr(resource, 'to_dict'):
        return resource.to_dict()
    elif isinstance(resource, dict):
        return {key: serialize_resource_details(value) for key, value in resource.items()}
    elif isinstance(resource, list):
        return [serialize_resource_details(item) for item in resource]
    else:
        return str(resource)

def pull_gcp_resources(gcp_account):
    """Pull GCP resources for the given account"""
    logger.info(f"Pulling GCP resources for project: {gcp_account.project_id}")
    
    try:
        credentials = service_account.Credentials.from_service_account_info(
            gcp_account.service_account_info,
            scopes=[
                'https://www.googleapis.com/auth/cloud-platform.read-only',
                'https://www.googleapis.com/auth/compute.readonly'
            ]
        )

        # Get Compute Engine instances
        try:
            instance_client = compute_v1.InstancesClient(credentials=credentials)
            request = compute_v1.AggregatedListInstancesRequest(
                project=gcp_account.project_id
            )
            for zone, response in instance_client.aggregated_list(request=request):
                if response.instances:
                    for instance in response.instances:
                        GCPResource.objects.update_or_create(
                            account=gcp_account,
                            case=gcp_account.case,
                            resource_id=instance.id,
                            defaults={
                                'resource_type': 'compute.googleapis.com/Instance',
                                'resource_name': instance.name,
                                'location': zone.split('/')[-1],
                                'resource_details': {
                                    'machine_type': instance.machine_type,
                                    'status': instance.status,
                                    'creation_timestamp': instance.creation_timestamp,
                                    'network_interfaces': [
                                        {
                                            'network': nic.network,
                                            'subnetwork': nic.subnetwork,
                                            'internal_ip': nic.network_i_p,
                                            'external_ip': nic.access_configs[0].nat_i_p if nic.access_configs else None
                                        } for nic in instance.network_interfaces
                                    ]
                                }
                            }
                        )
        except Exception as e:
            logger.error(f"Error listing Compute Engine instances: {e}")

        # Get Storage buckets
        try:
            storage_client = storage.Client(credentials=credentials, project=gcp_account.project_id)
            for bucket in storage_client.list_buckets():
                GCPResource.objects.update_or_create(
                    account=gcp_account,
                    case=gcp_account.case,
                    resource_id=bucket.id,
                    defaults={
                        'resource_type': 'storage.googleapis.com/Bucket',
                        'resource_name': bucket.name,
                        'location': bucket.location,
                        'resource_details': {
                            'storage_class': bucket.storage_class,
                            'created': bucket.time_created.isoformat() if bucket.time_created else None,
                            'updated': bucket.updated.isoformat() if bucket.updated else None,
                            'versioning_enabled': bucket.versioning_enabled
                        }
                    }
                )
        except Exception as e:
            logger.error(f"Error listing Storage buckets: {e}")

    except Exception as e:
        logger.error(f"Error pulling GCP resources: {e}")
        raise

def discover_log_sources(gcp_account):
    """Discover available log sources in the GCP project"""
    logger.info(f"Discovering log sources for project: {gcp_account.project_id}")
    
    try:
        credentials = service_account.Credentials.from_service_account_info(
            gcp_account.service_account_info,
            scopes=['https://www.googleapis.com/auth/logging.read']
        )

        logging_client = logging.Client(credentials=credentials, project=gcp_account.project_id)
        
        # List all log entries to discover available log types
        for entry in logging_client.list_entries(page_size=1000, order_by=logging.DESCENDING):
            GCPLogSource.objects.update_or_create(
                account=gcp_account,
                case=gcp_account.case,
                service_name=entry.resource.type,
                log_name=entry.log_name,
                defaults={
                    'status': 'Enabled',
                    'log_details': {
                        'resource_type': entry.resource.type,
                        'severity': entry.severity
                    }
                }
            )

    except Exception as e:
        logger.error(f"Error discovering log sources: {e}")
        raise
