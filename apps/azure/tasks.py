from celery import shared_task
from .models import AzureAccount
from .utils import pull_azure_resources, discover_log_sources, fetch_and_normalize_activity_logs
import logging

logger = logging.getLogger('azure_tasks')
logger = logging.getLogger(__name__)

@shared_task
def pull_azure_resources_task(subscription_id):
    """
    Background task to pull Azure resources for a given subscription ID.
    """
    try:
        logger.info(f"Starting discovery for Azure subscription ID: {subscription_id}")
        azure_account = AzureAccount.objects.get(subscription_id=subscription_id)
        
        # Pull resources and discover log sources
        pull_azure_resources(azure_account)
        discover_log_sources(azure_account)
        
        logger.info(f"Successfully pulled resources for Azure subscription ID: {subscription_id}")
        return f"Successfully pulled resources for Azure subscription {subscription_id}"
    except AzureAccount.DoesNotExist:
        logger.error(f"AzureAccount with subscription ID {subscription_id} does not exist.")
        return f"AzureAccount with subscription ID {subscription_id} does not exist."
    except Exception as e:
        logger.error(f"Error pulling Azure resources: {e}")
        return f"Error pulling resources: {str(e)}"

@shared_task
def fetch_normalize_activity_logs_task(subscription_id, start_date, end_date, case_id):
    """Background task to fetch and normalize Azure Activity Log entries."""
    try:
        logger.info(f"Starting Activity Log fetch for Azure subscription ID: {subscription_id}")
        fetch_and_normalize_activity_logs(
            subscription_id=subscription_id,
            start_date=start_date,
            end_date=end_date,
            case_id=case_id
        )
        logger.info(f"Successfully fetched Activity Logs for Azure subscription ID: {subscription_id}")
    except Exception as e:
        logger.error(f"Error fetching Activity Logs for Azure subscription ID {subscription_id}: {e}")
        raise

@shared_task
def fetch_azure_identities_task(account_id):
    """
    Background task to fetch Azure AD identities.
    Note: This would need a corresponding utility function in utils.py
    """
    try:
        logger.info(f"Starting identity fetch for Azure subscription ID: {account_id}")
        azure_account = AzureAccount.objects.get(subscription_id=account_id)
        # TODO: Implement fetch_azure_identities in utils.py
        # fetch_azure_identities(azure_account)
        logger.info(f"Successfully fetched identities for Azure subscription ID: {account_id}")
    except AzureAccount.DoesNotExist:
        logger.error(f"AzureAccount with subscription ID {account_id} does not exist.")
    except Exception as e:
        logger.error(f"Error fetching identities for Azure subscription ID {account_id}: {e}")
        raise
