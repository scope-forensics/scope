from celery import shared_task
from .models import GCPAccount
from .utils import pull_gcp_resources, discover_log_sources
import logging

logger = logging.getLogger(__name__)

@shared_task
def pull_gcp_resources_task(gcp_account_id):
    """Background task to pull GCP resources"""
    try:
        gcp_account = GCPAccount.objects.get(id=gcp_account_id)
        pull_gcp_resources(gcp_account)
        discover_log_sources(gcp_account)
    except Exception as e:
        logger.error(f"Error pulling GCP resources: {e}")
        raise
