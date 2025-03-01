from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from apps.case.models import Case
from .models import AzureAccount, AzureResource, AzureLogSource, AzureIdentity
from apps.data.models import NormalizedLog, Tag
from .forms import AzureAccountForm
from .utils import validate_azure_credentials
from .tasks import pull_azure_resources_task, fetch_normalize_activity_logs_task
from datetime import datetime, timedelta
from django.db.models import Count

import logging

logger = logging.getLogger(__name__)

@login_required
def connect_azure(request, slug):
    """Connect an Azure account to a case."""
    case = get_object_or_404(Case, slug=slug)

    if request.method == "POST":
        form = AzureAccountForm(request.POST)
        if form.is_valid():
            azure_account = form.save(commit=False)
            azure_account.case = case
            azure_account.added_by = request.user

            # Validate credentials
            is_valid, error_message = validate_azure_credentials(
                tenant_id=azure_account.tenant_id,
                client_id=azure_account.client_id,
                client_secret=azure_account.client_secret,
                subscription_id=azure_account.subscription_id
            )
            azure_account.validated = is_valid
            azure_account.save()

            if is_valid:
                messages.success(request, "Azure account connected successfully!")
            else:
                messages.error(request, f"Azure account saved, but validation failed: {error_message}")

            return redirect('case:case_detail', slug=case.slug)
    else:
        form = AzureAccountForm()

    return render(request, 'azure/connect_azure.html', {'form': form, 'case': case})

@login_required
def edit_account(request, subscription_id):
    """Edit an existing Azure account."""
    account = get_object_or_404(AzureAccount, subscription_id=subscription_id)
    logger.info(f"Editing Azure account with subscription ID: {subscription_id}")
    
    if request.method == "POST":
        form = AzureAccountForm(request.POST, instance=account)
        if form.is_valid():
            azure_account = form.save(commit=False)
            
            # Log the values being used for validation (mask sensitive data)
            logger.info(f"Validating credentials for subscription: {azure_account.subscription_id}")
            logger.info(f"Using tenant_id: {azure_account.tenant_id}")
            logger.info(f"Using client_id: {azure_account.client_id}")
            logger.info("Client secret provided: [MASKED]")
            
            # Re-validate credentials
            is_valid, error_message = validate_azure_credentials(
                tenant_id=azure_account.tenant_id,
                client_id=azure_account.client_id,
                client_secret=azure_account.client_secret,
                subscription_id=azure_account.subscription_id
            )
            
            # Log the validation result
            if is_valid:
                logger.info("Azure credential validation successful")
            else:
                logger.error(f"Azure credential validation failed: {error_message}")
            
            azure_account.validated = is_valid
            azure_account.save()

            if is_valid:
                messages.success(request, "Azure account updated and credentials validated successfully!")
            else:
                messages.error(request, f"Azure account updated, but validation failed: {error_message}")

            return redirect('case:case_detail', slug=account.case.slug)
    else:
        form = AzureAccountForm(instance=account)

    return render(request, 'azure/edit_account.html', {'form': form, 'account': account})

@login_required
def delete_account(request, subscription_id):
    """Delete an Azure account."""
    account = get_object_or_404(AzureAccount, subscription_id=subscription_id)
    slug = account.case.slug
    account.delete()
    return redirect('case:case_detail', slug=slug)

@login_required
def pull_resources_view(request, subscription_id):
    """Trigger the background task to pull Azure resources."""
    azure_account = get_object_or_404(AzureAccount, subscription_id=subscription_id)

    if not azure_account.validated:
        messages.error(request, "Cannot pull resources because the Azure account credentials are not validated.")
        return redirect('case:case_detail', slug=azure_account.case.slug)

    # Trigger background task with subscription_id
    pull_azure_resources_task.delay(subscription_id)
    messages.info(request, "Resource pulling has started. Refresh the page after a few minutes to see the results.")

    return redirect('azure:account_resources', subscription_id=subscription_id)

@login_required
def account_resources(request, subscription_id):
    """Display Azure resources and log sources for an account."""
    azure_account = get_object_or_404(AzureAccount, subscription_id=subscription_id)
    case = azure_account.case

    # Group resources by their type
    resources = AzureResource.objects.filter(account=azure_account).order_by('resource_type', 'resource_name')
    grouped_resources = {}
    for resource in resources:
        grouped_resources.setdefault(resource.resource_type, []).append(resource)

    # Group log sources by service
    log_sources = AzureLogSource.objects.filter(account=azure_account).order_by('service_name', 'log_name')
    grouped_log_sources = {}
    for log_source in log_sources:
        grouped_log_sources.setdefault(log_source.service_name, []).append(log_source)

    # Add error messages if applicable
    error_messages = []
    if not resources.exists():
        error_messages.append("No Azure resources found for this account.")
    if not log_sources.exists():
        error_messages.append("No Azure log sources found for this account.")

    context = {
        'azure_account': azure_account,
        'case': case,
        'grouped_resources': grouped_resources,
        'grouped_log_sources': grouped_log_sources,
        'error_messages': error_messages,
        'all_tags': Tag.objects.all(),
    }
    return render(request, 'azure/account_resources.html', context)

@login_required
def azure_resource_details(request, slug):
    """Display detailed information for a specific Azure resource."""
    resource = get_object_or_404(AzureResource, slug=slug)
    account = resource.account
    case = account.case
    
    return render(request, 'azure/resource_details.html', {
        'resource': resource,
        'account': account,
        'case': case
    })

@login_required
def azure_logsource_details(request, slug):
    """Display detailed information for a specific Azure log source."""
    log_source = get_object_or_404(AzureLogSource, slug=slug)
    account = log_source.account
    case = account.case
    
    return render(request, 'azure/logsource_details.html', {
        'log_source': log_source,
        'account': account,
        'case': case,
        'azure_account': account
    })

@login_required
def trigger_activity_log_fetch(request, subscription_id):
    """Trigger the background task to fetch Azure Activity Logs"""
    azure_account = get_object_or_404(AzureAccount, subscription_id=subscription_id)
    logger.info(f"Triggering Activity Log fetch for Azure subscription {subscription_id}")

    # Set date range for last 89 days to be safe
    end_date = timezone.now()
    start_date = end_date - timedelta(days=89)  # Changed from 90 to 89 to be safe

    # Format dates as strings
    start_date_str = start_date.strftime('%Y-%m-%d')
    end_date_str = end_date.strftime('%Y-%m-%d')

    # Trigger background task with positional arguments
    fetch_normalize_activity_logs_task.delay(
        subscription_id,
        start_date_str,
        end_date_str,
        azure_account.case.id
    )
    
    messages.info(request, 
        "Azure Activity Log history is being fetched. Note: Azure only retains activity logs for 90 days."
    )
    logger.info(f"Task queued for Azure subscription {subscription_id}")

    return redirect("azure:normalized_logs", subscription_id=azure_account.subscription_id)

@login_required
def normalized_logs_view(request, subscription_id):
    """Display normalized logs for an Azure account."""
    azure_account = get_object_or_404(AzureAccount, subscription_id=subscription_id)
    
    # Get date range from request
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    
    # Set default date range if not provided (last 7 days)
    if not start_date:
        start_date = (timezone.now() - timedelta(days=7)).strftime('%Y-%m-%d')
    if not end_date:
        end_date = timezone.now().strftime('%Y-%m-%d')
    
    # Convert to datetime objects (naive)
    start_datetime = datetime.strptime(start_date, '%Y-%m-%d')
    end_datetime = datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)
    
    # Calculate 90 days ago (naive)
    ninety_days_ago = timezone.now().replace(tzinfo=None) - timedelta(days=90)
    
    # Check if requested date range is within 90 days
    if start_datetime < ninety_days_ago:
        messages.warning(request, "Azure only retains activity logs for 90 days. Adjusting start date.")
        start_datetime = ninety_days_ago
        start_date = start_datetime.strftime('%Y-%m-%d')
    
    # Make datetime objects timezone-aware after all calculations
    start_datetime = timezone.make_aware(start_datetime)
    end_datetime = timezone.make_aware(end_datetime)
    
    # Query logs
    logs = NormalizedLog.objects.filter(
        case=azure_account.case,
        event_source='azure',
        event_time__gte=start_datetime,
        event_time__lt=end_datetime,
        azure_account=azure_account
    ).order_by('-event_time')
    
    # Aggregate top 10 users
    top_users = logs.values('user_identity').annotate(
        count=Count('user_identity')).order_by('-count')[:10]
    
    # Aggregate top 10 IPs
    top_ips = logs.values('ip_address').annotate(
        count=Count('ip_address')).order_by('-count')[:10]
    
    # Aggregate top 10 events
    top_events = logs.values('event_name').annotate(
        count=Count('event_name')).order_by('-count')[:10]
    
    
    context = {
        "azure_account": azure_account,
        "logs": logs,
        "top_users": top_users,
        "top_ips": top_ips,
        "top_events": top_events,
        "start_date": start_date,
        "end_date": end_date,
    }
    return render(request, "azure/get_logs.html", context)

@login_required
def add_tag_to_resource(request, resource_id):
    if request.method == 'POST':
        tag_id = request.POST.get('tag_id')
        try:
            resource = AzureResource.objects.get(id=resource_id)
            tag = Tag.objects.get(id=tag_id)
            resource.tags.add(tag)
            messages.success(request, f'Tag "{tag.name}" added successfully.')
        except (AzureResource.DoesNotExist, Tag.DoesNotExist):
            messages.error(request, 'Error adding tag.')
        return redirect('azure:account_resources', subscription_id=resource.account.subscription_id)

@login_required
def edit_resource_tag(request, resource_id, tag_id):
    if request.method == 'POST':
        new_tag_id = request.POST.get('new_tag_id')
        redirect_url = request.META.get('HTTP_REFERER', '')
        
        try:
            resource = AzureResource.objects.get(id=resource_id)
            old_tag = Tag.objects.get(id=tag_id)
            new_tag = Tag.objects.get(id=new_tag_id)
            
            resource.tags.remove(old_tag)
            resource.tags.add(new_tag)
            messages.success(request, f'Tag updated from "{old_tag.name}" to "{new_tag.name}"')
        except (AzureResource.DoesNotExist, Tag.DoesNotExist):
            messages.error(request, 'Error updating tag.')
        
        if redirect_url:
            return redirect(redirect_url)
    return redirect('azure:account_resources', subscription_id=resource.account.subscription_id)

@login_required
def remove_tag_from_resource(request, resource_id, tag_id):
    if request.method == 'POST':
        redirect_url = request.META.get('HTTP_REFERER', '')
        
        try:
            resource = AzureResource.objects.get(id=resource_id)
            tag = Tag.objects.get(id=tag_id)
            resource.tags.remove(tag)
            messages.success(request, f'Tag "{tag.name}" removed successfully.')
        except (AzureResource.DoesNotExist, Tag.DoesNotExist):
            messages.error(request, 'Error removing tag.')
        
        if redirect_url:
            return redirect(redirect_url)
    return redirect('azure:account_resources', subscription_id=resource.account.subscription_id)

@login_required
def add_tag_to_logsource(request, logsource_id):
    if request.method == 'POST':
        tag_id = request.POST.get('tag_id')
        try:
            logsource = AzureLogSource.objects.get(id=logsource_id)
            tag = Tag.objects.get(id=tag_id)
            logsource.tags.add(tag)
            messages.success(request, f'Tag "{tag.name}" added successfully.')
        except (AzureLogSource.DoesNotExist, Tag.DoesNotExist):
            messages.error(request, 'Error adding tag.')
    return redirect('azure:account_resources', subscription_id=logsource.account.subscription_id)

@login_required
def edit_logsource_tag(request, logsource_id, tag_id):
    if request.method == 'POST':
        new_tag_id = request.POST.get('new_tag_id')
        redirect_url = request.META.get('HTTP_REFERER', '')
        
        try:
            logsource = AzureLogSource.objects.get(id=logsource_id)
            old_tag = Tag.objects.get(id=tag_id)
            new_tag = Tag.objects.get(id=new_tag_id)
            
            logsource.tags.remove(old_tag)
            logsource.tags.add(new_tag)
            messages.success(request, f'Tag updated from "{old_tag.name}" to "{new_tag.name}"')
        except (AzureLogSource.DoesNotExist, Tag.DoesNotExist):
            messages.error(request, 'Error updating tag.')
        
        if redirect_url:
            return redirect(redirect_url)
    return redirect('azure:account_resources', subscription_id=logsource.account.subscription_id)

@login_required
def remove_tag_from_logsource(request, logsource_id, tag_id):
    if request.method == 'POST':
        redirect_url = request.META.get('HTTP_REFERER', '')
        
        try:
            logsource = AzureLogSource.objects.get(id=logsource_id)
            tag = Tag.objects.get(id=tag_id)
            logsource.tags.remove(tag)
            messages.success(request, f'Tag "{tag.name}" removed successfully.')
        except (AzureLogSource.DoesNotExist, Tag.DoesNotExist):
            messages.error(request, 'Error removing tag.')
        
        if redirect_url:
            return redirect(redirect_url)
    return redirect('azure:account_resources', subscription_id=logsource.account.subscription_id)

@login_required
def azure_identity_details(request, slug):
    """Display detailed information for a specific Azure identity."""
    identity = get_object_or_404(AzureIdentity, slug=slug)
    account = identity.account
    case = account.case
    
    return render(request, 'azure/identity_details.html', {
        'identity': identity,
        'account': account,
        'case': case,
        'azure_account': account
    })

@login_required
def add_tag_to_identity(request, identity_id):
    if request.method == 'POST':
        tag_id = request.POST.get('tag_id')
        try:
            identity = AzureIdentity.objects.get(id=identity_id)
            tag = Tag.objects.get(id=tag_id)
            identity.tags.add(tag)
            messages.success(request, f'Tag "{tag.name}" added successfully.')
        except (AzureIdentity.DoesNotExist, Tag.DoesNotExist):
            messages.error(request, 'Error adding tag.')
    return redirect('azure:account_resources', subscription_id=identity.account.subscription_id)

@login_required
def edit_identity_tag(request, identity_id, tag_id):
    if request.method == 'POST':
        new_tag_id = request.POST.get('new_tag_id')
        redirect_url = request.META.get('HTTP_REFERER', '')
        
        try:
            identity = AzureIdentity.objects.get(id=identity_id)
            old_tag = Tag.objects.get(id=tag_id)
            new_tag = Tag.objects.get(id=new_tag_id)
            
            identity.tags.remove(old_tag)
            identity.tags.add(new_tag)
            messages.success(request, f'Tag updated from "{old_tag.name}" to "{new_tag.name}"')
        except (AzureIdentity.DoesNotExist, Tag.DoesNotExist):
            messages.error(request, 'Error updating tag.')
        
        if redirect_url:
            return redirect(redirect_url)
    return redirect('azure:account_resources', subscription_id=identity.account.subscription_id)

@login_required
def remove_tag_from_identity(request, identity_id, tag_id):
    if request.method == 'POST':
        redirect_url = request.META.get('HTTP_REFERER', '')
        
        try:
            identity = AzureIdentity.objects.get(id=identity_id)
            tag = Tag.objects.get(id=tag_id)
            identity.tags.remove(tag)
            messages.success(request, f'Tag "{tag.name}" removed successfully.')
        except (AzureIdentity.DoesNotExist, Tag.DoesNotExist):
            messages.error(request, 'Error removing tag.')
        
        if redirect_url:
            return redirect(redirect_url)
    return redirect('azure:account_resources', subscription_id=identity.account.subscription_id)
