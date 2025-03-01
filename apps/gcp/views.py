from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from apps.case.models import Case
from .models import GCPAccount, GCPResource, GCPLogSource
from apps.data.models import NormalizedLog
from .forms import GCPAccountForm
from .utils import validate_gcp_credentials
from datetime import datetime, timedelta
from django.utils import timezone
from apps.data.models import Tag

# Create your views here.

@login_required
def connect_gcp(request, slug):
    """Connect a GCP project to a case."""
    case = get_object_or_404(Case, slug=slug)

    if request.method == "POST":
        form = GCPAccountForm(request.POST, request.FILES)
        if form.is_valid():
            gcp_account = form.save(commit=False)
            gcp_account.case = case
            gcp_account.added_by = request.user

            # Validate credentials
            is_valid, error_message = validate_gcp_credentials(
                project_id=gcp_account.project_id,
                service_account_info=gcp_account.service_account_info
            )
            gcp_account.validated = is_valid
            gcp_account.save()

            if is_valid:
                messages.success(request, "GCP project connected successfully!")
            else:
                messages.error(request, f"GCP project saved, but validation failed: {error_message}")

            return redirect('case:case_detail', slug=case.slug)
    else:
        form = GCPAccountForm()

    return render(request, 'gcp/connect_gcp.html', {'form': form, 'case': case})

@login_required
def edit_account(request, project_id):
    """Edit an existing GCP account."""
    account = get_object_or_404(GCPAccount, project_id=project_id)
    
    if request.method == "POST":
        form = GCPAccountForm(request.POST, request.FILES, instance=account)
        if form.is_valid():
            gcp_account = form.save(commit=False)
            
            # Re-validate credentials
            is_valid, error_message = validate_gcp_credentials(
                project_id=gcp_account.project_id,
                service_account_info=gcp_account.service_account_info
            )
            
            gcp_account.validated = is_valid
            gcp_account.save()

            if is_valid:
                messages.success(request, "GCP project updated and credentials validated successfully!")
            else:
                messages.error(request, f"GCP project updated, but validation failed: {error_message}")

            return redirect('case:case_detail', slug=account.case.slug)
    else:
        form = GCPAccountForm(instance=account)

    return render(request, 'gcp/edit_account.html', {'form': form, 'account': account})

@login_required
def delete_account(request, project_id):
    """Delete a GCP account."""
    account = get_object_or_404(GCPAccount, project_id=project_id)
    slug = account.case.slug
    account.delete()
    messages.success(request, "GCP project disconnected successfully.")
    return redirect('case:case_detail', slug=slug)

@login_required
def account_resources(request, project_id):
    """Display GCP resources and log sources for an account."""
    gcp_account = get_object_or_404(GCPAccount, project_id=project_id)
    case = gcp_account.case

    # Group resources by their type
    resources = GCPResource.objects.filter(account=gcp_account).order_by('resource_type', 'resource_name')
    grouped_resources = {}
    for resource in resources:
        grouped_resources.setdefault(resource.resource_type, []).append(resource)

    # Group log sources by service
    log_sources = GCPLogSource.objects.filter(account=gcp_account).order_by('service_name', 'log_name')
    grouped_log_sources = {}
    for log_source in log_sources:
        grouped_log_sources.setdefault(log_source.service_name, []).append(log_source)

    # Add error messages if applicable
    error_messages = []
    if not resources.exists():
        error_messages.append("No GCP resources found for this project.")
    if not log_sources.exists():
        error_messages.append("No GCP log sources found for this project.")

    context = {
        'gcp_account': gcp_account,
        'case': case,
        'grouped_resources': grouped_resources,
        'grouped_log_sources': grouped_log_sources,
        'error_messages': error_messages,
        'all_tags': Tag.objects.all(),
    }
    return render(request, 'gcp/account_resources.html', context)

@login_required
def normalized_logs(request, project_id):
    """Display normalized logs for a GCP project."""
    gcp_account = get_object_or_404(GCPAccount, project_id=project_id)
    
    # Get date range from request
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    
    # Set default date range if not provided (last 7 days)
    if not start_date:
        start_date = (timezone.now() - timedelta(days=7)).strftime('%Y-%m-%d')
    if not end_date:
        end_date = timezone.now().strftime('%Y-%m-%d')
    
    # Convert to datetime objects
    start_datetime = datetime.strptime(start_date, '%Y-%m-%d')
    end_datetime = datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)
    
    # Make datetime objects timezone-aware
    start_datetime = timezone.make_aware(start_datetime)
    end_datetime = timezone.make_aware(end_datetime)
    
    # Query logs
    logs = NormalizedLog.objects.filter(
        case=gcp_account.case,
        event_source='gcp',
        event_time__gte=start_datetime,
        event_time__lt=end_datetime,
        gcp_account=gcp_account
    ).order_by('-event_time')
    
    context = {
        "gcp_account": gcp_account,
        "logs": logs,
        "start_date": start_date,
        "end_date": end_date,
    }
    return render(request, "gcp/normalized_logs.html", context)

@login_required
def pull_resources(request, project_id):
    """Pull latest resources from GCP project."""
    gcp_account = get_object_or_404(GCPAccount, project_id=project_id)
    
    try:
        # Import here to avoid circular imports
        from .tasks import pull_gcp_resources_task
        pull_gcp_resources_task.delay(gcp_account.id)
        messages.success(request, "Resource refresh started. This may take a few minutes.")
    except Exception as e:
        logger.error(f"Error starting resource pull: {e}")
        messages.error(request, "Error starting resource refresh. Please try again.")
    
    return redirect('gcp:account_resources', project_id=project_id)

@login_required
def add_tag_to_resource(request, resource_id):
    """Add a tag to a GCP resource."""
    resource = get_object_or_404(GCPResource, id=resource_id)
    if request.method == "POST":
        tag_id = request.POST.get('tag_id')
        tag = get_object_or_404(Tag, id=tag_id)
        resource.tags.add(tag)
        messages.success(request, f"Tag '{tag.name}' added to resource.")
    return redirect('gcp:account_resources', project_id=resource.account.project_id)

@login_required
def edit_resource_tag(request, resource_id, tag_id):
    """Edit a tag on a GCP resource."""
    resource = get_object_or_404(GCPResource, id=resource_id)
    old_tag = get_object_or_404(Tag, id=tag_id)
    if request.method == "POST":
        new_tag_id = request.POST.get('new_tag_id')
        new_tag = get_object_or_404(Tag, id=new_tag_id)
        resource.tags.remove(old_tag)
        resource.tags.add(new_tag)
        messages.success(request, f"Tag updated from '{old_tag.name}' to '{new_tag.name}'.")
    return redirect('gcp:account_resources', project_id=resource.account.project_id)

@login_required
def remove_tag_from_resource(request, resource_id, tag_id):
    """Remove a tag from a GCP resource."""
    resource = get_object_or_404(GCPResource, id=resource_id)
    tag = get_object_or_404(Tag, id=tag_id)
    resource.tags.remove(tag)
    messages.success(request, f"Tag '{tag.name}' removed from resource.")
    return redirect('gcp:account_resources', project_id=resource.account.project_id)

@login_required
def add_tag_to_logsource(request, logsource_id):
    """Add a tag to a GCP log source."""
    log_source = get_object_or_404(GCPLogSource, id=logsource_id)
    if request.method == "POST":
        tag_id = request.POST.get('tag_id')
        tag = get_object_or_404(Tag, id=tag_id)
        log_source.tags.add(tag)
        messages.success(request, f"Tag '{tag.name}' added to log source.")
    return redirect('gcp:account_resources', project_id=log_source.account.project_id)

@login_required
def edit_logsource_tag(request, logsource_id, tag_id):
    """Edit a tag on a GCP log source."""
    log_source = get_object_or_404(GCPLogSource, id=logsource_id)
    old_tag = get_object_or_404(Tag, id=tag_id)
    if request.method == "POST":
        new_tag_id = request.POST.get('new_tag_id')
        new_tag = get_object_or_404(Tag, id=new_tag_id)
        log_source.tags.remove(old_tag)
        log_source.tags.add(new_tag)
        messages.success(request, f"Tag updated from '{old_tag.name}' to '{new_tag.name}'.")
    return redirect('gcp:account_resources', project_id=log_source.account.project_id)

@login_required
def remove_tag_from_logsource(request, logsource_id, tag_id):
    """Remove a tag from a GCP log source."""
    log_source = get_object_or_404(GCPLogSource, id=logsource_id)
    tag = get_object_or_404(Tag, id=tag_id)
    log_source.tags.remove(tag)
    messages.success(request, f"Tag '{tag.name}' removed from log source.")
    return redirect('gcp:account_resources', project_id=log_source.account.project_id)

@login_required
def resource_details(request, slug):
    """Display detailed information about a GCP resource."""
    resource = get_object_or_404(GCPResource, slug=slug)
    account = resource.account
    
    context = {
        'resource': resource,
        'account': account,
    }
    return render(request, 'gcp/resource_details.html', context)

@login_required
def logsource_details(request, logsource_id):
    """Display detailed information about a GCP log source."""
    log_source = get_object_or_404(GCPLogSource, id=logsource_id)
    account = log_source.account
    
    context = {
        'log_source': log_source,
        'account': account,
    }
    return render(request, 'gcp/logsource_details.html', context)
