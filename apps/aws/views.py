import boto3
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from .models import AWSAccount, AWSResource, AWSLogSource, AWSCredential, Tag
from .forms import AWSAccountForm, FetchCloudTrailLogsForm
from apps.case.models import Case
from .utils import validate_aws_credentials 
from django.contrib import messages
from .tasks import pull_aws_resources_task, fetch_management_history_task, fetch_normalize_cloudtrail_logs_task
from datetime import datetime, timedelta
from django.utils import timezone
from django.http import JsonResponse
from django.utils.timezone import make_aware
from apps.data.models import NormalizedLog
from django.db.models import Count, Value
from django.db.models.functions import Coalesce


import logging

logger = logging.getLogger(__name__)


# This is used to add access to the aws account to be investigated and connect it to scope.
@login_required
def connect_aws(request, slug):
    case = get_object_or_404(Case, slug=slug)

    if request.method == "POST":
        form = AWSAccountForm(request.POST)
        if form.is_valid():
            aws_account = form.save(commit=False)
            aws_account.case = case
            aws_account.added_by = request.user

            # Validate credentials
            is_valid, error_message = validate_aws_credentials(
                aws_access_key=aws_account.aws_access_key,
                aws_secret_key=aws_account.aws_secret_key,
                region=aws_account.aws_region
            )
            aws_account.validated = is_valid
            aws_account.save()

            # Provide user feedback
            if is_valid:
                messages.success(request, "AWS account connected successfully!")
            else:
                messages.error(request, f"AWS account saved, but validation failed: {error_message}")

            # Redirect to connected accounts page
            return redirect('case:case_detail', slug=case.slug)
    else:
        form = AWSAccountForm()

    return render(request, 'aws/connect_aws.html', {'form': form, 'case': case})

# Edit aws connection
@login_required
def edit_account(request, account_id):
    account = get_object_or_404(AWSAccount, account_id=account_id)
    if request.method == "POST":
        form = AWSAccountForm(request.POST, instance=account)
        if form.is_valid():
            form.save()
            return redirect('case:case_detail', slug=account.case.slug)
    else:
        form = AWSAccountForm(instance=account)

    return render(request, 'aws/edit_account.html', {'form': form, 'account': account})

# Delete aws account
@login_required
def delete_account(request, account_id):
    account = get_object_or_404(AWSAccount, id=account_id)
    slug = account.case.slug  # Save the slug for redirection
    account.delete()
    return redirect('case:case_detail', slug=slug)


#This is the trigger for getting the resources of the AWS account.
#It calls a background worker to get the data (need to add progress bar)
@login_required
def pull_resources_view(request, account_id):
    aws_account = get_object_or_404(AWSAccount, account_id=account_id)

    if not aws_account.validated:
        messages.error(request, "Cannot pull resources because the AWS account credentials are not validated.")
        return redirect('case:case_detail', slug=aws_account.case.slug)

    # Trigger background task
    pull_aws_resources_task.delay(account_id)
    messages.info(request, "Resource pulling has started. Refresh the page after after a few minutes to see the results.")

    return redirect('aws:account_resources', account_id=aws_account.account_id)

# Open a modal to show the details of the resources
@login_required
def aws_resource_details(request, resource_id):
    """
    Fetch and return details for a specific AWS resource.
    """
    resource = get_object_or_404(AWSResource, id=resource_id)
    account = resource.account
    case = account.case
    
    return render(request, 'aws/resource_details.html', {
        'resource': resource,
        'account': account,
        'case': case
    })

# this renders both the aws resources and logging sources into one page
@login_required
def account_resources(request, account_id):
    aws_account = get_object_or_404(AWSAccount, account_id=account_id)
    case = aws_account.case

    # Group resources by their type
    resources = AWSResource.objects.filter(account=aws_account).order_by('resource_type', 'resource_name')
    grouped_resources = {}
    for resource in resources:
        grouped_resources.setdefault(resource.resource_type, []).append(resource)

    # Group log sources by service
    log_sources = AWSLogSource.objects.filter(account=aws_account).order_by('service_name', 'log_name')
    grouped_log_sources = {}
    for log_source in log_sources:
        grouped_log_sources.setdefault(log_source.service_name, []).append(log_source)

    # Add error messages if applicable
    error_messages = []
    if not resources.exists():
        error_messages.append("No AWS resources found for this account.")
    if not log_sources.exists():
        error_messages.append("No AWS log sources found for this account.")

    aws_credentials = AWSCredential.objects.filter(account=aws_account)
    
    # Get all available tags
    all_tags = Tag.objects.all()
    
    context = {
        'aws_account': aws_account,
        'case': case,
        'grouped_resources': grouped_resources,
        'grouped_log_sources': grouped_log_sources,
        'error_messages': error_messages,
        'aws_credentials': aws_credentials,
        'all_tags': all_tags,
    }
    return render(request, 'aws/account_resources.html', context)

# The main view to display the overview of the logs for a specific AWS account.
@login_required
def normalized_logs_view(request, account_id):
    aws_account = get_object_or_404(AWSAccount, account_id=account_id)

    # Default date filter: Last day
    end_date = datetime.now()
    start_date = request.GET.get("start_date", (end_date - timedelta(days=1)).strftime("%Y-%m-%d"))
    end_date = request.GET.get("end_date", end_date.strftime("%Y-%m-%d"))

    # Convert to date objects
    start_date = datetime.strptime(start_date, "%Y-%m-%d").date()
    end_date = datetime.strptime(end_date, "%Y-%m-%d").date()

    # Filter logs for the specific AWSAccount within the date range
    logs = NormalizedLog.objects.filter(
        aws_account=aws_account,
        event_time__date__gte=start_date,
        event_time__date__lte=end_date
    )

    # Aggregate top 10 users
    top_users = logs.values('user_identity').annotate(count=Count('user_identity')).order_by('-count')[:10]

    # Aggregate top 10 IPs
    top_ips = logs.values('ip_address').annotate(count=Count('ip_address')).order_by('-count')[:10]

    # Aggregate top 10 events
    top_events = logs.values('event_name').annotate(count=Count('event_name')).order_by('-count')[:10]

    context = {
        "aws_account": aws_account,
        "logs": logs,
        "top_users": top_users,
        "top_ips": top_ips,
        "top_events": top_events,
        "start_date": start_date,
        "end_date": end_date,
    }
    return render(request, "aws/get_logs.html", context)

# Fetch and return details for a specific AWS log source using its slug.
@login_required
def aws_logsource_details(request, slug):
    """
    Fetch and return details for a specific AWS log source.
    """
    log_source = get_object_or_404(AWSLogSource, slug=slug)
    account = log_source.account  # Get the AWS account
    case = account.case
    
    context = {
        'log_source': log_source,
        'account': account,
        'case': case,
        'aws_account': account  # Add this for consistency with other templates
    }
    
    return render(request, 'aws/logsource_details.html', context)

# This allows a user to pull CloudTrail logs that are stored in an s3 bucket. 
@login_required
def browse_s3_structure(request):
    resource_id = request.GET.get("resource_id")
    current_prefix = request.GET.get("current_prefix", "")
    resource = get_object_or_404(AWSResource, id=resource_id)
    account = resource.account

    session = boto3.Session(
        aws_access_key_id=account.aws_access_key,
        aws_secret_access_key=account.aws_secret_key,
        region_name=resource.aws_region or account.aws_region)
    s3 = session.client("s3")
    bucket_name = resource.resource_name or resource.resource_id

    if current_prefix and not current_prefix.endswith("/"):
        current_prefix += "/"

    paginator = s3.get_paginator("list_objects_v2")
    subfolders = []
    files = []
    
    for page in paginator.paginate(Bucket=bucket_name, Prefix=current_prefix, Delimiter="/"):
        # Get subfolders
        for cp in page.get("CommonPrefixes", []):
            subfolders.append(cp["Prefix"])
        
        # Get files
        for obj in page.get("Contents", []):
            if not obj["Key"].endswith("/"):  # Skip folder objects
                files.append({
                    "key": obj["Key"],
                    "size": obj["Size"],
                    "last_modified": obj["LastModified"].isoformat()
                })

    return JsonResponse({
        "subfolders": subfolders,
        "files": files
    })

# Helper function to suggest CloudTrail prefixes based on date range
@login_required
def suggest_cloudtrail_prefix(request):
    """Endpoint to automatically suggest CloudTrail prefixes based on date range"""
    resource_id = request.GET.get("resource_id")
    start_date = request.GET.get("start_date")
    end_date = request.GET.get("end_date")
    
    if not all([resource_id, start_date, end_date]):
        return JsonResponse({"error": "Missing required parameters"}, status=400)
    
    try:
        resource = get_object_or_404(AWSResource, id=resource_id)
        account = resource.account
        
        # Use resource region or fall back to account's default region
        region = resource.aws_region or account.aws_region
        if not region:
            return JsonResponse({"error": "No region specified for resource or account"}, status=400)

        # Convert dates to datetime objects
        start_date = datetime.strptime(start_date, "%Y-%m-%d")
        end_date = datetime.strptime(end_date, "%Y-%m-%d")

        # Generate list of possible prefixes based on date range
        prefixes = []
        current_date = start_date
        while current_date <= end_date:
            # Standard CloudTrail log path structure:
            # AWSLogs/aws-account-id/CloudTrail/region/YYYY/MM/DD/
            prefix = (f"AWSLogs/{account.account_id}/CloudTrail/{region}/"
                     f"{current_date.strftime('%Y/%m/%d/')}")
            prefixes.append(prefix)
            current_date += timedelta(days=1)

        # Also suggest the root CloudTrail directory
        root_prefix = f"AWSLogs/{account.account_id}/CloudTrail/{region}/"
        if root_prefix not in prefixes:
            prefixes.insert(0, root_prefix)

        return JsonResponse({
            "prefixes": prefixes,
            "account_id": account.account_id,
            "region": region
        })
    except Exception as e:
        logger.error(f"Error generating CloudTrail prefixes: {str(e)}")
        return JsonResponse({"error": str(e)}, status=500)

@login_required
def fetch_cloudtrail_logs(request, account_id):
    aws_account = get_object_or_404(AWSAccount, account_id=account_id)
    if request.method == "POST":
        form = FetchCloudTrailLogsForm(request.POST)
        if form.is_valid():
            resource = form.cleaned_data["resource"]
            prefix = form.cleaned_data["prefix"]
            start_date = form.cleaned_data["start_date"]
            end_date = form.cleaned_data["end_date"]

            if resource.account.account_id != aws_account.account_id:
                messages.error(request, "Selected bucket is not linked to this AWS account.")
                return redirect("case:case_detail", slug=resource.case.slug)

            # If prefix doesn't start with the standard CloudTrail structure, construct it
            if not prefix.startswith("AWSLogs/"):
                region = resource.aws_region or aws_account.aws_region
                if not region:
                    messages.error(request, "No region specified for resource or account")
                    return redirect("aws:fetch_cloudtrail_logs", account_id=account_id)
                
                # Construct the full CloudTrail path
                base_prefix = f"AWSLogs/{aws_account.account_id}/CloudTrail/{region}/"
                
                # If prefix is just a date path (YYYY/MM/DD/), append it to base_prefix
                if prefix.count('/') == 3:  # Format: YYYY/MM/DD/
                    prefix = base_prefix + prefix
                else:
                    prefix = base_prefix

            fetch_normalize_cloudtrail_logs_task.delay(
                account_id=aws_account.account_id,
                resource_id=resource.id,
                prefix=prefix,
                start_date=str(start_date),
                end_date=str(end_date),
                case_id=resource.case.id
            )
            messages.success(request, "CloudTrail log fetching has been queued.")
            return redirect("aws:normalized_logs", account_id=aws_account.account_id)
    else:
        form = FetchCloudTrailLogsForm()

    return render(request, "aws/fetch_cloudtrail_logs.html", {
        "form": form, 
        "account_id": account_id,
        "aws_account": aws_account
    })

@login_required
def trigger_management_event_fetch(request, account_id):
    aws_account = get_object_or_404(AWSAccount, account_id=account_id)
    logger.info(f"Triggering fetch for AWS account {account_id}")

    # Trigger background task
    fetch_management_history_task.delay(account_id, aws_account.case.id)
    messages.success(request, "Management event history is being fetched.")
    logger.info(f"Task queued for AWS account {account_id}")

    return redirect("aws:normalized_logs", account_id=aws_account.account_id)

@login_required
def aws_credential_details(request, slug):
    """
    Display detailed information for a specific IAM credential.
    """
    credential = get_object_or_404(AWSCredential, slug=slug)
    
    context = {
        'credential': credential,
        'case': credential.case,
        'aws_account': credential.account,
    }
    
    return render(request, 'aws/credential_details.html', context)

@login_required
def add_tag_to_resource(request, resource_id):
    if request.method == 'POST':
        tag_id = request.POST.get('tag_id')
        try:
            resource = AWSResource.objects.get(id=resource_id)
            tag = Tag.objects.get(id=tag_id)
            resource.tags.add(tag)
            messages.success(request, f'Tag "{tag.name}" added successfully.')
        except (AWSResource.DoesNotExist, Tag.DoesNotExist):
            messages.error(request, 'Error adding tag.')
    return redirect('aws:account_resources', account_id=resource.account.account_id)

@login_required
def add_tag_to_credential(request, credential_id):
    if request.method == 'POST':
        tag_id = request.POST.get('tag_id')
        try:
            credential = AWSCredential.objects.get(id=credential_id)
            tag = Tag.objects.get(id=tag_id)
            credential.tags.add(tag)
            messages.success(request, f'Tag "{tag.name}" added successfully.')
        except (AWSCredential.DoesNotExist, Tag.DoesNotExist):
            messages.error(request, 'Error adding tag.')
    return redirect('aws:account_resources', account_id=credential.account.account_id)

@login_required
def add_tag_to_logsource(request, logsource_id):
    if request.method == 'POST':
        tag_id = request.POST.get('tag_id')
        try:
            logsource = AWSLogSource.objects.get(id=logsource_id)
            tag = Tag.objects.get(id=tag_id)
            logsource.tags.add(tag)
            messages.success(request, f'Tag "{tag.name}" added successfully.')
        except (AWSLogSource.DoesNotExist, Tag.DoesNotExist):
            messages.error(request, 'Error adding tag.')
    return redirect('aws:account_resources', account_id=logsource.account.account_id)

@login_required
def edit_resource_tag(request, resource_id, tag_id):
    if request.method == 'POST':
        new_tag_id = request.POST.get('new_tag_id')
        redirect_url = request.META.get('HTTP_REFERER', '')
        
        try:
            resource = AWSResource.objects.get(id=resource_id)
            old_tag = Tag.objects.get(id=tag_id)
            new_tag = Tag.objects.get(id=new_tag_id)
            
            resource.tags.remove(old_tag)
            resource.tags.add(new_tag)
            messages.success(request, f'Tag updated from "{old_tag.name}" to "{new_tag.name}"')
        except (AWSResource.DoesNotExist, Tag.DoesNotExist):
            messages.error(request, 'Error updating tag.')
        
        if redirect_url:
            return redirect(redirect_url)
    return redirect('aws:account_resources', account_id=resource.account.account_id)

@login_required
def edit_credential_tag(request, credential_id, tag_id):
    if request.method == 'POST':
        new_tag_id = request.POST.get('new_tag_id')
        redirect_url = request.META.get('HTTP_REFERER', '')
        
        try:
            credential = AWSCredential.objects.get(id=credential_id)
            old_tag = Tag.objects.get(id=tag_id)
            new_tag = Tag.objects.get(id=new_tag_id)
            
            credential.tags.remove(old_tag)
            credential.tags.add(new_tag)
            messages.success(request, f'Tag updated from "{old_tag.name}" to "{new_tag.name}"')
        except (AWSCredential.DoesNotExist, Tag.DoesNotExist):
            messages.error(request, 'Error updating tag.')
        
        if redirect_url:
            return redirect(redirect_url)
    return redirect('aws:account_resources', account_id=credential.account.account_id)

@login_required
def edit_logsource_tag(request, logsource_id, tag_id):
    if request.method == 'POST':
        new_tag_id = request.POST.get('new_tag_id')
        redirect_url = request.META.get('HTTP_REFERER', '')
        
        try:
            logsource = AWSLogSource.objects.get(id=logsource_id)
            old_tag = Tag.objects.get(id=tag_id)
            new_tag = Tag.objects.get(id=new_tag_id)
            
            logsource.tags.remove(old_tag)
            logsource.tags.add(new_tag)
            messages.success(request, f'Tag updated from "{old_tag.name}" to "{new_tag.name}"')
        except (AWSLogSource.DoesNotExist, Tag.DoesNotExist):
            messages.error(request, 'Error updating tag.')
        
        if redirect_url:
            return redirect(redirect_url)
    return redirect('aws:account_resources', account_id=logsource.account.account_id)

@login_required
def remove_tag_from_resource(request, resource_id, tag_id):
    if request.method == 'POST':
        redirect_url = request.META.get('HTTP_REFERER', '')
        
        try:
            resource = AWSResource.objects.get(id=resource_id)
            tag = Tag.objects.get(id=tag_id)
            resource.tags.remove(tag)
            messages.success(request, f'Tag "{tag.name}" removed successfully.')
        except (AWSResource.DoesNotExist, Tag.DoesNotExist):
            messages.error(request, 'Error removing tag.')
        
        if redirect_url:
            return redirect(redirect_url)
    return redirect('aws:account_resources', account_id=resource.account.account_id)

@login_required
def remove_tag_from_credential(request, credential_id, tag_id):
    if request.method == 'POST':
        redirect_url = request.META.get('HTTP_REFERER', '')
        
        try:
            credential = AWSCredential.objects.get(id=credential_id)
            tag = Tag.objects.get(id=tag_id)
            credential.tags.remove(tag)
            messages.success(request, f'Tag "{tag.name}" removed successfully.')
        except (AWSCredential.DoesNotExist, Tag.DoesNotExist):
            messages.error(request, 'Error removing tag.')
        
        if redirect_url:
            return redirect(redirect_url)
    return redirect('aws:account_resources', account_id=credential.account.account_id)

@login_required
def remove_tag_from_logsource(request, logsource_id, tag_id):
    if request.method == 'POST':
        redirect_url = request.META.get('HTTP_REFERER', '')
        
        try:
            logsource = AWSLogSource.objects.get(id=logsource_id)
            tag = Tag.objects.get(id=tag_id)
            logsource.tags.remove(tag)
            messages.success(request, f'Tag "{tag.name}" removed successfully.')
        except (AWSLogSource.DoesNotExist, Tag.DoesNotExist):
            messages.error(request, 'Error removing tag.')
        
        if redirect_url:
            return redirect(redirect_url)
    return redirect('aws:account_resources', account_id=logsource.account.account_id)

