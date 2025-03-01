from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db.models import Q
from apps.data.models import NormalizedLog, Tag
from datetime import datetime
from django.contrib import messages
from apps.aws.models import AWSAccount
from apps.azure.models import AzureAccount

@login_required
def NormalizedLogListView(request):
    # Get account filter from query params
    account_filter = request.GET.get('account')
    case = None
    
    # Start with all logs
    queryset = NormalizedLog.objects.all().order_by('-event_time')
    
    # Parse account filter (format: "aws:account_id" or "azure:subscription_id")
    if account_filter:
        account_type, account_id = account_filter.split(':')
        if account_type == 'aws':
            aws_account = get_object_or_404(AWSAccount, account_id=account_id)
            queryset = queryset.filter(aws_account=aws_account)
            case = aws_account.case
        elif account_type == 'azure':
            azure_account = get_object_or_404(AzureAccount, subscription_id=account_id)
            queryset = queryset.filter(azure_account=azure_account)
            case = azure_account.case
    
    # Get unique accounts that have logs
    accounts = []
    aws_accounts = AWSAccount.objects.filter(
        normalized_logs__isnull=False
    ).distinct()
    azure_accounts = AzureAccount.objects.filter(
        normalized_logs__isnull=False
    ).distinct()
    
    for aws_acc in aws_accounts:
        accounts.append({
            'id': f'aws:{aws_acc.account_id}',
            'name': f'AWS Account: {aws_acc.account_id}',
            'type': 'aws'
        })
    
    for azure_acc in azure_accounts:
        accounts.append({
            'id': f'azure:{azure_acc.subscription_id}',
            'name': f'Azure Account: {azure_acc.subscription_id}',
            'type': 'azure'
        })

    search_query = request.GET.get('search', '')
    field_filter = request.GET.get('field', '')
    field_value = request.GET.get('field_value', '')
    sort_order = request.GET.get('sort', '-event_time')
    start_date = request.GET.get('start_date', '')
    end_date = request.GET.get('end_date', '')
    
    # Validate sort_order field
    valid_sort_fields = [
        'event_time', '-event_time',
        'event_type', '-event_type',
        'event_source', '-event_source',
        'event_name', '-event_name',
        'user_identity', '-user_identity',
        'region', '-region',
        'ip_address', '-ip_address'
    ]
    if sort_order not in valid_sort_fields:
        sort_order = '-event_time'
    
    if start_date:
        try:
            start_date = datetime.strptime(start_date, '%Y-%m-%d')
            queryset = queryset.filter(event_time__gte=start_date)
        except ValueError:
            pass
    
    if end_date:
        try:
            end_date = datetime.strptime(end_date, '%Y-%m-%d')
            queryset = queryset.filter(event_time__lte=end_date)
        except ValueError:
            pass
    
    if search_query:
        queryset = queryset.filter(
            Q(event_name__icontains=search_query) |
            Q(event_source__icontains=search_query) |
            Q(event_type__icontains=search_query) |
            Q(user_identity__icontains=search_query) |
            Q(region__icontains=search_query) |
            Q(resources__icontains=search_query)
        )
    
    if field_filter and field_value:
        filter_kwargs = {f"{field_filter}__icontains": field_value}
        queryset = queryset.filter(**filter_kwargs)
    
    queryset = queryset.order_by(sort_order)
    
    all_tags = Tag.objects.all()
    
    paginator = Paginator(queryset, 100)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)
    
    context = {
        'object_list': page_obj,
        'page_obj': page_obj,
        'search_query': search_query,
        'field_filter': field_filter,
        'field_value': field_value,
        'sort_order': sort_order,
        'start_date': start_date,
        'end_date': end_date,
        'is_paginated': page_obj.has_other_pages(),
        'all_tags': all_tags,
        'accounts': accounts,
        'selected_account': account_filter,
        'case': case
    }
    
    return render(request, 'data/normalized_logs.html', context)

@login_required
def add_tag_to_log(request, log_id):
    if request.method == 'POST':
        tag_id = request.POST.get('tag_id')
        # Get the referer URL with all its query parameters
        redirect_url = request.META.get('HTTP_REFERER', '')
        
        try:
            log = NormalizedLog.objects.get(id=log_id)
            tag = Tag.objects.get(id=tag_id)
            log.tags.add(tag)
            messages.success(request, f'Tag "{tag.name}" added successfully.')
        except (NormalizedLog.DoesNotExist, Tag.DoesNotExist):
            messages.error(request, 'Error adding tag.')
        
        # If we have a referer URL, redirect back to it to preserve filters
        if redirect_url:
            return redirect(redirect_url)
            
    return redirect('data:normalized_logs')

@login_required
def edit_log_tag(request, log_id, tag_id):
    if request.method == 'POST':
        new_tag_id = request.POST.get('new_tag_id')
        redirect_url = request.META.get('HTTP_REFERER', '')
        
        try:
            log = NormalizedLog.objects.get(id=log_id)
            old_tag = Tag.objects.get(id=tag_id)
            new_tag = Tag.objects.get(id=new_tag_id)
            
            # Remove old tag and add new tag
            log.tags.remove(old_tag)
            log.tags.add(new_tag)
            
            messages.success(request, f'Tag updated from "{old_tag.name}" to "{new_tag.name}"')
        except (NormalizedLog.DoesNotExist, Tag.DoesNotExist):
            messages.error(request, 'Error updating tag.')
        
        if redirect_url:
            return redirect(redirect_url)
            
    return redirect('data:normalized_logs')

@login_required
def remove_log_tag(request, log_id, tag_id):
    if request.method == 'POST':
        redirect_url = request.META.get('HTTP_REFERER', '')
        
        try:
            log = NormalizedLog.objects.get(id=log_id)
            tag = Tag.objects.get(id=tag_id)
            log.tags.remove(tag)
            messages.success(request, f'Tag "{tag.name}" removed successfully.')
        except (NormalizedLog.DoesNotExist, Tag.DoesNotExist):
            messages.error(request, 'Error removing tag.')
        
        if redirect_url:
            return redirect(redirect_url)
            
    return redirect('data:normalized_logs')
