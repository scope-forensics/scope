from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db.models import Q
from apps.data.models import NormalizedLog

@login_required
def NormalizedLogListView(request):
    # Get all logs and apply default sorting
    queryset = NormalizedLog.objects.all().order_by('-event_time')
    
    # Get filter parameters from request
    search_query = request.GET.get('search', '')
    field_filter = request.GET.get('field', '')
    field_value = request.GET.get('field_value', '')
    sort_order = request.GET.get('sort', '-event_time')
    
    # Apply search if query exists
    if search_query:
        queryset = queryset.filter(
            Q(event_name__icontains=search_query) |
            Q(event_source__icontains=search_query) |
            Q(event_type__icontains=search_query) |
            Q(user_identity__icontains=search_query) |
            Q(resources__icontains=search_query)
        )
    
    # Apply field-specific filter if specified
    if field_filter and field_value:
        filter_kwargs = {f"{field_filter}__icontains": field_value}
        queryset = queryset.filter(**filter_kwargs)
    
    # Apply sorting
    queryset = queryset.order_by(sort_order.replace('timestamp', 'event_time'))
    
    # Pagination
    paginator = Paginator(queryset, 50)  # Show 50 logs per page
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)
    
    context = {
        'object_list': page_obj,
        'page_obj': page_obj,
        'search_query': search_query,
        'field_filter': field_filter,
        'field_value': field_value,
        'sort_order': sort_order,
        'is_paginated': page_obj.has_other_pages(),
    }
    
    return render(request, 'data/normalized_logs.html', context)
