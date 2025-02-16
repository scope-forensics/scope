from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse
from .models import Detection
from apps.data.models import DetectionResult, NormalizedLog
from .forms import DetectionForm
from .tasks import run_detections_task
from apps.case.models import Case
from django.core.management import call_command
from io import StringIO
from apps.aws.models import AWSAccount
from .models import Tag

@login_required
def detection_list(request, case_id):
    case = get_object_or_404(Case, id=case_id)
    detections = Detection.objects.all()
    return render(request, 'analysis/detection_list.html', {
        'detections': detections,
        'case': case
    })

@login_required
def detection_create(request, case_id):
    case = get_object_or_404(Case, id=case_id)
    if request.method == 'POST':
        form = DetectionForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Detection rule created successfully.')
            return redirect('analysis:detection_list', case_id=case_id)
    else:
        form = DetectionForm()
    
    return render(request, 'analysis/detection_form.html', {
        'form': form,
        'is_create': True,
        'case': case
    })

@login_required
def detection_edit(request, case_id, pk):
    case = get_object_or_404(Case, id=case_id)
    detection = get_object_or_404(Detection, pk=pk)
    
    if request.method == 'POST':
        form = DetectionForm(request.POST, instance=detection)
        if form.is_valid():
            form.save()
            messages.success(request, 'Detection rule updated successfully.')
            return redirect('analysis:detection_list', case_id=case_id)
    else:
        form = DetectionForm(instance=detection)
    
    return render(request, 'analysis/detection_form.html', {
        'form': form,
        'is_create': False,
        'detection': detection,
        'case': case
    })

@login_required
def detection_delete(request, case_id, pk):
    case = get_object_or_404(Case, id=case_id)
    detection = get_object_or_404(Detection, pk=pk)
    
    if request.method == 'POST':
        detection.delete()
        messages.success(request, 'Detection rule deleted successfully.')
        return redirect('analysis:detection_list', case_id=case_id)
    
    return render(request, 'analysis/detection_confirm_delete.html', {
        'detection': detection,
        'case': case
    })

@login_required
def run_detections(request, case_id):
    """Trigger detection run for a case"""
    if request.method == 'POST':
        # Debug: Check if the log exists at all
        print("\nChecking for GetCallerIdentity logs:")
        all_logs = NormalizedLog.objects.filter(
            event_name='GetCallerIdentity'
        )
        print(f"Found {all_logs.count()} total GetCallerIdentity logs")
        for log in all_logs:
            print(f"Case ID: {log.case_id}")
            print(f"AWS Account ID: {log.aws_account_id}")
            print(f"Event source: {log.event_source}")
            print(f"Event name: {log.event_name}")
            print("---")

        # Get the AWS account for this case
        aws_account = AWSAccount.objects.filter(case_id=case_id).first()
        if not aws_account:
            messages.error(request, 'No AWS account found for this case')
            return redirect('analysis:case_detections', case_id=case_id)
            
        task = run_detections_task.delay(case_id, aws_account.account_id)
        messages.success(request, 'Detection scan started. Results will be available shortly.')
        return redirect('analysis:case_detections', case_id=case_id)
    return redirect('analysis:case_detections', case_id=case_id)

@login_required
def detection_results(request, case_id):
    results = DetectionResult.objects.filter(
        case_id=case_id
    ).select_related('detection', 'matched_log')
    
    return render(request, 'analysis/detection_results.html', {
        'results': results
    })

@login_required
def case_detections(request, case_id):
    """Main detections page showing results and management options"""
    case = get_object_or_404(Case, id=case_id)
    detection_results = DetectionResult.objects.filter(
        case_id=case_id
    ).select_related('detection', 'matched_log').order_by('-created_at')
    
    # Get all available tags
    available_tags = Tag.objects.all()
    
    # Group results by detection
    results_by_detection = {}
    for result in detection_results:
        if result.detection not in results_by_detection:
            results_by_detection[result.detection] = []
        results_by_detection[result.detection].append(result)

    context = {
        'case': case,
        'results_by_detection': results_by_detection,
        'total_results': detection_results.count(),
        'detection_count': Detection.objects.filter(enabled=True).count(),
        'available_tags': available_tags
    }
    
    return render(request, 'analysis/case_detections.html', context)

@login_required
def load_prebuilt_rules(request, case_id):
    if request.method == 'POST':
        try:
            # Capture command output
            out = StringIO()
            call_command('load_detection_rules', stdout=out)
            messages.success(request, 'Pre-built detection rules loaded successfully')
            return redirect('analysis:detection_list', case_id=case_id)
        except Exception as e:
            messages.error(request, f'Error loading pre-built rules: {str(e)}')
            return redirect('analysis:detection_list', case_id=case_id)
    return redirect('analysis:detection_list', case_id=case_id)

@login_required
def tag_detection_result(request, case_id, result_id):
    if request.method == 'POST':
        result = get_object_or_404(DetectionResult, id=result_id, case_id=case_id)
        tag_ids = request.POST.getlist('tag_ids')
        
        # Clear existing tags
        result.matched_log.tags.clear()
        
        # Add selected tags
        if tag_ids:
            tags = Tag.objects.filter(id__in=tag_ids)
            result.matched_log.tags.add(*tags)
            messages.success(request, 'Tags updated successfully')
    
    return redirect('analysis:case_detections', case_id=case_id)

@login_required
def get_detection_result_tags(request, result_id):
    result = get_object_or_404(DetectionResult, id=result_id)
    tags = list(result.matched_log.tags.values_list('id', flat=True))
    return JsonResponse({'tags': tags})
