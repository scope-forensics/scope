from django.db.models import Q
from apps.data.models import NormalizedLog, DetectionResult
from apps.analysis.models import Detection

def get_case_logs(case_id):
    """Get all logs for a case"""
    logs = NormalizedLog.objects.filter(case_id=case_id)
    print(f"\nFound {logs.count()} logs for case {case_id}")
    return logs

def apply_detection_filters(logs, detection):
    """Apply detection rule filters to logs"""
    print(f"\nApplying filters for detection: {detection.name}")
    
    # Apply event name filter
    if detection.event_name:
        print(f"Filtering for event_name: {detection.event_name}")
        logs = logs.filter(event_name__iexact=detection.event_name)
        print(f"Found {logs.count()} logs with matching event name")
        # Debug: show matching logs
        for log in logs:
            print(f"Matching log - Event: {log.event_name}, Source: {log.event_source}")
    
    # Apply event source filter
    if detection.event_source:
        print(f"Filtering for event_source: {detection.event_source}")
        logs = logs.filter(event_source__iexact=detection.event_source)
        print(f"Found {logs.count()} logs with matching event source")
    
    # Apply event type filter
    if detection.event_type:
        print(f"Filtering for event_type: {detection.event_type}")
        logs = logs.filter(event_type__iexact=detection.event_type)
        print(f"Found {logs.count()} logs with matching event type")
    
    # Apply additional criteria
    if detection.additional_criteria:
        for key, value in detection.additional_criteria.items():
            if key == 'raw_data_contains':
                logs = logs.filter(raw_data__icontains=value)
            elif key == 'ip_address':
                logs = logs.filter(ip_address=value)
            elif key == 'user_identity':
                logs = logs.filter(user_identity=value)
    
    return logs

def tag_matching_logs(logs, detection):
    """Add detection tags to matching logs"""
    for log in logs:
        log.tags.add(*detection.auto_tags.all())

def run_detection(case_id, account_id, detection):
    """Run a single detection rule"""
    # Get base logs
    logs = get_case_logs(case_id)
    
    # Apply detection filters
    matching_logs = apply_detection_filters(logs, detection)
    
    # Create detection results and tag logs
    for log in matching_logs:
        # Create detection result if it doesn't exist
        DetectionResult.objects.get_or_create(
            case_id=case_id,
            detection=detection,
            matched_log=log
        )
        # Tag the log
        log.tags.add(*detection.auto_tags.all())
    
    return matching_logs

def run_all_detections(case_id, account_id):
    """Run all enabled AWS detections"""
    results = []
    detections = Detection.objects.filter(enabled=True, cloud='aws')
    
    for detection in detections:
        matching_logs = run_detection(case_id, account_id, detection)
        results.append({
            'detection': detection,
            'matches': matching_logs.count(),
            'matching_logs': matching_logs
        })
    
    return results
