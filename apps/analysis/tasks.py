from celery import shared_task
from .detections import run_all_detections

@shared_task
def run_detections_task(case_id, account_id):
    """Celery task to run detections"""
    results = run_all_detections(case_id, account_id)
    
    total_matches = sum(r['matches'] for r in results)
    
    return {
        'total_detections': len(results),
        'total_matches': total_matches
    }
