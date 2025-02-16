from django.urls import path
from . import views

app_name = 'analysis'

urlpatterns = [
    path('case/<int:case_id>/detections/', views.case_detections, name='case_detections'),
    path('case/<int:case_id>/detections/rules/', views.detection_list, name='detection_list'),
    path('case/<int:case_id>/detections/rules/create/', views.detection_create, name='detection_create'),
    path('case/<int:case_id>/detections/rules/<int:pk>/edit/', views.detection_edit, name='detection_edit'),
    path('case/<int:case_id>/detections/rules/<int:pk>/delete/', views.detection_delete, name='detection_delete'),
    path('case/<int:case_id>/detections/run/', views.run_detections, name='run_detections'),
    path('case/<int:case_id>/detections/rules/load-prebuilt/', views.load_prebuilt_rules, name='load_prebuilt_rules'),
    path('case/<int:case_id>/detection-result/<int:result_id>/tag/', 
         views.tag_detection_result, name='tag_detection_result'),
    path('api/detection-result/<int:result_id>/tags/', 
         views.get_detection_result_tags, name='get_detection_result_tags'),
] 