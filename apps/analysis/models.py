from django.db import models
from apps.data.models import Tag

class Detection(models.Model):
    CLOUD_CHOICES = [
        ('aws', 'Amazon Web Services'),
        ('gcp', 'Google Cloud Platform'),
        ('azure', 'Microsoft Azure'),
    ]
    
    DETECTION_TYPE = [
        ('api_call', 'API Call'),
        ('login', 'Login Activity'),
        ('data_access', 'Data Access'),
        ('network', 'Network Activity'),
        ('iam', 'IAM Changes'),
        ('other', 'Other')
    ]
    
    SEVERITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical')
    ]

    name = models.CharField(max_length=200)
    description = models.TextField()
    cloud = models.CharField(max_length=10, choices=CLOUD_CHOICES)
    detection_type = models.CharField(max_length=20, choices=DETECTION_TYPE)
    enabled = models.BooleanField(default=True)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='medium')
    
    # Detection criteria
    event_source = models.CharField(max_length=1000, blank=True, null=True)
    event_name = models.CharField(max_length=1000, blank=True, null=True)
    event_type = models.CharField(max_length=1000, blank=True, null=True)
    
    # Additional filters as JSON
    additional_criteria = models.JSONField(default=dict, blank=True)
    
    # Auto-tag matches with these tags
    auto_tags = models.ManyToManyField(Tag, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name} ({self.cloud})"