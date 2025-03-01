from django.db import models
from django.conf import settings
from apps.case.models import Case
from django.utils.text import slugify
from apps.data.models import Tag

class GCPAccount(models.Model):
    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name='gcp_accounts')
    project_id = models.CharField(max_length=100, unique=True)
    service_account_info = models.JSONField()  # Stores the service account key JSON
    added_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='added_gcp_accounts')
    added_at = models.DateTimeField(auto_now_add=True)
    validated = models.BooleanField(default=False)

    def __str__(self):
        return f"GCP Project {self.project_id} for Case {self.case.name}"

class GCPResource(models.Model):
    account = models.ForeignKey('GCPAccount', on_delete=models.CASCADE, related_name='resources')
    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name='gcp_resources')
    resource_id = models.CharField(max_length=200)
    resource_type = models.CharField(max_length=100)  # e.g., compute.googleapis.com/Instance
    resource_name = models.CharField(max_length=200)
    location = models.CharField(max_length=50, blank=True, null=True)  # GCP region/zone
    resource_details = models.JSONField(blank=True, null=True)
    slug = models.SlugField(max_length=255, unique=True, blank=True)
    discovered_at = models.DateTimeField(auto_now_add=True)
    
    tags = models.ManyToManyField(Tag, related_name='gcp_resource')

    def save(self, *args, **kwargs):
        if not self.slug:
            base_slug = slugify(f"{self.resource_type}-{self.resource_name}")
            unique_slug = base_slug
            num = 1
            while GCPResource.objects.filter(slug=unique_slug).exists():
                unique_slug = f"{base_slug}-{num}"
                num += 1
            self.slug = unique_slug
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.resource_type} - {self.resource_name}"

class GCPLogSource(models.Model):
    account = models.ForeignKey('GCPAccount', on_delete=models.CASCADE, related_name='log_sources')
    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name='gcp_log_sources')
    service_name = models.CharField(max_length=100)  # e.g., CloudAudit.googleapis.com
    log_name = models.CharField(max_length=255)
    log_details = models.JSONField(blank=True, null=True)
    status = models.CharField(max_length=50)
    location = models.CharField(max_length=50, blank=True, null=True)
    slug = models.SlugField(max_length=255, unique=True, blank=True)
    discovered_at = models.DateTimeField(auto_now_add=True)
    
    tags = models.ManyToManyField(Tag, related_name='gcp_log_source')

    def save(self, *args, **kwargs):
        if not self.slug:
            base_slug = slugify(f"{self.service_name}-{self.log_name}")
            unique_slug = base_slug
            num = 1
            while GCPLogSource.objects.filter(slug=unique_slug).exists():
                unique_slug = f"{base_slug}-{num}"
                num += 1
            self.slug = unique_slug
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.service_name} - {self.log_name}"
