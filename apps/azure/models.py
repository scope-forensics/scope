from django.db import models
from django.conf import settings
from apps.case.models import Case
from django.utils.text import slugify
from apps.data.models import Tag

class AzureAccount(models.Model):
    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name='azure_accounts')
    subscription_id = models.CharField(max_length=50, unique=True)
    tenant_id = models.CharField(max_length=50)
    client_id = models.CharField(max_length=100)  # Application (client) ID
    client_secret = models.CharField(max_length=100)  # Client secret
    added_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='added_azure_accounts')
    added_at = models.DateTimeField(auto_now_add=True)
    validated = models.BooleanField(default=False)

    def __str__(self):
        return f"Azure Subscription {self.subscription_id} for Case {self.case.name}"

#Get an overview of all the resources in the subscription for analysis
class AzureResource(models.Model):
    account = models.ForeignKey('AzureAccount', on_delete=models.CASCADE, related_name='resources')
    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name='azure_resources')
    resource_id = models.CharField(max_length=200)  # Azure Resource ID
    resource_type = models.CharField(max_length=100)  # e.g., Microsoft.Compute/virtualMachines
    resource_name = models.CharField(max_length=200, blank=True, null=True)
    resource_group = models.CharField(max_length=200)
    resource_details = models.JSONField(blank=True, null=True)
    location = models.CharField(max_length=50, blank=True, null=True)  # Azure region
    slug = models.SlugField(max_length=255, unique=True, blank=True)
    discovered_at = models.DateTimeField(auto_now_add=True)

    # Tags
    tags = models.ManyToManyField(Tag, related_name='azure_resource')

    def save(self, *args, **kwargs):
        if not self.slug:
            base_slug = slugify(f"{self.resource_type}-{self.resource_name}")
            unique_slug = base_slug
            num = 1
            while AzureResource.objects.filter(slug=unique_slug).exists():
                unique_slug = f"{base_slug}-{num}"
                num += 1
            self.slug = unique_slug
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.resource_type} - {self.resource_name or self.resource_id}"

#Represents different Azure logging sources like Activity Logs and sign in logs
class AzureLogSource(models.Model):
    
    account = models.ForeignKey('AzureAccount', on_delete=models.CASCADE, related_name='log_sources')
    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name='azure_log_sources')
    service_name = models.CharField(max_length=100)  # e.g., ActivityLogs, DiagnosticSettings
    log_name = models.CharField(max_length=255)
    log_details = models.JSONField(blank=True, null=True)
    status = models.CharField(max_length=50)
    location = models.CharField(max_length=50, blank=True, null=True)
    slug = models.SlugField(max_length=255, unique=True, blank=True)
    discovered_at = models.DateTimeField(auto_now_add=True)

    # Tags
    tags = models.ManyToManyField(Tag, related_name='azure_log_source')

    def save(self, *args, **kwargs):
        if not self.slug:
            base_slug = slugify(f"{self.service_name}-{self.log_name}")
            unique_slug = base_slug
            num = 1
            while AzureLogSource.objects.filter(slug=unique_slug).exists():
                unique_slug = f"{base_slug}-{num}"
                num += 1
            self.slug = unique_slug
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.service_name} - {self.log_name}"


# Model to store Azure AD identities and their details
class AzureIdentity(models.Model):
    account = models.ForeignKey(AzureAccount, on_delete=models.CASCADE, related_name='identities')
    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name='azure_identities')
    
    # Identity details
    object_id = models.CharField(max_length=100)
    display_name = models.CharField(max_length=300)
    user_principal_name = models.CharField(max_length=300, null=True, blank=True)
    identity_type = models.CharField(max_length=50)  # user, service_principal, managed_identity
    
    # Security details
    mfa_enabled = models.BooleanField(default=False)
    created_datetime = models.DateTimeField(null=True, blank=True)
    last_sign_in = models.DateTimeField(null=True, blank=True)
    account_enabled = models.BooleanField(default=True)
    
    # Additional details stored as JSON
    assigned_roles = models.JSONField(blank=True, null=True)
    identity_details = models.JSONField(blank=True, null=True)
    
    slug = models.SlugField(max_length=255, unique=True, blank=True)
    discovered_at = models.DateTimeField(auto_now_add=True)

    # Tags
    tags = models.ManyToManyField(Tag, related_name='azure_identity')

    class Meta:
        unique_together = ('account', 'object_id')
        verbose_name_plural = "Azure identities"

    def save(self, *args, **kwargs):
        if not self.slug:
            base_slug = slugify(f"{self.identity_type}-{self.display_name}")
            unique_slug = base_slug
            num = 1
            while AzureIdentity.objects.filter(slug=unique_slug).exists():
                unique_slug = f"{base_slug}-{num}"
                num += 1
            self.slug = unique_slug
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.display_name} ({self.identity_type})"
