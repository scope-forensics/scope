from django import forms
from .models import AzureAccount, AzureResource

class AzureAccountForm(forms.ModelForm):
    """Form for connecting an Azure subscription using service principal credentials"""
    class Meta:
        model = AzureAccount
        fields = ['subscription_id', 'tenant_id', 'client_id', 'client_secret']
        widgets = {
            'client_secret': forms.PasswordInput(),
            'subscription_id': forms.TextInput(attrs={
                'placeholder': 'e.g., 12345678-1234-5678-1234-567812345678',
                'class': 'form-control'
            }),
            'tenant_id': forms.TextInput(attrs={
                'placeholder': 'e.g., 87654321-4321-8765-4321-876543210987',
                'class': 'form-control'
            }),
            'client_id': forms.TextInput(attrs={
                'placeholder': 'e.g., 11111111-2222-3333-4444-555555555555',
                'class': 'form-control'
            })
        }
        labels = {
            'subscription_id': 'Subscription ID',
            'tenant_id': 'Directory (tenant) ID',
            'client_id': 'Application (client) ID',
            'client_secret': 'Client Secret'
        }
        help_texts = {
            'subscription_id': 'Found in Azure Portal under Subscriptions',
            'tenant_id': 'Found in Azure Active Directory → Overview',
            'client_id': 'Found in App Registration → Overview',
            'client_secret': 'Created in App Registration → Certificates & secrets'
        }

class FetchActivityLogsForm(forms.Form):
    """Form for fetching Azure Activity Logs"""
    start_date = forms.DateField(
        label="Start Date",
        widget=forms.DateInput(attrs={
            "type": "date", 
            "class": "form-control"
        })
    )
    end_date = forms.DateField(
        label="End Date",
        widget=forms.DateInput(attrs={
            "type": "date", 
            "class": "form-control"
        })
    )
