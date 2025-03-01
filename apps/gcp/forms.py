from django import forms
from .models import GCPAccount
import json

class GCPAccountForm(forms.ModelForm):
    service_account_key = forms.FileField(
        help_text="Upload your service account key JSON file",
        widget=forms.FileInput(attrs={'class': 'form-control'})
    )

    class Meta:
        model = GCPAccount
        fields = ['project_id']
        widgets = {
            'project_id': forms.TextInput(attrs={
                'placeholder': 'e.g., my-project-123456',
                'class': 'form-control'
            })
        }
        labels = {
            'project_id': 'Project ID',
        }
        help_texts = {
            'project_id': 'Found in GCP Console under Project Info',
        }

    def clean_service_account_key(self):
        file = self.cleaned_data['service_account_key']
        try:
            content = file.read().decode('utf-8')
            json_content = json.loads(content)
            
            required_fields = ['type', 'project_id', 'private_key_id', 'private_key', 'client_email']
            for field in required_fields:
                if field not in json_content:
                    raise forms.ValidationError(f"Service account key is missing required field: {field}")
            
            if json_content['type'] != 'service_account':
                raise forms.ValidationError("Invalid service account key format")
            
            return json_content
        except json.JSONDecodeError:
            raise forms.ValidationError("Invalid JSON format in service account key file")
        except Exception as e:
            raise forms.ValidationError(f"Error processing service account key: {str(e)}")

    def save(self, commit=True):
        instance = super().save(commit=False)
        instance.service_account_info = self.cleaned_data['service_account_key']
        if commit:
            instance.save()
        return instance
