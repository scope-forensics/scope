from django import forms
from .models import Detection

class DetectionForm(forms.ModelForm):
    class Meta:
        model = Detection
        fields = ['name', 'description', 'cloud', 'detection_type', 'severity',
                 'event_source', 'event_name', 'event_type', 'additional_criteria',
                 'auto_tags', 'enabled']
        
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Add Bootstrap classes to all fields
        for field in self.fields.values():
            if isinstance(field.widget, forms.TextInput) or \
               isinstance(field.widget, forms.Select) or \
               isinstance(field.widget, forms.Textarea):
                field.widget.attrs.update({'class': 'form-control'})
            elif isinstance(field.widget, forms.CheckboxInput):
                field.widget.attrs.update({'class': 'form-check-input'})
        self.fields['additional_criteria'].widget = forms.Textarea(attrs={'rows': 4}) 