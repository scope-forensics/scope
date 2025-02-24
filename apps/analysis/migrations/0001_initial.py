# Generated by Django 5.1.3 on 2025-02-13 23:50

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('data', '0004_alter_normalizedlog_unique_together'),
    ]

    operations = [
        migrations.CreateModel(
            name='Detection',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=200)),
                ('description', models.TextField()),
                ('cloud', models.CharField(choices=[('aws', 'Amazon Web Services'), ('gcp', 'Google Cloud Platform'), ('azure', 'Microsoft Azure')], max_length=10)),
                ('detection_type', models.CharField(choices=[('api_call', 'API Call'), ('login', 'Login Activity'), ('data_access', 'Data Access'), ('network', 'Network Activity'), ('iam', 'IAM Changes'), ('other', 'Other')], max_length=20)),
                ('enabled', models.BooleanField(default=True)),
                ('severity', models.CharField(choices=[('low', 'Low'), ('medium', 'Medium'), ('high', 'High'), ('critical', 'Critical')], default='medium', max_length=10)),
                ('event_source', models.CharField(blank=True, max_length=1000, null=True)),
                ('event_name', models.CharField(blank=True, max_length=1000, null=True)),
                ('event_type', models.CharField(blank=True, max_length=1000, null=True)),
                ('additional_criteria', models.JSONField(blank=True, default=dict)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('auto_tags', models.ManyToManyField(blank=True, to='data.tag')),
            ],
        ),
    ]
