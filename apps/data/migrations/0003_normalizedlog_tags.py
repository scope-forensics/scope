# Generated by Django 5.1.3 on 2025-01-24 03:07

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('data', '0002_tag_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='normalizedlog',
            name='tags',
            field=models.ManyToManyField(related_name='normalized_logs', to='data.tag'),
        ),
    ]
