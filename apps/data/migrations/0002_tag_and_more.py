# Generated by Django 5.1.3 on 2025-01-24 03:03

import django.contrib.postgres.indexes
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('aws', '0001_initial'),
        ('case', '0001_initial'),
        ('data', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Tag',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=1000)),
                ('description', models.TextField(blank=True, null=True)),
                ('slug', models.SlugField(max_length=1000, unique=True)),
            ],
        ),
        migrations.RemoveIndex(
            model_name='normalizedlog',
            name='data_normal_log_sou_bee0df_btree',
        ),
        migrations.RemoveIndex(
            model_name='normalizedlog',
            name='data_normal_log_typ_a9e795_btree',
        ),
        migrations.RemoveField(
            model_name='normalizedlog',
            name='extra_data',
        ),
        migrations.RemoveField(
            model_name='normalizedlog',
            name='log_id',
        ),
        migrations.RemoveField(
            model_name='normalizedlog',
            name='log_source',
        ),
        migrations.RemoveField(
            model_name='normalizedlog',
            name='log_type',
        ),
        migrations.AddField(
            model_name='normalizedlog',
            name='event_id',
            field=models.CharField(blank=True, max_length=1000, null=True),
        ),
        migrations.AddField(
            model_name='normalizedlog',
            name='event_source',
            field=models.CharField(blank=True, choices=[('aws', 'Amazon Web Services'), ('gcp', 'Google Cloud Platform'), ('azure', 'Microsoft Azure')], db_index=True, max_length=1000, null=True),
        ),
        migrations.AddField(
            model_name='normalizedlog',
            name='event_type',
            field=models.CharField(blank=True, db_index=True, max_length=1000, null=True),
        ),
        migrations.AddField(
            model_name='normalizedlog',
            name='file_name',
            field=models.CharField(blank=True, max_length=2000, null=True),
        ),
        migrations.AddField(
            model_name='normalizedlog',
            name='region',
            field=models.CharField(blank=True, max_length=1000, null=True),
        ),
        migrations.AddField(
            model_name='normalizedlog',
            name='user_agent',
            field=models.CharField(blank=True, max_length=3000, null=True),
        ),
        migrations.AlterField(
            model_name='normalizedlog',
            name='event_name',
            field=models.CharField(blank=True, db_index=True, max_length=1000, null=True),
        ),
        migrations.AlterField(
            model_name='normalizedlog',
            name='event_time',
            field=models.DateTimeField(blank=True, db_index=True, null=True),
        ),
        migrations.AlterField(
            model_name='normalizedlog',
            name='user_identity',
            field=models.CharField(blank=True, max_length=1000, null=True),
        ),
        migrations.AddIndex(
            model_name='normalizedlog',
            index=django.contrib.postgres.indexes.BTreeIndex(fields=['event_source'], name='data_normal_event_s_9d3f1d_btree'),
        ),
        migrations.AddIndex(
            model_name='normalizedlog',
            index=django.contrib.postgres.indexes.BTreeIndex(fields=['user_agent'], name='data_normal_user_ag_bd607d_btree'),
        ),
        migrations.AddIndex(
            model_name='normalizedlog',
            index=django.contrib.postgres.indexes.BTreeIndex(fields=['region'], name='data_normal_region_72366d_btree'),
        ),
    ]
