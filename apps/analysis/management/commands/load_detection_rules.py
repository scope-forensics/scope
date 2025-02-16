from django.core.management.base import BaseCommand
from django.db import transaction
from apps.analysis.models import Detection
from apps.data.models import Tag
import yaml
import os
from pathlib import Path

class Command(BaseCommand):
    help = 'Load pre-built detection rules from YAML files'

    def add_arguments(self, parser):
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force reload all rules, overwriting existing ones',
        )

    def handle(self, *args, **options):
        rules_dir = Path(__file__).resolve().parent.parent.parent / 'detection_rules'
        force = options['force']

        for yaml_file in rules_dir.glob('*.yaml'):
            self.stdout.write(f'Processing {yaml_file.name}...')
            
            with open(yaml_file) as f:
                rules = yaml.safe_load(f)

            with transaction.atomic():
                for rule in rules:
                    # Handle auto_tags
                    auto_tags = rule.pop('auto_tags', [])
                    
                    # Create or get the detection rule
                    detection, created = Detection.objects.update_or_create(
                        name=rule['name'],
                        defaults=rule
                    )

                    if created:
                        self.stdout.write(self.style.SUCCESS(
                            f'Created detection rule: {detection.name}'
                        ))
                    elif force:
                        self.stdout.write(self.style.WARNING(
                            f'Updated existing detection rule: {detection.name}'
                        ))
                    else:
                        self.stdout.write(self.style.NOTICE(
                            f'Skipped existing detection rule: {detection.name}'
                        ))

                    # Handle tags
                    if created or force:
                        # Clear existing tags if updating
                        detection.auto_tags.clear()
                        
                        # Create and add tags
                        for tag_name in auto_tags:
                            tag, _ = Tag.objects.get_or_create(
                                name=tag_name.title(),
                                slug=tag_name.lower().replace(' ', '-')
                            )
                            detection.auto_tags.add(tag)

        self.stdout.write(self.style.SUCCESS('Successfully loaded detection rules')) 