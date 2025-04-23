"""
AWS timeline generation module for creating forensic timelines from CloudTrail logs.
"""

import csv
import json
import logging
import os
from datetime import datetime

logger = logging.getLogger(__name__)

class AWSTimeline:
    """
    Creates forensic timelines from AWS CloudTrail events.
    """
    
    def __init__(self, events=None):
        """
        Initialize the AWS timeline generator.
        
        Args:
            events (list, optional): List of normalized CloudTrail events.
        """
        self.events = events or []
        self.csv_fields = [
            'event_time', 'event_name', 'event_source', 'username', 
            'aws_region', 'source_ip', 'user_agent', 'event_id'
        ]
        
    def add_events(self, events):
        """
        Add events to the timeline.
        
        Args:
            events (list): List of normalized CloudTrail events.
        """
        self.events.extend(events)
        
    def sort_events(self):
        """
        Sort events by timestamp.
        """
        self.events.sort(key=lambda x: x['event_time'] if x['event_time'] else datetime.max)
        
    def filter_events(self, filter_func):
        """
        Filter events using a custom filter function.
        
        Args:
            filter_func (callable): Function that takes an event and returns True to keep it.
            
        Returns:
            list: Filtered list of events.
        """
        return [event for event in self.events if filter_func(event)]
        
    def export_csv(self, output_file, fields=None):
        """
        Export timeline to CSV format.
        
        Args:
            output_file (str): Path to output CSV file.
            fields (list, optional): List of fields to include. If None, includes standard fields.
            
        Returns:
            str: Path to the created CSV file.
        """
        if not fields:
            fields = [
                'event_time', 'event_name', 'event_source', 'username', 
                'aws_region', 'source_ip', 'user_agent', 'event_id'
            ]
            
        # Ensure output directory exists
        os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
        
        # Sort events by time before export
        self.sort_events()
        
        with open(output_file, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fields, extrasaction='ignore')
            writer.writeheader()
            
            for event in self.events:
                # Convert datetime objects to strings
                row = event.copy()
                if row.get('event_time') and isinstance(row['event_time'], datetime):
                    row['event_time'] = row['event_time'].isoformat()
                    
                # Convert complex objects to JSON strings
                for key, value in row.items():
                    if isinstance(value, (dict, list)):
                        row[key] = json.dumps(value)
                        
                writer.writerow(row)
                
        logger.info(f"Exported {len(self.events)} events to {output_file}")
        return output_file
        
    def export_json(self, output_file):
        """
        Export timeline to JSON format.
        
        Args:
            output_file (str): Path to output JSON file.
            
        Returns:
            str: Path to the created JSON file.
        """
        # Ensure output directory exists
        os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
        
        # Sort events by time before export
        self.sort_events()
        
        # Convert datetime objects to strings
        serializable_events = []
        for event in self.events:
            event_copy = event.copy()
            if event_copy.get('event_time') and isinstance(event_copy['event_time'], datetime):
                event_copy['event_time'] = event_copy['event_time'].isoformat()
            serializable_events.append(event_copy)
            
        with open(output_file, 'w') as jsonfile:
            json.dump(serializable_events, jsonfile, indent=2)
            
        logger.info(f"Exported {len(self.events)} events to {output_file}")
        return output_file

    def export_csv_header(self, filename):
        """Write only the CSV header to a file."""
        # Ensure output directory exists
        os.makedirs(os.path.dirname(os.path.abspath(filename)), exist_ok=True)
        
        with open(filename, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=self.csv_fields)
            writer.writeheader()

    def append_csv(self, filename):
        """Append events to an existing CSV file."""
        with open(filename, 'a', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=self.csv_fields, extrasaction='ignore')
            for event in self.events:
                # Convert datetime objects to strings
                row = event.copy()
                if row.get('event_time') and isinstance(row['event_time'], datetime):
                    row['event_time'] = row['event_time'].isoformat()
                    
                # Convert complex objects to JSON strings
                for key, value in row.items():
                    if isinstance(value, (dict, list)):
                        row[key] = json.dumps(value)
                        
                writer.writerow(row)

    def append_json(self, filename, first_batch=False):
        """Append events to a JSON file."""
        with open(filename, 'a') as f:
            for i, event in enumerate(self.events):
                # Convert datetime objects to strings
                event_copy = event.copy()
                if event_copy.get('event_time') and isinstance(event_copy['event_time'], datetime):
                    event_copy['event_time'] = event_copy['event_time'].isoformat()
                    
                # Add comma if not the first event in the file
                if not first_batch or i > 0:
                    f.write(',\n')
                f.write(json.dumps(event_copy, default=str, indent=2)) 