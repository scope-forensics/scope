"""
AWS log parsing module for processing CloudTrail logs.
"""

import json
import logging
import ipaddress
from datetime import datetime

logger = logging.getLogger(__name__)

class CloudTrailParser:
    """
    Parser for CloudTrail logs to extract and normalize event data.
    """
    
    @staticmethod
    def parse_datetime(datetime_str):
        """
        Parse AWS datetime string to datetime object.
        
        Args:
            datetime_str (str): AWS datetime string in format '%Y-%m-%dT%H:%M:%SZ'
            
        Returns:
            datetime or None: Parsed datetime object or None if parsing fails
        """
        if not datetime_str or datetime_str in ['N/A', 'not_supported']:
            return None
            
        try:
            return datetime.strptime(datetime_str, '%Y-%m-%dT%H:%M:%SZ')
        except ValueError:
            logger.debug(f"Could not parse datetime: {datetime_str}")
            return None
            
    @staticmethod
    def normalize_event(raw_event):
        """
        Normalize a CloudTrail event into a consistent format.
        
        Args:
            raw_event (dict): Raw CloudTrail event
            
        Returns:
            dict: Normalized event data
        """
        # Handle Records array if present
        if 'Records' in raw_event:
            raw_event = raw_event['Records'][0]  # Take the first record
        
        # If this is from LookupEvents API, the actual event is in CloudTrailEvent
        if 'CloudTrailEvent' in raw_event:
            try:
                raw_event = json.loads(raw_event['CloudTrailEvent'])
            except (json.JSONDecodeError, TypeError):
                pass

        # Extract event time
        event_time = raw_event.get('eventTime')
        if event_time:
            event_time = CloudTrailParser.parse_datetime(event_time)

        # Extract user identity
        user_identity = raw_event.get('userIdentity', {})
        username = (
            user_identity.get('userName') or
            user_identity.get('sessionContext', {}).get('sessionIssuer', {}).get('userName') or
            user_identity.get('invokedBy') or
            user_identity.get('type') or
            'Unknown'
        )

        # Get resources directly from CloudTrail event
        resources = raw_event.get('resources', [])
        
        # If no resources field, try to extract from request/response
        if not resources:
            request_params = raw_event.get('requestParameters', {})
            response_elements = raw_event.get('responseElements', {})
            
            # Store as raw data to preserve all information
            if request_params or response_elements:
                resources = [{
                    'requestParameters': request_params,
                    'responseElements': response_elements
                }]
        
        # Validate and process the source IP address
        source_ip = raw_event.get('sourceIPAddress')
        if source_ip:
            try:
                # This will raise a ValueError if the IP is not valid
                ipaddress.ip_address(source_ip)
            except ValueError:
                logger.debug(f"Invalid source IP: {source_ip}")
                source_ip = None
        
        # Build normalized event data
        normalized_data = {
            'event_id': raw_event.get('eventID'),
            'event_time': event_time,
            'event_source': raw_event.get('eventSource'),
            'event_name': raw_event.get('eventName'),
            'event_type': raw_event.get('eventType'),
            'username': username,
            'aws_region': raw_event.get('awsRegion'),
            'source_ip': source_ip,
            'user_agent': raw_event.get('userAgent'),
            'resources': resources,
            'raw_data': raw_event
        }

        return normalized_data
        
    @staticmethod
    def batch_normalize_events(events):
        """
        Normalize a batch of CloudTrail events.
        
        Args:
            events (list): List of raw CloudTrail events
            
        Returns:
            list: List of normalized events
        """
        normalized_events = []
        
        for event in events:
            try:
                normalized_event = CloudTrailParser.normalize_event(event)
                normalized_events.append(normalized_event)
            except Exception as e:
                logger.error(f"Error normalizing event: {e}")
                continue
                
        return normalized_events 