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

    @staticmethod
    def parse_resource_data(resource_data):
        """
        Parse AWS resource data into a standardized format.
        
        Args:
            resource_data (dict): Raw AWS resource data
            
        Returns:
            dict: Standardized resource data
        """
        # Extract common fields
        resource_id = resource_data.get('resource_id', 'unknown')
        resource_type = resource_data.get('resource_type', 'unknown')
        resource_name = resource_data.get('resource_name', resource_id)
        aws_region = resource_data.get('aws_region', 'unknown')
        
        # Extract resource-specific details
        details = resource_data.get('resource_details', {})
        
        # Create standardized resource object
        standardized_resource = {
            'id': resource_id,
            'type': resource_type,
            'name': resource_name,
            'region': aws_region,
            'creation_date': None,
            'tags': {},
            'details': {}
        }
        
        # Extract creation date if available
        if 'LaunchTime' in details:
            standardized_resource['creation_date'] = details['LaunchTime']
        elif 'CreationDate' in details:
            standardized_resource['creation_date'] = details['CreationDate']
        elif 'CreateTime' in details:
            standardized_resource['creation_date'] = details['CreateTime']
        
        # Extract tags if available
        if 'Tags' in details and isinstance(details['Tags'], list):
            for tag in details['Tags']:
                if 'Key' in tag and 'Value' in tag:
                    standardized_resource['tags'][tag['Key']] = tag['Value']
        
        # Add resource-specific details
        if resource_type == 'EC2':
            standardized_resource['details'] = {
                'instance_type': details.get('InstanceType'),
                'state': details.get('State', {}).get('Name'),
                'private_ip': details.get('PrivateIpAddress'),
                'public_ip': details.get('PublicIpAddress'),
                'vpc_id': details.get('VpcId'),
                'subnet_id': details.get('SubnetId'),
                'security_groups': [sg.get('GroupName') for sg in details.get('SecurityGroups', [])]
            }
        elif resource_type == 'S3':
            standardized_resource['details'] = {
                'creation_date': details.get('CreationDate')
            }
        elif resource_type == 'IAM User':
            standardized_resource['details'] = {
                'arn': details.get('Arn'),
                'create_date': details.get('CreateDate'),
                'path': details.get('Path'),
                'user_id': details.get('UserId')
            }
        elif resource_type == 'IAM Role':
            standardized_resource['details'] = {
                'arn': details.get('Arn'),
                'create_date': details.get('CreateDate'),
                'path': details.get('Path'),
                'role_id': details.get('RoleId')
            }
        elif resource_type == 'Lambda Function':
            standardized_resource['details'] = {
                'runtime': details.get('Runtime'),
                'handler': details.get('Handler'),
                'last_modified': details.get('LastModified'),
                'memory_size': details.get('MemorySize'),
                'timeout': details.get('Timeout'),
                'description': details.get('Description')
            }
        elif resource_type == 'RDS':
            standardized_resource['details'] = {
                'engine': details.get('Engine'),
                'engine_version': details.get('EngineVersion'),
                'status': details.get('DBInstanceStatus'),
                'storage': details.get('AllocatedStorage'),
                'instance_class': details.get('DBInstanceClass'),
                'endpoint': details.get('Endpoint', {}).get('Address')
            }
        
        return standardized_resource

    @staticmethod
    def parse_credential_report(report_data):
        """
        Parse AWS IAM credential report data.
        
        Args:
            report_data (list): List of dictionaries containing credential report data
            
        Returns:
            dict: Parsed credential report with user data
        """
        parsed_report = {
            'report_date': datetime.now(),
            'users': []
        }
        
        for user_data in report_data:
            parsed_user = {
                'username': user_data.get('user'),
                'arn': user_data.get('arn'),
                'user_creation_time': CloudTrailParser.parse_datetime(user_data.get('user_creation_time')),
                'password_status': {
                    'enabled': user_data.get('password_enabled', False),
                    'last_used': CloudTrailParser.parse_datetime(user_data.get('password_last_used')),
                    'last_changed': CloudTrailParser.parse_datetime(user_data.get('password_last_changed')),
                    'next_rotation': CloudTrailParser.parse_datetime(user_data.get('password_next_rotation'))
                },
                'mfa_active': user_data.get('mfa_active', False),
                'access_keys': {
                    'access_key_1': {
                        'active': user_data.get('access_key_1_active', False),
                        'last_rotated': CloudTrailParser.parse_datetime(user_data.get('access_key_1_last_rotated')),
                        'last_used_date': CloudTrailParser.parse_datetime(user_data.get('access_key_1_last_used_date')),
                        'last_used_region': user_data.get('access_key_1_last_used_region'),
                        'last_used_service': user_data.get('access_key_1_last_used_service')
                    },
                    'access_key_2': {
                        'active': user_data.get('access_key_2_active', False),
                        'last_rotated': CloudTrailParser.parse_datetime(user_data.get('access_key_2_last_rotated')),
                        'last_used_date': CloudTrailParser.parse_datetime(user_data.get('access_key_2_last_used_date')),
                        'last_used_region': user_data.get('access_key_2_last_used_region'),
                        'last_used_service': user_data.get('access_key_2_last_used_service')
                    }
                },
                'certificates': {
                    'cert_1': {
                        'active': user_data.get('cert_1_active', False),
                        'last_rotated': CloudTrailParser.parse_datetime(user_data.get('cert_1_last_rotated'))
                    },
                    'cert_2': {
                        'active': user_data.get('cert_2_active', False),
                        'last_rotated': CloudTrailParser.parse_datetime(user_data.get('cert_2_last_rotated'))
                    }
                }
            }
            
            parsed_report['users'].append(parsed_user)
        
        return parsed_report 