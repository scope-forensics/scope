"""
AWS log collection module for retrieving CloudTrail logs.
"""

import boto3
import json
import gzip
import logging
import os
from datetime import datetime, timedelta
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

class AWSLogCollector:
    """
    Collects CloudTrail logs from AWS, either from S3 buckets or via the LookupEvents API.
    """
    
    def __init__(self, aws_access_key=None, aws_secret_key=None, aws_session_token=None, region='us-east-1'):
        """
        Initialize the AWS log collector.
        
        Args:
            aws_access_key (str, optional): AWS access key. If not provided, will use environment variables or AWS config.
            aws_secret_key (str, optional): AWS secret key. If not provided, will use environment variables or AWS config.
            aws_session_token (str, optional): AWS session token for temporary credentials.
            region (str, optional): AWS region to use. Defaults to 'us-east-1'.
        """
        self.session = boto3.Session(
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            aws_session_token=aws_session_token,
            region_name=region
        )
        self.region = region
        
    def validate_credentials(self):
        """
        Validate AWS credentials by calling the STS GetCallerIdentity API.
        
        Returns:
            tuple: (bool, str) - (Success status, Error message if any)
        """
        try:
            sts = self.session.client('sts')
            identity = sts.get_caller_identity()
            logger.info(f"Credentials validated for account: {identity['Account']}")
            return True, identity['Account']
        except Exception as e:
            logger.error(f"Credential validation failed: {str(e)}")
            return False, str(e)
    
    def discover_bucket_structure(self, bucket_name, max_prefixes=10):
        """
        Discover the directory structure of an S3 bucket to help identify CloudTrail logs.
        
        Args:
            bucket_name (str): Name of the S3 bucket to explore
            max_prefixes (int, optional): Maximum number of prefixes to display at each level
            
        Returns:
            dict: Dictionary representing the bucket structure
        """
        s3 = self.session.client('s3')
        
        try:
            # First, check if the bucket exists
            s3.head_bucket(Bucket=bucket_name)
            logger.info(f"Exploring structure of bucket: {bucket_name}")
            
            # Get top-level prefixes (folders)
            paginator = s3.get_paginator('list_objects_v2')
            top_prefixes = []
            
            # Use delimiter to get folder-like structure
            for page in paginator.paginate(Bucket=bucket_name, Delimiter='/'):
                for prefix in page.get('CommonPrefixes', []):
                    top_prefixes.append(prefix.get('Prefix'))
                    if len(top_prefixes) >= max_prefixes:
                        break
                if len(top_prefixes) >= max_prefixes:
                    break
            
            # Look for CloudTrail-specific patterns
            cloudtrail_paths = []
            
            # Check for AWSLogs pattern which is common for CloudTrail
            for prefix in top_prefixes:
                if 'AWSLogs' in prefix:
                    # Explore one level deeper to find account IDs
                    for page in paginator.paginate(Bucket=bucket_name, Prefix=prefix, Delimiter='/'):
                        for account_prefix in page.get('CommonPrefixes', []):
                            account_path = account_prefix.get('Prefix')
                            
                            # Check for CloudTrail under this account
                            for ct_page in paginator.paginate(Bucket=bucket_name, Prefix=account_path, Delimiter='/'):
                                for service_prefix in ct_page.get('CommonPrefixes', []):
                                    service_path = service_prefix.get('Prefix')
                                    if 'CloudTrail' in service_path:
                                        cloudtrail_paths.append(service_path)
                                        
                                        # Check for regions
                                        for region_page in paginator.paginate(Bucket=bucket_name, Prefix=service_path, Delimiter='/'):
                                            for region_prefix in region_page.get('CommonPrefixes', []):
                                                region_path = region_prefix.get('Prefix')
                                                cloudtrail_paths.append(region_path)
                                                
                                                # Check for a sample year
                                                for year_page in paginator.paginate(Bucket=bucket_name, Prefix=region_path, Delimiter='/'):
                                                    for year_prefix in year_page.get('CommonPrefixes', []):
                                                        year_path = year_prefix.get('Prefix')
                                                        cloudtrail_paths.append(year_path)
                                                        break  # Just get one year as example
                                                break  # Just get one region as example
                                        break  # Just get one CloudTrail path
            
            # If we didn't find CloudTrail in AWSLogs, look for other common patterns
            if not cloudtrail_paths:
                for prefix in top_prefixes:
                    if 'cloudtrail' in prefix.lower():
                        cloudtrail_paths.append(prefix)
            
            result = {
                'bucket': bucket_name,
                'top_level_prefixes': top_prefixes,
                'cloudtrail_paths': cloudtrail_paths
            }
            
            logger.info(f"Found {len(cloudtrail_paths)} potential CloudTrail paths in bucket {bucket_name}")
            return result
            
        except Exception as e:
            logger.error(f"Error exploring bucket {bucket_name}: {str(e)}")
            return {
                'bucket': bucket_name,
                'error': str(e)
            }
            
    def collect_from_s3(self, bucket_name, prefix="", start_date=None, end_date=None, output_dir=None, regions=None, batch_size=1000):
        """
        Collect CloudTrail logs from an S3 bucket.
        
        Args:
            bucket_name (str): Name of the S3 bucket containing CloudTrail logs.
            prefix (str, optional): Prefix within the bucket to search for logs.
            start_date (str, optional): Start date in YYYY-MM-DD format. Defaults to 7 days ago.
            end_date (str, optional): End date in YYYY-MM-DD format. Defaults to today.
            output_dir (str, optional): Directory to save raw log files. If None, logs are not saved locally.
            regions (list, optional): List of AWS regions to collect logs from. If None, collects from all regions.
            batch_size (int, optional): Number of events to process in memory before yielding a batch.
            
        Returns:
            generator: Yields batches of parsed CloudTrail events.
        """
        s3 = self.session.client('s3')
        
        # If no prefix is provided, try to discover the bucket structure
        if not prefix:
            logger.info(f"No prefix provided, attempting to discover CloudTrail logs in bucket {bucket_name}")
            structure = self.discover_bucket_structure(bucket_name)
            
            # If we found CloudTrail paths, use the first one
            if structure.get('cloudtrail_paths'):
                # Find the base CloudTrail path (without region)
                for path in structure['cloudtrail_paths']:
                    if 'CloudTrail' in path and not any(region in path for region in ['us-east-1', 'us-west-2', 'eu-west-1']):
                        prefix = path
                        logger.info(f"Automatically selected base prefix: {prefix}")
                        break
                
                # If we couldn't find a base path, use the first one
                if not prefix:
                    prefix = structure['cloudtrail_paths'][0]
                    logger.info(f"Automatically selected prefix: {prefix}")
            else:
                logger.warning(f"Could not automatically detect CloudTrail logs in bucket {bucket_name}. Please specify a prefix.")
        
        # Set default dates if not provided
        if not start_date:
            start_date = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d')
        if not end_date:
            end_date = datetime.now().strftime('%Y-%m-%d')
            
        start_date_obj = datetime.strptime(start_date, "%Y-%m-%d").date()
        end_date_obj = datetime.strptime(end_date, "%Y-%m-%d").date()
        
        if prefix and not prefix.endswith("/"):
            prefix += "/"
            
        # Create output directory if specified
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        logger.info(f"Collecting CloudTrail logs from bucket '{bucket_name}' between {start_date} and {end_date}")
        
        # Determine regions to collect from
        if not regions:
            # Try to discover available regions
            try:
                available_regions = []
                region_prefix = prefix
                
                # List all directories under the prefix to find regions
                paginator = s3.get_paginator('list_objects_v2')
                for page in paginator.paginate(Bucket=bucket_name, Prefix=region_prefix, Delimiter='/'):
                    for region_dir in page.get('CommonPrefixes', []):
                        region_path = region_dir.get('Prefix')
                        # Extract region name from path
                        region_name = region_path.rstrip('/').split('/')[-1]
                        if region_name.startswith(('us-', 'eu-', 'ap-', 'sa-', 'ca-')):
                            available_regions.append(region_name)
                
                if available_regions:
                    logger.info(f"Discovered {len(available_regions)} regions with CloudTrail logs")
                    regions = available_regions
                else:
                    # Default to current region if no regions found
                    regions = [self.region]
                    logger.info(f"No regions discovered, defaulting to {self.region}")
            except Exception as e:
                logger.error(f"Error discovering regions: {e}")
                regions = [self.region]
        
        total_events = 0
        current_batch = []
        
        # Process each region
        for region in regions:
            logger.info(f"Collecting logs for region: {region}")
            region_prefix = f"{prefix}{region}/"
            
            current_date = start_date_obj
            while current_date <= end_date_obj:
                date_folder = f"{current_date.year}/{current_date.strftime('%m')}/{current_date.strftime('%d')}/"
                final_prefix = region_prefix + date_folder
                
                logger.info(f"Checking prefix '{final_prefix}' in bucket '{bucket_name}'")
                
                try:
                    paginator = s3.get_paginator("list_objects_v2")
                    for page in paginator.paginate(Bucket=bucket_name, Prefix=final_prefix):
                        for obj in page.get("Contents", []):
                            key = obj["Key"]
                            
                            # Only process .gz files which contain CloudTrail logs
                            if not key.endswith(".gz"):
                                continue
                                
                            try:
                                logger.debug(f"Processing file: {key}")
                                resp = s3.get_object(Bucket=bucket_name, Key=key)
                                raw_body = resp["Body"].read()
                                
                                # Decompress gzipped content
                                file_data = gzip.decompress(raw_body).decode("utf-8")
                                    
                                # Save raw file if output directory is specified
                                if output_dir:
                                    # Create region subdirectory
                                    region_dir = os.path.join(output_dir, region)
                                    if not os.path.exists(region_dir):
                                        os.makedirs(region_dir)
                                    
                                    # Create date subdirectory
                                    date_dir = os.path.join(region_dir, current_date.strftime('%Y-%m-%d'))
                                    if not os.path.exists(date_dir):
                                        os.makedirs(date_dir)
                                    
                                    # Save the decompressed JSON file
                                    filename = os.path.basename(key)[:-3] + '.json'  # Remove .gz extension
                                    with open(os.path.join(date_dir, filename), 'w') as f:
                                        f.write(file_data)
                                
                                # Parse the JSON data
                                try:
                                    json_data = json.loads(file_data)
                                    records = json_data.get("Records", [])
                                    
                                    # Add region information to each record
                                    for record in records:
                                        if 'awsRegion' not in record:
                                            record['awsRegion'] = region
                                    
                                    # Add records to current batch
                                    current_batch.extend(records)
                                    total_events += len(records)
                                    
                                    # If batch size reached, yield the batch
                                    if len(current_batch) >= batch_size:
                                        logger.debug(f"Yielding batch of {len(current_batch)} events")
                                        yield current_batch
                                        current_batch = []
                                    
                                    logger.debug(f"Added {len(records)} events from {key}")
                                except json.JSONDecodeError as e:
                                    logger.error(f"Error parsing JSON from {key}: {e}")
                                
                            except Exception as e:
                                logger.error(f"Error processing file {key}: {e}")
                                continue
                                
                except Exception as e:
                    logger.error(f"Error processing date {current_date} in region {region}: {e}")
                    
                current_date += timedelta(days=1)
        
        # Yield any remaining events in the final batch
        if current_batch:
            logger.debug(f"Yielding final batch of {len(current_batch)} events")
            yield current_batch
        
        logger.info(f"Collected {total_events} CloudTrail events from {len(regions)} regions")
        
    def collect_management_events(self, start_time=None, end_time=None, lookup_attributes=None):
        """
        Collect CloudTrail management events using the LookupEvents API.
        
        Args:
            start_time (datetime, optional): Start time for events. Defaults to 7 days ago.
            end_time (datetime, optional): End time for events. Defaults to now.
            lookup_attributes (list, optional): List of attribute dictionaries to filter events.
                Example: [{'AttributeKey': 'EventName', 'AttributeValue': 'ConsoleLogin'}]
                
        Returns:
            list: List of CloudTrail events.
        """
        cloudtrail = self.session.client('cloudtrail')
        
        # Set default times if not provided
        if not start_time:
            start_time = datetime.now() - timedelta(days=7)
        if not end_time:
            end_time = datetime.now()
            
        logger.info(f"Collecting CloudTrail management events from {start_time} to {end_time}")
        
        # Prepare parameters for lookup_events
        params = {
            'StartTime': start_time,
            'EndTime': end_time
        }
        
        if lookup_attributes:
            params['LookupAttributes'] = lookup_attributes
            
        paginator = cloudtrail.get_paginator('lookup_events')
        all_events = []
        
        try:
            for page in paginator.paginate(**params):
                events = page.get('Events', [])
                all_events.extend(events)
                logger.debug(f"Retrieved {len(events)} events")
                
        except ClientError as e:
            logger.error(f"Error retrieving management events: {e}")
            
        logger.info(f"Collected {len(all_events)} management events")
        return all_events
        
    def discover_trails(self):
        """
        Discover CloudTrail trails in the account.
        
        Returns:
            list: List of CloudTrail trail configurations.
        """
        cloudtrail = self.session.client('cloudtrail')
        
        try:
            response = cloudtrail.describe_trails()
            trails = response.get('trailList', [])
            logger.info(f"Discovered {len(trails)} CloudTrail trails")
            return trails
        except ClientError as e:
            logger.error(f"Error discovering CloudTrail trails: {e}")
            return []

    def process_local_logs(self, directory, recursive=False, batch_size=1000):
        """
        Process CloudTrail logs from a local directory.
        
        Args:
            directory (str): Path to directory containing CloudTrail logs.
            recursive (bool, optional): Whether to search subdirectories recursively. Defaults to False.
            batch_size (int, optional): Number of events to process in memory before yielding a batch.
            
        Returns:
            generator: Yields batches of parsed CloudTrail events.
        """
        # Normalize the path to handle Windows backslashes correctly
        directory = os.path.normpath(directory)
        
        logger.info(f"Processing CloudTrail logs from directory: {directory}")
        
        if not os.path.exists(directory):
            logger.error(f"Directory does not exist: {directory}")
            return
        
        if not os.path.isdir(directory):
            logger.error(f"Path is not a directory: {directory}")
            return
        
        total_events = 0
        current_batch = []
        processed_files = 0
        
        # Function to process a single file
        def process_file(file_path):
            nonlocal total_events, current_batch, processed_files
            
            try:
                logger.debug(f"Processing file: {file_path}")
                
                # Check if file is gzipped
                if file_path.endswith('.gz'):
                    with gzip.open(file_path, 'rb') as f:
                        file_data = f.read().decode('utf-8')
                else:
                    with open(file_path, 'r') as f:
                        file_data = f.read()
                
                # Parse the JSON data
                try:
                    json_data = json.loads(file_data)
                    
                    # Handle different CloudTrail log formats
                    if 'Records' in json_data:
                        # Standard CloudTrail log format
                        records = json_data.get('Records', [])
                    elif 'eventVersion' in json_data:
                        # Single event format
                        records = [json_data]
                    else:
                        # Unknown format
                        logger.warning(f"Unknown log format in file: {file_path}")
                        return
                    
                    # Try to extract region from filename if not in records
                    region = None
                    filename = os.path.basename(file_path)
                    for part in filename.split('_'):
                        if part.startswith(('us-', 'eu-', 'ap-', 'sa-', 'ca-')):
                            region = part
                            break
                    
                    # Add region information to each record if missing
                    for record in records:
                        if 'awsRegion' not in record and region:
                            record['awsRegion'] = region
                    
                    # Add records to current batch
                    current_batch.extend(records)
                    total_events += len(records)
                    processed_files += 1
                    
                    # If batch size reached, yield the batch
                    if len(current_batch) >= batch_size:
                        logger.debug(f"Yielding batch of {len(current_batch)} events")
                        yield current_batch
                        current_batch = []
                    
                    logger.debug(f"Added {len(records)} events from {file_path}")
                except json.JSONDecodeError as e:
                    logger.error(f"Error parsing JSON from {file_path}: {e}")
                
            except Exception as e:
                logger.error(f"Error processing file {file_path}: {e}")
        
        # Walk through directory structure
        if recursive:
            for root, _, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    # Only process .json or .gz files
                    if file_path.endswith(('.json', '.gz')):
                        yield from process_file(file_path)
        else:
            # Only process files in the top-level directory
            for file in os.listdir(directory):
                file_path = os.path.join(directory, file)
                if os.path.isfile(file_path) and file_path.endswith(('.json', '.gz')):
                    yield from process_file(file_path)
        
        # Yield any remaining events in the final batch
        if current_batch:
            logger.debug(f"Yielding final batch of {len(current_batch)} events")
            yield current_batch
        
        logger.info(f"Processed {processed_files} files containing {total_events} CloudTrail events")

    def discover_resources(self, resource_types=None, regions=None, output_format='json', output_file=None):
        """
        Discover AWS resources across specified regions.
        
        Args:
            resource_types (list, optional): List of resource types to discover. 
                Supported types: 'ec2', 's3', 'iam_users', 'iam_roles', 'lambda', 'rds'.
                If None, discovers all supported resource types.
            regions (list, optional): List of AWS regions to search. If None, searches all available regions.
            output_format (str, optional): Output format - 'json', 'csv', or 'terminal'. Defaults to 'json'.
            output_file (str, optional): Path to output file. If None, prints to terminal.
            
        Returns:
            dict: Dictionary of discovered resources by type
        """
        # Default resource types if none specified
        if not resource_types:
            resource_types = ['ec2', 's3', 'iam_users', 'iam_roles', 'lambda', 'rds']
        
        logger.info(f"Discovering AWS resources: {', '.join(resource_types)}")
        
        # Initialize results dictionary
        resources = {resource_type: [] for resource_type in resource_types}
        
        # Helper function to serialize datetime objects for JSON output
        def serialize_resource_details(resource):
            if isinstance(resource, dict):
                return {key: serialize_resource_details(value) for key, value in resource.items()}
            elif isinstance(resource, list):
                return [serialize_resource_details(item) for item in resource]
            elif isinstance(resource, datetime):
                return resource.isoformat()
            else:
                return resource
        
        # Helper function to discover resources by region
        def discover_by_region(service_name, fetch_function):
            try:
                # If regions not specified, get all available regions for the service
                if not regions:
                    available_regions = self.session.get_available_regions(service_name)
                else:
                    available_regions = regions
                    
                for region in available_regions:
                    try:
                        client = self.session.client(service_name, region_name=region)
                        logger.info(f"Discovering {service_name} resources in region {region}...")
                        for resource in fetch_function(client, region):
                            yield resource
                    except Exception as e:
                        logger.error(f"Error discovering {service_name} resources in {region}: {str(e)}")
                        continue
            except Exception as e:
                logger.error(f"Failed to fetch regions for {service_name}: {str(e)}")
        
        # EC2 instances
        if 'ec2' in resource_types:
            def fetch_ec2_instances(client, region):
                try:
                    paginator = client.get_paginator('describe_instances')
                    for page in paginator.paginate():
                        for reservation in page.get('Reservations', []):
                            for instance in reservation.get('Instances', []):
                                resource_region = instance.get('Placement', {}).get('AvailabilityZone', region)[:-1]
                                
                                # Get instance name from tags
                                instance_name = None
                                for tag in instance.get('Tags', []):
                                    if tag.get('Key') == 'Name':
                                        instance_name = tag.get('Value')
                                        break
                                
                                yield {
                                    'resource_id': instance.get('InstanceId'),
                                    'resource_type': 'EC2',
                                    'resource_name': instance_name or instance.get('InstanceId'),
                                    'resource_details': serialize_resource_details(instance),
                                    'aws_region': resource_region,
                                }
                except Exception as e:
                    logger.error(f"Error fetching EC2 instances in {region}: {str(e)}")
            
            for resource in discover_by_region('ec2', fetch_ec2_instances):
                resources['ec2'].append(resource)
        
        # S3 buckets (global service)
        if 's3' in resource_types:
            try:
                s3 = self.session.client('s3')
                buckets = s3.list_buckets()
                
                for bucket in buckets.get('Buckets', []):
                    bucket_name = bucket.get('Name')
                    try:
                        # Get bucket location
                        location = s3.get_bucket_location(Bucket=bucket_name)
                        bucket_region = location.get('LocationConstraint') or 'us-east-1'
                        
                        resource = {
                            'resource_id': bucket_name,
                            'resource_type': 'S3',
                            'resource_name': bucket_name,
                            'resource_details': serialize_resource_details(bucket),
                            'aws_region': bucket_region,
                        }
                        resources['s3'].append(resource)
                    except Exception as e:
                        logger.error(f"Error getting location for bucket {bucket_name}: {str(e)}")
            except Exception as e:
                logger.error(f"Error listing S3 buckets: {str(e)}")
        
        # IAM users (global service)
        if 'iam_users' in resource_types:
            try:
                iam = self.session.client('iam')
                paginator = iam.get_paginator('list_users')
                
                for page in paginator.paginate():
                    for user in page.get('Users', []):
                        resource = {
                            'resource_id': user.get('UserId'),
                            'resource_type': 'IAM User',
                            'resource_name': user.get('UserName'),
                            'resource_details': serialize_resource_details(user),
                            'aws_region': 'global',
                        }
                        resources['iam_users'].append(resource)
            except Exception as e:
                logger.error(f"Error listing IAM users: {str(e)}")
        
        # IAM roles (global service)
        if 'iam_roles' in resource_types:
            try:
                iam = self.session.client('iam')
                paginator = iam.get_paginator('list_roles')
                
                for page in paginator.paginate():
                    for role in page.get('Roles', []):
                        resource = {
                            'resource_id': role.get('RoleId'),
                            'resource_type': 'IAM Role',
                            'resource_name': role.get('RoleName'),
                            'resource_details': serialize_resource_details(role),
                            'aws_region': 'global',
                        }
                        resources['iam_roles'].append(resource)
            except Exception as e:
                logger.error(f"Error listing IAM roles: {str(e)}")
        
        # Lambda functions
        if 'lambda' in resource_types:
            def fetch_lambda_functions(client, region):
                try:
                    paginator = client.get_paginator('list_functions')
                    for page in paginator.paginate():
                        for function in page.get('Functions', []):
                            yield {
                                'resource_id': function.get('FunctionArn'),
                                'resource_type': 'Lambda Function',
                                'resource_name': function.get('FunctionName'),
                                'resource_details': serialize_resource_details(function),
                                'aws_region': region,
                            }
                except Exception as e:
                    logger.error(f"Error fetching Lambda functions in {region}: {str(e)}")
            
            for resource in discover_by_region('lambda', fetch_lambda_functions):
                resources['lambda'].append(resource)
        
        # RDS instances
        if 'rds' in resource_types:
            def fetch_rds_instances(client, region):
                try:
                    paginator = client.get_paginator('describe_db_instances')
                    for page in paginator.paginate():
                        for instance in page.get('DBInstances', []):
                            yield {
                                'resource_id': instance.get('DBInstanceIdentifier'),
                                'resource_type': 'RDS',
                                'resource_name': instance.get('DBInstanceIdentifier'),
                                'resource_details': serialize_resource_details(instance),
                                'aws_region': region,
                            }
                except Exception as e:
                    logger.error(f"Error fetching RDS instances in {region}: {str(e)}")
            
            for resource in discover_by_region('rds', fetch_rds_instances):
                resources['rds'].append(resource)
        
        # Output the results
        total_resources = sum(len(resources[resource_type]) for resource_type in resources)
        logger.info(f"Discovered {total_resources} resources across {len(resource_types)} resource types")
        
        # Format and output the results
        if output_format == 'json':
            output_data = json.dumps(resources, indent=2)
        elif output_format == 'csv':
            import csv
            import io
            
            output = io.StringIO()
            fieldnames = ['resource_type', 'resource_id', 'resource_name', 'aws_region']
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            
            for resource_type, resource_list in resources.items():
                for resource in resource_list:
                    writer.writerow({
                        'resource_type': resource['resource_type'],
                        'resource_id': resource['resource_id'],
                        'resource_name': resource['resource_name'],
                        'aws_region': resource['aws_region'] or 'global'
                    })
            
            output_data = output.getvalue()
        else:  # terminal output
            output_lines = []
            output_lines.append("AWS Resource Discovery Results:")
            output_lines.append("=" * 80)
            
            for resource_type, resource_list in resources.items():
                if resource_list:
                    output_lines.append(f"\n{resource_type.upper()} Resources ({len(resource_list)}):")
                    output_lines.append("-" * 80)
                    
                    for resource in resource_list:
                        region_str = f" ({resource['aws_region']})" if resource['aws_region'] else " (global)"
                        output_lines.append(f"{resource['resource_name']} - {resource['resource_id']}{region_str}")
            
            output_data = "\n".join(output_lines)
        
        # Output to file or terminal
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output_data)
            logger.info(f"Resource discovery results written to {output_file}")
        else:
            print(output_data)
        
        return resources

    def get_credential_report(self, output_format='json', output_file=None):
        """
        Generate and retrieve the IAM credential report.
        
        Args:
            output_format (str, optional): Output format - 'json', 'csv', or 'terminal'. Defaults to 'json'.
            output_file (str, optional): Path to output file. If None, prints to terminal.
            
        Returns:
            dict or str: Credential report data in the specified format
        """
        logger.info("Generating IAM credential report")
        
        try:
            iam = self.session.client('iam')
            
            # Generate credential report
            response = iam.generate_credential_report()
            logger.info(f"Credential report generation status: {response.get('State')}")
            
            # Wait for report to be generated with timeout
            max_attempts = 10
            attempt = 0
            
            while attempt < max_attempts:
                try:
                    response = iam.get_credential_report()
                    if response.get('Content'):
                        break
                except Exception as e:
                    if 'ReportNotPresent' in str(e) or 'ReportInProgress' in str(e):
                        logger.info(f"Report not ready yet, attempt {attempt + 1}/{max_attempts}")
                        attempt += 1
                        import time
                        time.sleep(2)
                        continue
                    else:
                        raise
                
            if attempt >= max_attempts:
                logger.error("Timed out waiting for credential report")
                return None
            
            # Get and process the credential report
            report_csv = response['Content'].decode('utf-8')
            
            # Parse CSV content
            import csv
            from io import StringIO
            
            csv_reader = csv.DictReader(StringIO(report_csv))
            report_data = list(csv_reader)
            
            # Convert boolean strings to actual booleans and dates to datetime objects
            for user_data in report_data:
                for key, value in user_data.items():
                    if value.lower() in ('true', 'false'):
                        user_data[key] = value.lower() == 'true'
                    elif 'date' in key.lower() or 'time' in key.lower() or 'last_used' in key.lower() or 'last_rotated' in key.lower():
                        if value and value not in ('N/A', 'not_supported', 'no_information'):
                            try:
                                user_data[key] = datetime.strptime(value, '%Y-%m-%dT%H:%M:%S+00:00')
                            except ValueError:
                                try:
                                    user_data[key] = datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ')
                                except ValueError:
                                    pass  # Keep as string if parsing fails
            
            logger.info(f"Successfully retrieved credential report for {len(report_data)} users")
            
            # Format and output the results
            if output_format == 'json':
                # Convert datetime objects to strings for JSON serialization
                for user_data in report_data:
                    for key, value in user_data.items():
                        if isinstance(value, datetime):
                            user_data[key] = value.isoformat()
                
                output_data = json.dumps(report_data, indent=2)
            elif output_format == 'csv':
                # Return the original CSV
                output_data = report_csv
            else:  # terminal output
                output_lines = []
                output_lines.append("AWS IAM Credential Report:")
                output_lines.append("=" * 80)
                
                for user_data in report_data:
                    output_lines.append(f"\nUser: {user_data.get('user')}")
                    output_lines.append("-" * 80)
                    
                    for key, value in user_data.items():
                        if key != 'user':  # Skip user since we already displayed it
                            if isinstance(value, datetime):
                                value = value.isoformat()
                            output_lines.append(f"{key}: {value}")
                
                output_data = "\n".join(output_lines)
            
            # Output to file or terminal
            if output_file:
                with open(output_file, 'w') as f:
                    f.write(output_data)
                logger.info(f"Credential report written to {output_file}")
            else:
                print(output_data)
            
            return report_data
            
        except Exception as e:
            logger.error(f"Error generating credential report: {str(e)}")
            return None 