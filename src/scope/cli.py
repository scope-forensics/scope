#!/usr/bin/env python3
"""
Command-line interface for the Scope package.
"""

import argparse
import logging
import sys
import os
import configparser
from datetime import datetime, timedelta

from scope.aws.collector import AWSLogCollector
from scope.aws.parser import CloudTrailParser
from scope.aws.timeline import AWSTimeline
from scope.common.utils import setup_logging

logger = logging.getLogger(__name__)

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Scope - Cloud Forensics Tool')
    
    # Global options
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--log-file', help='Path to log file')
    
    # Create subparsers for different cloud providers
    subparsers = parser.add_subparsers(dest='provider', help='Cloud provider')
    
    # AWS subparser
    aws_parser = subparsers.add_parser('aws', help='AWS operations')
    aws_parser.add_argument('--access-key', help='AWS access key')
    aws_parser.add_argument('--secret-key', help='AWS secret key')
    aws_parser.add_argument('--region', default='us-east-1', help='AWS region')
    
    # AWS operations
    aws_subparsers = aws_parser.add_subparsers(dest='operation', help='AWS operation')
    
    # Configure AWS credentials
    configure_parser = aws_subparsers.add_parser('configure', help='Configure AWS credentials')
    configure_parser.add_argument('--profile', default='default', help='AWS profile name')
    
    # Process local logs
    local_parser = aws_subparsers.add_parser('local', help='Process CloudTrail logs from local directory')
    local_parser.add_argument('--directory', required=True, help='Directory containing CloudTrail logs')
    local_parser.add_argument('--output-file', required=True, help='Output file for timeline')
    local_parser.add_argument('--format', choices=['csv', 'json'], default='csv', help='Output format')
    local_parser.add_argument('--recursive', action='store_true', help='Recursively search subdirectories')
    
    # Collect from S3
    s3_parser = aws_subparsers.add_parser('s3', help='Collect CloudTrail logs from S3')
    s3_parser.add_argument('--bucket', required=True, help='S3 bucket name')
    s3_parser.add_argument('--prefix', default='', help='S3 prefix')
    s3_parser.add_argument('--start-date', help='Start date (YYYY-MM-DD)')
    s3_parser.add_argument('--end-date', help='End date (YYYY-MM-DD)')
    s3_parser.add_argument('--output-dir', help='Directory to save raw logs')
    s3_parser.add_argument('--output-file', required=True, help='Output file for timeline')
    s3_parser.add_argument('--format', choices=['csv', 'json'], default='csv', help='Output format')
    s3_parser.add_argument('--regions', nargs='+', help='Specific regions to collect from (space-separated)')
    
    # Collect management events
    mgmt_parser = aws_subparsers.add_parser('management', help='Collect CloudTrail management events')
    mgmt_parser.add_argument('--days', type=int, default=7, help='Number of days to look back')
    mgmt_parser.add_argument('--output-file', required=True, help='Output file for timeline')
    mgmt_parser.add_argument('--format', choices=['csv', 'json'], default='csv', help='Output format')
    
    # Discover trails
    discover_parser = aws_subparsers.add_parser('discover', help='Discover CloudTrail trails')
    
    # Explore S3 bucket structure
    explore_parser = aws_subparsers.add_parser('explore-bucket', help='Explore S3 bucket structure')
    explore_parser.add_argument('--bucket', required=True, help='S3 bucket name')
    
    # Resource discovery
    resource_parser = aws_subparsers.add_parser('discover-resources', help='Discover AWS resources')
    resource_parser.add_argument('--resource-types', nargs='+', 
                                choices=['ec2', 's3', 'iam_users', 'iam_roles', 'lambda', 'rds', 'all'],
                                default=['all'], help='Resource types to discover')
    resource_parser.add_argument('--regions', nargs='+', help='Specific regions to search (space-separated)')
    resource_parser.add_argument('--output-file', help='Output file path')
    resource_parser.add_argument('--format', choices=['json', 'csv', 'terminal'], default='terminal', 
                                help='Output format')

    # Credential report
    cred_report_parser = aws_subparsers.add_parser('credential-report', help='Generate and retrieve IAM credential report')
    cred_report_parser.add_argument('--output-file', help='Output file path')
    cred_report_parser.add_argument('--format', choices=['json', 'csv', 'terminal'], default='terminal',
                                   help='Output format')
    
    return parser.parse_args()

def main():
    """Main entry point for the CLI."""
    args = parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    setup_logging(log_level=log_level, log_file=args.log_file)
    
    if not args.provider:
        logger.error("No cloud provider specified")
        sys.exit(1)
        
    if args.provider == 'aws':
        handle_aws_commands(args)
    else:
        logger.error(f"Unsupported provider: {args.provider}")
        sys.exit(1)

def handle_aws_commands(args):
    """Handle AWS-specific commands."""
    if not args.operation:
        logger.error("No AWS operation specified")
        sys.exit(1)
        
    if args.operation == 'configure':
        configure_aws_credentials(args)
        return
        
    # Initialize AWS collector
    collector = AWSLogCollector(
        aws_access_key=args.access_key,
        aws_secret_key=args.secret_key,
        region=args.region
    )
    
    # For local operation, we don't need to validate AWS credentials
    if args.operation != 'local':
        # Validate credentials
        valid, account_id = collector.validate_credentials()
        if not valid:
            logger.error(f"Invalid AWS credentials: {account_id}")
            sys.exit(1)
        
        logger.info(f"Using AWS account: {account_id}")
    
    if args.operation == 'local':
        # Process local CloudTrail logs
        # Create timeline object for streaming
        timeline = AWSTimeline([])
        
        # Open output file
        output_format = args.format
        output_file = args.output_file
        
        # Initialize the file with headers if CSV
        if output_format == 'csv':
            timeline.export_csv_header(output_file)
        elif output_format == 'json':
            # Initialize JSON file with opening bracket
            with open(output_file, 'w') as f:
                f.write('[\n')
        
        # Process events in batches
        first_batch = True
        for batch in collector.process_local_logs(
            directory=args.directory,
            recursive=args.recursive
        ):
            # Parse events in this batch
            normalized_batch = CloudTrailParser.batch_normalize_events(batch)
            
            # Update timeline with this batch
            timeline.events = normalized_batch
            
            # Append to output file
            if output_format == 'csv':
                timeline.append_csv(output_file)
            else:  # JSON
                timeline.append_json(output_file, first_batch)
                first_batch = False
        
        # Finalize JSON file if needed
        if output_format == 'json':
            with open(output_file, 'a') as f:
                f.write('\n]')
        
        logger.info(f"Timeline exported to {output_file}")
    
    elif args.operation == 's3':
        # Create timeline object for streaming
        timeline = AWSTimeline([])
        
        # Open output file
        output_format = args.format
        output_file = args.output_file
        
        # Initialize the file with headers if CSV
        if output_format == 'csv':
            timeline.export_csv_header(output_file)
        elif output_format == 'json':
            # Initialize JSON file with opening bracket
            with open(output_file, 'w') as f:
                f.write('[\n')
        
        # Process events in batches
        first_batch = True
        for batch in collector.collect_from_s3(
            bucket_name=args.bucket,
            prefix=args.prefix,
            start_date=args.start_date,
            end_date=args.end_date,
            output_dir=args.output_dir,
            regions=args.regions
        ):
            # Parse events in this batch
            normalized_batch = CloudTrailParser.batch_normalize_events(batch)
            
            # Update timeline with this batch
            timeline.events = normalized_batch
            
            # Append to output file
            if output_format == 'csv':
                timeline.append_csv(output_file)
            else:  # JSON
                timeline.append_json(output_file, first_batch)
                first_batch = False
        
        # Finalize JSON file if needed
        if output_format == 'json':
            with open(output_file, 'a') as f:
                f.write('\n]')
        
        logger.info(f"Timeline exported to {output_file}")
            
    elif args.operation == 'management':
        # Calculate start and end times
        end_time = datetime.now()
        start_time = end_time - timedelta(days=args.days)
        
        # Collect management events
        events = collector.collect_management_events(
            start_time=start_time,
            end_time=end_time
        )
        
        # Parse events
        normalized_events = CloudTrailParser.batch_normalize_events(events)
        
        # Create timeline
        timeline = AWSTimeline(normalized_events)
        
        # Export timeline
        if args.format == 'csv':
            timeline.export_csv(args.output_file)
        else:
            timeline.export_json(args.output_file)
            
    elif args.operation == 'discover':
        # Discover CloudTrail trails
        trails = collector.discover_trails()
        
        if not trails:
            logger.info("No CloudTrail trails found")
        else:
            logger.info(f"Found {len(trails)} CloudTrail trails:")
            for trail in trails:
                logger.info(f"  - {trail['Name']}")
                logger.info(f"    S3 Bucket: {trail.get('S3BucketName', 'N/A')}")
                logger.info(f"    Region: {trail.get('HomeRegion', 'N/A')}")
                logger.info(f"    Multi-region: {trail.get('IsMultiRegionTrail', False)}")
                logger.info("")
                
    elif args.operation == 'explore-bucket':
        # Explore S3 bucket structure
        structure = collector.discover_bucket_structure(args.bucket)
        
        if 'error' in structure:
            logger.error(f"Error exploring bucket: {structure['error']}")
        else:
            logger.info(f"S3 Bucket Structure for: {args.bucket}")
            
            logger.info("Top-level prefixes:")
            for prefix in structure['top_level_prefixes']:
                logger.info(f"  - {prefix}")
                
            if structure['cloudtrail_paths']:
                logger.info("\nPotential CloudTrail paths:")
                for path in structure['cloudtrail_paths']:
                    logger.info(f"  - {path}")
                    
                logger.info("\nTo collect logs, use:")
                example_path = structure['cloudtrail_paths'][0]
                logger.info(f"  scope aws s3 --bucket {args.bucket} --prefix {example_path} --output-file timeline.csv")
            else:
                logger.info("\nNo CloudTrail paths automatically detected.")
                logger.info("If you know the path, use:")
                logger.info(f"  scope aws s3 --bucket {args.bucket} --prefix YOUR_PREFIX --output-file timeline.csv")

    elif args.operation == 'discover-resources':
        # Handle 'all' resource type
        if 'all' in args.resource_types:
            resource_types = None  # None means all supported types
        else:
            resource_types = args.resource_types
            
        # Discover resources
        resources = collector.discover_resources(
            resource_types=resource_types,
            regions=args.regions,
            output_format=args.format,
            output_file=args.output_file
        )
        
        logger.info(f"Resource discovery completed")
        
    elif args.operation == 'credential-report':
        # Generate and retrieve credential report
        report = collector.get_credential_report(
            output_format=args.format,
            output_file=args.output_file
        )
        
        if report:
            logger.info(f"Credential report retrieved successfully")
        else:
            logger.error("Failed to retrieve credential report")

def configure_aws_credentials(args):
    """
    Configure AWS credentials by prompting the user for input
    and saving to the AWS credentials file.
    """
    profile = args.profile
    
    # Prompt for credentials
    print(f"\nConfiguring AWS credentials for profile: {profile}")
    access_key = input("AWS Access Key ID: ")
    secret_key = input("AWS Secret Access Key: ")
    region = input("AWS Region (default is us-east-1): ") or "us-east-1"
    
    # Validate input
    if not access_key or not secret_key:
        logger.error("Access key and secret key cannot be empty")
        sys.exit(1)
    
    # Determine the AWS credentials file path
    credentials_file = os.path.expanduser("~/.aws/credentials")
    config_file = os.path.expanduser("~/.aws/config")
    
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(credentials_file), exist_ok=True)
    
    # Update credentials file
    credentials = configparser.ConfigParser()
    if os.path.exists(credentials_file):
        credentials.read(credentials_file)
    
    if profile not in credentials:
        credentials[profile] = {}
    
    credentials[profile]['aws_access_key_id'] = access_key
    credentials[profile]['aws_secret_access_key'] = secret_key
    
    with open(credentials_file, 'w') as f:
        credentials.write(f)
    
    # Update config file with region
    config = configparser.ConfigParser()
    if os.path.exists(config_file):
        config.read(config_file)
    
    profile_section = f"profile {profile}" if profile != "default" else "default"
    if profile_section not in config:
        config[profile_section] = {}
    
    config[profile_section]['region'] = region
    
    with open(config_file, 'w') as f:
        config.write(f)
    
    logger.info(f"AWS credentials configured successfully for profile: {profile}")
    print(f"\nAWS credentials saved to: {credentials_file}")
    print(f"AWS region configuration saved to: {config_file}")
    
    # Validate the credentials
    try:
        collector = AWSLogCollector(
            aws_access_key=access_key,
            aws_secret_key=secret_key,
            region=region
        )
        valid, account_id = collector.validate_credentials()
        if valid:
            print(f"\nCredentials validated successfully!")
            print(f"Connected to AWS Account: {account_id}")
        else:
            print(f"\nWarning: Credentials validation failed: {account_id}")
    except Exception as e:
        print(f"\nWarning: Error validating credentials: {str(e)}")

if __name__ == '__main__':
    main() 