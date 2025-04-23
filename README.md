# Scope - Cloud Forensics Tool

Scope is an open source tool for collecting and analyzing cloud logs for forensic investigations. Scope currently supports AWS CloudTrail logs with plans to extend to Azure and GCP in the future.

## Features

- **AWS CloudTrail Collection**: Retrieve logs from S3 buckets or via the Management Events API
- **Normalized Timeline**: Convert cloud logs into a standardized timeline format
- **Multiple Export Formats**: Export timelines as CSV or JSON
- **Resource Discovery**: Identify available CloudTrail trails in your AWS account

## Installation

### Using pip (Recommended)

```bash
pip install scope
```

### From Source

```bash
# Clone the repository
git clone https://github.com/scope-forensics/scope.git
cd scope

# Install the package
pip install .

# For development (editable mode)
pip install -e .
```

## Usage

### Basic Commands

```bash
# Display help information
scope --help

# List available commands
scope aws --help
```

### AWS Authentication

Scope supports multiple authentication methods:

1. **Interactive configuration**:
   ```bash
   # Configure AWS credentials interactively
   scope aws configure
   
   # Configure for a specific profile
   scope aws configure --profile my-profile
   ```

2. **Command-line arguments**:
   ```bash
   scope aws --access-key YOUR_ACCESS_KEY --secret-key YOUR_SECRET_KEY --region us-east-1 discover
   ```

3. **Environment variables**:
   ```bash
   # Windows
   set AWS_ACCESS_KEY_ID=your_access_key
   set AWS_SECRET_ACCESS_KEY=your_secret_key
   set AWS_DEFAULT_REGION=us-east-1
   
   # macOS/Linux
   export AWS_ACCESS_KEY_ID=your_access_key
   export AWS_SECRET_ACCESS_KEY=your_secret_key
   export AWS_DEFAULT_REGION=us-east-1
   ```

4. **AWS credentials file** (`~/.aws/credentials`)
5. **IAM role** (if running on an EC2 instance with an IAM role)

### Setting Up AWS Permissions

To use Scope effectively, you'll need an AWS user with appropriate permissions. Here's how to create one:

1. **Sign in to the AWS Management Console** and open the IAM console.

2. **Create a new policy**:
   - Go to "Policies" and click "Create policy"
   - Use the JSON editor and paste the following policy:
   ```json
   {
       "Version": "2012-10-17",
       "Statement": [
           {
               "Effect": "Allow",
               "Action": [
                   "cloudtrail:LookupEvents",
                   "cloudtrail:DescribeTrails",
                   "s3:GetObject",
                   "s3:ListBucket",
                   "s3:GetBucketLocation"
               ],
               "Resource": "*"
           }
       ]
   }
   ```
   - Name the policy "ScopeForensicsPolicy" and create it

3. **Create a new user**:
   - Go to "Users" and click "Add users"
   - Enter a username (e.g., "scope-forensics")
   - Select "Access key - Programmatic access"
   - Click "Next: Permissions"
   - Select "Attach existing policies directly"
   - Search for and select the "ScopeForensicsPolicy" you created
   - Complete the user creation process

4. **Save the credentials**:
   - Download or copy the Access Key ID and Secret Access Key
   - Use these credentials with the `scope aws configure` command

> **Note**: Consider using more restrictive permissions by limiting the "Resource" section to specific S3 buckets and CloudTrail trails.

### Discover CloudTrail Trails

To list all available CloudTrail trails in your AWS account:

```bash
scope aws discover
```

This command will display information about each trail, including its name, S3 bucket location, and whether it logs management events.

### Explore S3 Bucket Structure

To explore the structure of an S3 bucket and automatically detect CloudTrail logs:

```bash
scope aws explore-bucket --bucket your-cloudtrail-bucket
```

This command will:
1. List top-level prefixes in the bucket
2. Automatically detect potential CloudTrail log paths
3. Provide a ready-to-use command for collecting logs from the detected paths

### Collect Management Events

To collect CloudTrail management events:

```bash
scope aws management --days 7 --output-file timeline.csv --format csv
```

Available parameters:
- `--days`: Number of days to look back (default: 7)
- `--output-file`: Path to save the timeline (required)
- `--format`: Choose between 'csv' or 'json' (default: csv)

### Collect from S3

To collect CloudTrail logs stored in an S3 bucket:

```bash
scope aws s3 --bucket your-cloudtrail-bucket --output-file timeline.csv
```

The command will automatically:
1. Discover the CloudTrail log structure in your bucket
2. Identify all available regions
3. Collect logs from all regions for the specified time period

For more control, you can specify additional parameters:

```bash
scope aws s3 --bucket your-cloudtrail-bucket --prefix AWSLogs/123456789012/CloudTrail/ --regions us-east-1 us-west-2 --start-date 2023-04-15 --end-date 2023-04-22 --output-dir ./raw_logs --output-file timeline.csv --format json
```

Available parameters:
- `--bucket`: S3 bucket containing CloudTrail logs (required)
- `--prefix`: S3 prefix to filter logs (optional)
- `--regions`: Specific regions to collect from (space-separated list)
- `--start-date`: Start date in YYYY-MM-DD format (default: 7 days ago)
- `--end-date`: End date in YYYY-MM-DD format (default: today)
- `--output-dir`: Directory to save raw logs (optional)
- `--output-file`: Path to save the timeline (required)
- `--format`: Choose between 'csv' or 'json' (default: csv)

### Collect from Local Files

To process CloudTrail logs that have already been downloaded to your local machine:

```bash
scope aws local --directory /path/to/logs --output-file timeline.csv
```

For recursive processing of all subdirectories:

```bash
scope aws local --directory /path/to/logs --recursive --output-file timeline.csv --format json
```

> **Note for Windows users**: When specifying file paths, use one of these formats:
> - Forward slashes: `C:/Users/username/Desktop/CloudTrail`
> - Escaped backslashes: `C:\\Users\\username\\Desktop\\CloudTrail`
> - Quoted paths: `"C:\Users\username\Desktop\CloudTrail"`

Available parameters:
- `--directory`: Directory containing CloudTrail logs (required)
- `--recursive`: Process subdirectories recursively
- `--output-file`: Path to save the timeline (required)
- `--format`: Choose between 'csv' or 'json' (default: csv)

This command will:
1. Find all CloudTrail log files (`.json` or `.json.gz`) in the specified directory
2. Parse and normalize the events
3. Create a standardized timeline in the specified format

### Exporting Timelines

By default, Scope exports timelines to the specified output file. You can specify different formats:

```