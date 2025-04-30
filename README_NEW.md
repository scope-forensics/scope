<a id="readme-top"></a>

[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![Apache-2.0 license
][license-shield]][license-url]
[![LinkedIn][linkedin-shield]][linkedin-url]

<!-- https://github.com/othneildrew/Best-README-Template/blob/main/BLANK_README.md -->

<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/scope-forensics/scope">
    <img src="images/logo/logo.png" alt="Logo" width="80" height="80">
  </a>

<h3 align="center">Scope</h3>

  <p align="center">
    Scope is an Open Source Cloud Forensics tool for AWS. Scope can rapidly obtain logs, discover resources, and create super timelines for analysis.




    <br />
    <a href="https://scopeforensics.com/docs"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    <a href="https://github.com/scope-forensics/scope">View Project</a>
    &middot;
    <a href="https://github.com/scope-forensics/scope/issues/new?labels=bug&template=bug-report---.md">Report Bug</a>
    &middot;
    <a href="https://github.com/scope-forensics/scope/issues/new?labels=enhancement&template=feature-request---.md">Request Feature</a>
  </p>
</div>



<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
    <li><a href="#acknowledgments">Acknowledgments</a></li>
  </ol>
</details>



<!-- ABOUT THE PROJECT -->
## About The Project

[![Product Name Screen Shot][product-screenshot]](https://example.com)

Scope is an open source tool for collecting and analyzing cloud logs for forensic investigations. Scope currently supports AWS CloudTrail logs with plans to extend to Azure and GCP in the future.

### Features

- **AWS CloudTrail Collection**: Retrieve logs from S3 buckets or via the Management Events API
- **Normalized Timeline**: Convert cloud logs into a standardized timeline format
- **Multiple Export Formats**: Export timelines as CSV or JSON
- **Resource Discovery**: Identify available CloudTrail trails and AWS resources in your account
- **Credential Reports**: Generate and analyze IAM credential reports for security assessment

<p align="right">(<a href="#readme-top">back to top</a>)</p>



### Built With

* [![Python][python.org]][Python-url]

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- GETTING STARTED -->
## Getting Started

Follow these instructions to get Scope up and running on your local machine.

### Prerequisites

Scope requires Python 3.6 or higher.

### Installation

#### Using pip (Recommended)

```sh
pip install scope-forensics
```

#### From Source

```sh
# Clone the repo
git clone https://github.com/scope-forensics/scope.git
cd scope

# Install the package
pip install .

# For development (editable mode)
pip install -e .
```

5. Change git remote url to avoid accidental pushes to base project
   ```sh
   git remote set-url origin scope-forensics/scope
   git remote -v # confirm the changes
   ```

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- USAGE EXAMPLES -->
## Usage

### Basic Commands

```sh
# Display help information
scope --help

# List available commands
scope aws --help
```

### AWS Authentication

Scope supports multiple authentication methods:

1. **Interactive configuration**:
   ```sh
   # Configure AWS credentials interactively
   scope aws configure
   
   # Configure for a specific profile
   scope aws configure --profile my-profile
   ```

2. **Command-line arguments**:
   ```sh
   scope aws --access-key YOUR_ACCESS_KEY --secret-key YOUR_SECRET_KEY --region us-east-1 discover
   ```

3. **Environment variables**:
   ```sh
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
                   "s3:GetBucketLocation",
                   "ec2:DescribeInstances",
                   "iam:ListUsers",
                   "iam:ListRoles",
                   "iam:GenerateCredentialReport",
                   "iam:GetCredentialReport",
                   "lambda:ListFunctions",
                   "rds:DescribeDBInstances"
               ],
               "Resource": "*"
           }
       ]
   }
   ```
   - Name the policy "ScopeForensicsPolicy" and create it

### Discover CloudTrail Trails

To list all available CloudTrail trails in your AWS account:

```sh
scope aws discover
```

This command will display information about each trail, including its name, S3 bucket location, and whether it logs management events.

### Discover AWS Resources

To discover various AWS resources in your account (EC2, S3, IAM, Lambda, RDS):

```sh
# Discover all supported resource types
scope aws discover-resources

# Discover specific resource types
scope aws discover-resources --resource-types ec2 s3 --format json --output-file resources.json
```

Available parameters:
- `--resource-types`: Types of resources to discover (choices: ec2, s3, iam_users, iam_roles, lambda, rds, all)
- `--regions`: Specific AWS regions to search (space-separated)
- `--output-file`: Path to save the output
- `--format`: Output format (choices: json, csv, terminal)

### Generate IAM Credential Report

To generate and retrieve an IAM credential report:

```sh
# Display credential report in terminal
scope aws credential-report

# Save credential report as CSV
scope aws credential-report --format csv --output-file credentials.csv

# Save credential report as JSON
scope aws credential-report --format json --output-file credentials.json
```

Available parameters:
- `--output-file`: Path to save the output
- `--format`: Output format (choices: json, csv, terminal)

The credential report includes details about IAM users such as:
- Password and access key usage
- MFA status
- Access key rotation dates
- Last activity timestamps

### Collect Management Events

To collect CloudTrail management events:

```sh
scope aws management --days 7 --output-file timeline.csv --format csv
```

### Collect from S3

To collect CloudTrail logs stored in an S3 bucket:

```sh
scope aws s3 --bucket your-cloudtrail-bucket --output-file timeline.csv
```

### Collect from Local Files

To process CloudTrail logs that have already been downloaded to your local machine:

```sh
scope aws local --directory /path/to/logs --output-file timeline.csv
```

For more detailed usage examples and documentation, please refer to the [Documentation](https://scopeforensics.com/docs).

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- ROADMAP -->
## Roadmap

- [x] AWS CloudTrail Support
- [ ] Azure Support
- [ ] GCP Support
- [ ] Advanced Timeline Analysis
- [ ] Suspicious Activity Detection
- [ ] Resource Identification

See the [open issues](https://github.com/scope-forensics/scope/issues) for a full list of proposed features (and known issues).

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".
Don't forget to give the project a star! Thanks again!

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

<p align="right">(<a href="#readme-top">back to top</a>)</p>

### Top contributors:

<a href="https://github.com/scope-forensics/scope/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=scope-forensics/scope" alt="contrib.rocks image" />
</a>



<!-- LICENSE -->
## License

Distributed under the Apache-2.0 license. See `LICENSE.txt` for more information.

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- CONTACT -->
## Contact

Scope Team - [@twitter_handle](https://twitter.com/twitter_handle) - scopeforensics@protonmail.com

Project Link: [https://github.com/scope-forensics/scope](https://github.com/scope-forensics/scope)

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- ACKNOWLEDGMENTS -->
## Acknowledgments

* [AWS Documentation](https://docs.aws.amazon.com/)
* [CloudTrail Documentation](https://docs.aws.amazon.com/cloudtrail/)
* [Boto3 Documentation](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[contributors-shield]: https://img.shields.io/github/contributors/scope-forensics/scope.svg?style=for-the-badge
[contributors-url]: https://github.com/scope-forensics/scope/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/scope-forensics/scope.svg?style=for-the-badge
[forks-url]: https://github.com/scope-forensics/scope/network/members
[stars-shield]: https://img.shields.io/github/stars/scope-forensics/scope.svg?style=for-the-badge
[stars-url]: https://github.com/scope-forensics/scope/stargazers
[issues-shield]: https://img.shields.io/github/issues/scope-forensics/scope.svg?style=for-the-badge
[issues-url]: https://github.com/scope-forensics/scope/issues
[license-shield]: https://img.shields.io/github/license/scope-forensics/scope.svg?style=for-the-badge
[license-url]: https://github.com/scope-forensics/scope/blob/master/LICENSE.txt
[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=555
[linkedin-url]: https://linkedin.com/in/linkedin_username
[product-screenshot]: images/screenshot.png
[Next.js]: https://img.shields.io/badge/next.js-000000?style=for-the-badge&logo=nextdotjs&logoColor=white
[Next-url]: https://nextjs.org/
[React.js]: https://img.shields.io/badge/React-20232A?style=for-the-badge&logo=react&logoColor=61DAFB
[React-url]: https://reactjs.org/
[Vue.js]: https://img.shields.io/badge/Vue.js-35495E?style=for-the-badge&logo=vuedotjs&logoColor=4FC08D
[Vue-url]: https://vuejs.org/
[Angular.io]: https://img.shields.io/badge/Angular-DD0031?style=for-the-badge&logo=angular&logoColor=white
[Angular-url]: https://angular.io/
[Svelte.dev]: https://img.shields.io/badge/Svelte-4A4A55?style=for-the-badge&logo=svelte&logoColor=FF3E00
[Svelte-url]: https://svelte.dev/
[Laravel.com]: https://img.shields.io/badge/Laravel-FF2D20?style=for-the-badge&logo=laravel&logoColor=white
[Laravel-url]: https://laravel.com
[Bootstrap.com]: https://img.shields.io/badge/Bootstrap-563D7C?style=for-the-badge&logo=bootstrap&logoColor=white
[Bootstrap-url]: https://getbootstrap.com
[Htmx.org]: https://img.shields.io/badge/Htmx-563D7C?style=for-the-badge&logo=htmx&logoColor=white
[Htmx-url]: https://htmx.org 
[Docker.com]: https://img.shields.io/badge/Docker-2CA5E0?style=for-the-badge&logo=docker&logoColor=white
[Docker-url]: https://docker.com    
[Djangoproject.com]: https://img.shields.io/badge/Django-092E20?style=for-the-badge&logo=django&logoColor=white
[Django-url]: https://djangoproject.com
[Python.org]: https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white
[Python-url]: https://python.org

