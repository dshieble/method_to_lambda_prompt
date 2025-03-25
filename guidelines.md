# AWS Lambda Deployment Pattern with Docker and Parameter Store

This guide describes a pattern for deploying AWS Lambda functions using Docker containers and AWS Parameter Store for secure environment variable management. This pattern is particularly useful for complex Lambda functions that require multiple dependencies and secure configuration.

## Table of Contents
1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Project Structure](#project-structure)
4. [Implementation Steps](#implementation-steps)
   - [Parameter Store Implementation](#parameter-store-implementation)
   - [Lambda Function Handler](#lambda-function-handler)
   - [Dockerfile Configuration](#dockerfile-configuration)
   - [Deployment Scripts](#deployment-scripts)
5. [Usage](#usage)
6. [Testing](#testing)
7. [Best Practices](#best-practices)

## Overview

This pattern provides:
- Secure environment variable management using AWS Parameter Store
- Docker-based Lambda deployment
- Automated IAM role and policy management
- Deployment scripts for building and updating Lambda functions
- URL endpoint configuration with CORS support

## Prerequisites

1. AWS CLI configured with appropriate credentials
2. Docker installed and configured
3. Python 3.x installed
4. The following environment variables set:
   - `AWS_DEFAULT_REGION`
   - `AWS_ACCESS_KEY_ID`
   - `AWS_SECRET_ACCESS_KEY`

## Project Structure

```
your-project/
├── scripts/
│   ├── deploy.sh
│   ├── deploy_lambda.py
│   ├── test_lambda.py
│   └── publish_env_to_aws.py
├── your_package/
│   ├── __init__.py
│   ├── lambda_function.py
│   └── utilities/
│       └── parameters.py
├── Dockerfile
├── requirements.txt
└── remote_env.json
```

## Implementation Steps

### Parameter Store Implementation

1. Create a Parameter Store client (`parameters.py`):

```python
import boto3
import json
from typing import Dict

class ParameterStoreClient:
    def __init__(self, region_name: str = "us-east-1"):
        self.ssm = boto3.client('ssm', region_name=region_name)
    
    def load_parameters(self, parameter_name: str) -> Dict[str, str]:
        response = self.ssm.get_parameter(
            Name=parameter_name,
            WithDecryption=True
        )
        return json.loads(response['Parameter']['Value'])
    
    def publish_parameters(self, 
        parameters: Dict[str, str], 
        parameter_name: str,
        description: str = "Environment variables"
    ) -> None:
        json_string = json.dumps(parameters)
        self.ssm.put_parameter(
            Name=parameter_name,
            Description=description,
            Value=json_string,
            Type='SecureString',
            Overwrite=True
        )

def set_environment_variables_from_parameter_store(parameter_name: str) -> None:
    client = ParameterStoreClient()
    env_vars = client.load_parameters(parameter_name=parameter_name)
    for key, value in env_vars.items():
        os.environ[key] = value
```

2. Create a script to publish environment variables (`publish_env_to_aws.py`):

```python
#!/usr/bin/env python3
import json
import logging
from your_package.utilities.parameters import ParameterStoreClient

ENVIRONMENT_PARAMETER_NAME = "/your_package/environment"

def read_env_file(env_path: str = "remote_env.json") -> Dict[str, str]:
    with open(env_path, 'r') as f:
        return json.load(f)

if __name__ == "__main__":
    logging.getLogger().setLevel(logging.INFO)
    env_vars = read_env_file()
    client = ParameterStoreClient()
    client.publish_parameters(
        parameters=env_vars,
        parameter_name=ENVIRONMENT_PARAMETER_NAME,
        description='Your app environment variables'
    )
```

### Lambda Function Handler

Create your Lambda function handler (`lambda_function.py`). Make sure to replace your_package with the actual package name.

```python
import os
import logging
import asyncio
from your_package.utilities.parameters import set_environment_variables_from_parameter_store

logger = logging.getLogger()
logger.setLevel(logging.INFO)

async def handle_lambda_event(event, context):
    """Implement your Lambda function logic here"""
    pass

def handler(event, context):
    """AWS Lambda handler function"""
    logger.info("Lambda function handler called")
    set_environment_variables_from_parameter_store()
    return asyncio.run(handle_lambda_event(event, context))
```

### Dockerfile Configuration

Create a Dockerfile for your Lambda function:

```dockerfile
FROM public.ecr.aws/lambda/python:3.12

# Copy requirements.txt
COPY requirements.txt ${LAMBDA_TASK_ROOT}

# Install the specified packages
RUN pip install -r requirements.txt

# Copy function code
COPY ./your_package ${LAMBDA_TASK_ROOT}/your_package

# Set the CMD to your handler
CMD [ "your_package.lambda_function.handler" ]
```

### Deployment Scripts

1. Create a deployment script (`deploy.sh`):

```bash
#!/bin/bash

set -e  # Exit on any error

# Configuration
REGION="us-east-1"
FUNCTION_NAME="your-function-name"
IMAGE_NAME="your-image-name"
ECR_REPO="your-account-id.dkr.ecr.${REGION}.amazonaws.com"

# Create ECR repository if it doesn't exist
aws ecr describe-repositories --repository-names ${IMAGE_NAME} --region ${REGION} || \
    aws ecr create-repository --repository-name ${IMAGE_NAME} --region ${REGION}

# Build Docker image
docker build -t ${IMAGE_NAME}:latest .

# Get ECR login token
aws ecr get-login-password --region ${REGION} | docker login --username AWS --password-stdin ${ECR_REPO}

# Tag and push image
docker tag ${IMAGE_NAME}:latest ${ECR_REPO}/${IMAGE_NAME}:latest
docker push ${ECR_REPO}/${IMAGE_NAME}:latest

# Deploy Lambda function
python scripts/deploy_lambda.py \
    --function_name ${FUNCTION_NAME} \
    --image_uri ${ECR_REPO}/${IMAGE_NAME}:latest \
    --region ${REGION}
```

2. Create a Lambda deployment script (`deploy_lambda.py`):

```python
#!/usr/bin/env python3

import argparse
import logging
import os
import sys
import boto3
import json
import time
from typing import Any

def wait_for_role_propagation(
    iam_client: Any,
    role_name: str,
    max_attempts: int = 30
) -> None:
    """
    Waits for an IAM role to fully propagate through AWS.
    
    Args:
        iam_client: Boto3 IAM client
        role_name: Name of the role to check
        max_attempts: Maximum number of attempts to check role
    """
    logging.info(f"Waiting for role {role_name} to propagate...")
    for attempt in range(max_attempts):
        time.sleep(10)  # Increased sleep time to allow for better propagation
        try:
            # Get the role to verify it exists
            role = iam_client.get_role(RoleName=role_name)
            
            # Verify trust relationship
            trust_policy = role['Role']['AssumeRolePolicyDocument']
            trust_valid = False
            
            # Check if Lambda service is allowed to assume the role
            required_services = {'lambda.amazonaws.com'}
            allowed_services = set()
            
            for statement in trust_policy['Statement']:
                if statement.get('Effect') == 'Allow' and 'sts:AssumeRole' in statement.get('Action', []):
                    services = statement.get('Principal', {}).get('Service', [])
                    if isinstance(services, str):
                        services = [services]
                    allowed_services.update(services)
            
            if required_services.issubset(allowed_services):
                trust_valid = True
            
            if not trust_valid:
                raise Exception("Trust policy not properly configured")
                
            # Check attached policies
            iam_client.list_attached_role_policies(RoleName=role_name)
            iam_client.list_role_policies(RoleName=role_name)
            
            logging.info("Role is ready!")
            return
            
        except iam_client.exceptions.NoSuchEntityException:
            logging.info(f"Attempt {attempt + 1}/{max_attempts}: Role not yet propagated...")
        
    raise TimeoutError(f"Role {role_name} did not propagate within {max_attempts * 10} seconds")

def delete_role_if_exists(
    iam_client: Any,
    role_name: str
) -> None:
    """
    Deletes an IAM role and all its attached policies if it exists.
    
    Args:
        iam_client: Boto3 IAM client
        role_name: Name of the role to delete
    """
    try:
        # First detach all managed policies
        paginator = iam_client.get_paginator('list_attached_role_policies')
        for page in paginator.paginate(RoleName=role_name):
            for policy in page['AttachedPolicies']:
                logging.info(f"Detaching managed policy: {policy['PolicyArn']}")
                iam_client.detach_role_policy(
                    RoleName=role_name,
                    PolicyArn=policy['PolicyArn']
                )
        
        # Delete all inline policies
        paginator = iam_client.get_paginator('list_role_policies')
        for page in paginator.paginate(RoleName=role_name):
            for policy_name in page['PolicyNames']:
                logging.info(f"Deleting inline policy: {policy_name}")
                iam_client.delete_role_policy(
                    RoleName=role_name,
                    PolicyName=policy_name
                )
        
        # Delete the role
        logging.info(f"Deleting role: {role_name}")
        iam_client.delete_role(RoleName=role_name)
        logging.info(f"Successfully deleted role: {role_name}")
        
    except iam_client.exceptions.NoSuchEntityException:
        logging.info(f"Role {role_name} does not exist")
    except Exception as e:
        logging.info(f"Error deleting role {role_name}: {str(e)}")
        raise

def delete_lambda_if_exists(
    lambda_client: Any,
    function_name: str
) -> None:
    """
    Deletes a Lambda function if it exists.
    
    Args:
        lambda_client: Boto3 Lambda client
        function_name: Name of the function to delete
    """
    try:
        # Delete function URL if it exists
        try:
            lambda_client.delete_function_url_config(FunctionName=function_name)
            logging.info(f"Deleted function URL for: {function_name}")
        except lambda_client.exceptions.ResourceNotFoundException:
            pass
        
        logging.info(f"Deleting function: {function_name}")
        lambda_client.delete_function(FunctionName=function_name)
        logging.info(f"Successfully deleted function: {function_name}")
    except lambda_client.exceptions.ResourceNotFoundException:
        logging.info(f"Function {function_name} does not exist")
    except Exception as e:
        logging.info(f"Error deleting function {function_name}: {str(e)}")
        raise

def wait_for_function_update_completion(
    lambda_client: Any,
    function_name: str,
    max_attempts: int = 60
) -> None:
    """
    Waits for a Lambda function update to complete.
    
    Args:
        lambda_client: Boto3 Lambda client
        function_name: Name of the Lambda function
        max_attempts: Maximum number of attempts to check status
    """
    logging.info(f"Waiting for function {function_name} to be ready...")
    for attempt in range(max_attempts):
        response = lambda_client.get_function(FunctionName=function_name)
        config = response['Configuration']
        state = config['State']
        last_update = config.get('LastUpdateStatus', 'Successful')
        
        logging.info(f"Attempt {attempt + 1}/{max_attempts}: State={state}, LastUpdateStatus={last_update}")
        
        if state == 'Active' and last_update in ['Successful', None]:
            logging.info("Function is ready!")
            return
            
        time.sleep(2)
        
    raise TimeoutError(
        f"Function {function_name} did not become active within {max_attempts * 2} seconds. "
        f"Final state: {state}, LastUpdateStatus: {last_update}"
    )

def deploy_lambda_function(
    function_name: str,
    image_uri: str,
    region: str,
    memory_size: int = 1024,
    timeout: int = 900,
    delete_existing: bool = False,
    architecture: str = 'arm64'
) -> dict:
    """
    Creates or updates an AWS Lambda function using the Docker container.
    
    Args:
        function_name: Name of the Lambda function
        image_uri: Full URI of the Docker image
        region: AWS region
        memory_size: Memory size in MB for the Lambda function
        timeout: Timeout in seconds for the Lambda function
        delete_existing: If True, delete and recreate resources. If False, update existing resources.
        architecture: CPU architecture to use ('arm64' or 'x86_64')
        
    Returns:
        Dict containing information about created resources and their console URLs
    """
    # Initialize clients
    lambda_client = boto3.client('lambda', region_name=region)
    iam_client = boto3.client('iam', region_name=region)
    
    # Create role for Lambda
    role_name = f"{function_name}-role"
    
    if delete_existing:
        # Delete existing role if it exists
        delete_role_if_exists(iam_client=iam_client, role_name=role_name)
        
        # Create new role
        logging.info(f"Creating new role: {role_name}")
        assume_role_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole"
            }]
        }
        role = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(assume_role_policy)
        )
        role_arn = role['Role']['Arn']
        
        # Attach necessary policies
        iam_client.attach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
        )
        
        # Add permissions for Parameter Store
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "ssm:GetParameter",
                        "ssm:GetParameters"
                    ],
                    "Resource": f"arn:aws:ssm:{region}:*:parameter/your_package/*"
                }
            ]
        }
        
        iam_client.put_role_policy(
            RoleName=role_name,
            PolicyName=f"{role_name}-parameter-store",
            PolicyDocument=json.dumps(policy_document)
        )
        
        # Wait for role and policies to propagate
        wait_for_role_propagation(
            iam_client=iam_client,
            role_name=role_name
        )
    else:
        try:
            role = iam_client.get_role(RoleName=role_name)
            role_arn = role['Role']['Arn']
            logging.info(f"Using existing role: {role_name}")
        except iam_client.exceptions.NoSuchEntityException:
            # If role doesn't exist, create it
            logging.info(f"Role {role_name} not found, creating new role")
            assume_role_policy = {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole"
                }]
            }
            role = iam_client.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(assume_role_policy)
            )
            role_arn = role['Role']['Arn']
            
            # Attach necessary policies
            iam_client.attach_role_policy(
                RoleName=role_name,
                PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
            )
            
            # Add permissions for Parameter Store
            policy_document = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "ssm:GetParameter",
                            "ssm:GetParameters"
                        ],
                        "Resource": f"arn:aws:ssm:{region}:*:parameter/your_package/*"
                    }
                ]
            }
            
            iam_client.put_role_policy(
                RoleName=role_name,
                PolicyName=f"{role_name}-parameter-store",
                PolicyDocument=json.dumps(policy_document)
            )
            
            # Wait for role and policies to propagate
            wait_for_role_propagation(
                iam_client=iam_client,
                role_name=role_name
            )

    # Function configuration
    function_config = {
        'FunctionName': function_name,
        'Role': role_arn,
        'Code': {'ImageUri': image_uri},
        'PackageType': 'Image',
        'Timeout': timeout,
        'MemorySize': memory_size,
        'Environment': {
            'Variables': {}  # Add environment variables if needed
        },
        'Architectures': [architecture]
    }

    if delete_existing:
        # Delete existing function if it exists
        delete_lambda_if_exists(
            lambda_client=lambda_client,
            function_name=function_name
        )
        
        # Create the Lambda function
        logging.info(f"Creating new Lambda function: {function_name}")
        response = lambda_client.create_function(**function_config)
    else:
        try:
            # Try to update the existing function
            logging.info(f"Updating existing Lambda function: {function_name}")
            response = lambda_client.update_function_configuration(
                FunctionName=function_name,
                Role=role_arn,
                Timeout=timeout,
                MemorySize=memory_size,
                Environment=function_config['Environment']
            )
            
            # Wait for configuration update to complete before updating code
            wait_for_function_update_completion(
                lambda_client=lambda_client,
                function_name=function_name
            )
            
            # Update the function code separately
            lambda_client.update_function_code(
                FunctionName=function_name,
                ImageUri=image_uri
            )
        except lambda_client.exceptions.ResourceNotFoundException:
            # If function doesn't exist, create it
            logging.info(f"Function {function_name} not found, creating new function")
            response = lambda_client.create_function(**function_config)
    
    # Wait for function to be active
    wait_for_function_update_completion(
        lambda_client=lambda_client,
        function_name=function_name
    )
    
    # Create or update function URL with CORS configuration
    try:
        url_config = lambda_client.get_function_url_config(FunctionName=function_name)
    except lambda_client.exceptions.ResourceNotFoundException:
        url_config = lambda_client.create_function_url_config(
            FunctionName=function_name,
            AuthType='NONE',  # Allow unauthenticated access for webhook
            Cors={
                'AllowOrigins': ['*'],  # Allow requests from any origin
                'AllowMethods': ['POST', 'OPTIONS'],  # Allow POST and OPTIONS methods for webhook
                'AllowHeaders': ['*'],  # Allow all headers
                'ExposeHeaders': ['*'],  # Expose all headers
                'MaxAge': 86400  # Cache preflight request results for 24 hours
            }
        )
        
        # Add permission for public access to function URL if newly created
        try:
            lambda_client.add_permission(
                FunctionName=function_name,
                StatementId='FunctionURLAllowPublicAccess',
                Action='lambda:InvokeFunctionUrl',
                Principal='*',
                FunctionUrlAuthType='NONE'
            )
        except lambda_client.exceptions.ResourceConflictException:
            # Permission already exists
            pass
    
    result = {
        "function_name": function_name,
        "function_arn": response['FunctionArn'],
        "function_url": url_config['FunctionUrl'],
        "role_name": role_name,
        "role_arn": role_arn,
        "console_urls": {
            "lambda": f"https://{region}.console.aws.amazon.com/lambda/home?region={region}#/functions/{function_name}",
            "iam": f"https://console.aws.amazon.com/iam/home?#/roles/{role_name}"
        }
    }
    
    logging.info("\nCreated/Updated AWS resources:")
    logging.info(f"Lambda Function: {result['console_urls']['lambda']}")
    logging.info(f"Function URL: {result['function_url']}")
    logging.info(f"IAM Role: {result['console_urls']['iam']}")
    
    return result

if __name__ == "__main__":
    logging.getLogger().setLevel(logging.INFO)
    parser = argparse.ArgumentParser(
        description='Create or update AWS Lambda function'
    )
    parser.add_argument(
        '--function_name',
        required=True,
        help='Name of the Lambda function'
    )
    parser.add_argument(
        '--image_uri',
        required=True,
        help='Full URI of the Docker image'
    )
    parser.add_argument(
        '--region',
        default="us-east-1",
        help='AWS region (default: us-east-1)'
    )
    parser.add_argument(
        '--delete_existing',
        action='store_true',
        help='Delete and recreate resources instead of updating them'
    )
    parser.add_argument(
        '--architecture',
        default='arm64',
        choices=['arm64', 'x86_64'],
        help='CPU architecture to use (default: arm64)'
    )
    args = parser.parse_args()

    result = deploy_lambda_function(
        function_name=args.function_name,
        image_uri=args.image_uri,
        region=args.region,
        delete_existing=args.delete_existing,
        architecture=args.architecture
    )
```

## Usage

1. Create your environment variables file (`remote_env.json`):
```json
{
    "API_KEY": "your-api-key",
    "DATABASE_URL": "your-database-url",
    "OTHER_CONFIG": "other-configuration"
}
```

2. Publish environment variables to Parameter Store:
```bash
python scripts/publish_env_to_aws.py
```

3. Deploy your Lambda function:
```bash
bash scripts/deploy.sh
```

## Testing

After deploying your Lambda function, it's important to verify that it's working correctly. Create a test script (`test_lambda.py`) to validate the function's behavior:

```python
#!/usr/bin/env python3

import argparse
import json
import logging
import requests
from typing import Dict, Any

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def create_sample_payload() -> Dict[str, Any]:
    """Create a sample payload for testing."""
    return {
        # Customize this payload based on your Lambda function's expected input
        "test_data": "example",
        "parameters": {
            "key1": "value1",
            "key2": "value2"
        }
    }

def test_lambda_function(function_url: str) -> None:
    """Test the Lambda function with a sample payload.
    
    Args:
        function_url: The URL of the Lambda function
    """
    # Create sample payload
    payload = create_sample_payload()
    logger.info("Testing Lambda function with sample payload:")
    logger.info(json.dumps(payload, indent=2))
    
    try:
        # Send request to Lambda function
        response = requests.post(function_url, json=payload)
        response.raise_for_status()
        
        # Parse and display response
        result = response.json()
        logger.info("\nLambda function response:")
        logger.info(json.dumps(result, indent=2))
        
        # Validate response structure
        if not isinstance(result, dict):
            logger.error("Response is not a valid JSON object")
            return
            
        # Log success
        logger.info("\nTest completed successfully!")
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to call Lambda function: {str(e)}")
        if hasattr(e.response, 'text'):
            logger.error(f"Response text: {e.response.text}")
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse response JSON: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Test the Lambda function')
    parser.add_argument(
        '--function-url',
        required=True,
        help='The URL of the Lambda function'
    )
    args = parser.parse_args()
    
    test_lambda_function(args.function_url)
```
