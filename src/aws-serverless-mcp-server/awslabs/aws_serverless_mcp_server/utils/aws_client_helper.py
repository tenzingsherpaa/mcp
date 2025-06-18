import boto3
from awslabs.aws_serverless_mcp_server import __version__
from botocore.config import Config
from typing import Any, Optional


def get_aws_client(service_name: str, region: Optional[str]) -> Any:
    """Creates and returns a boto3 client for the specified AWS service.

    Args:
        service_name (str): The name of the AWS service (e.g., 's3', 'ec2').
        region (Optional[str]): The AWS region to use for the client. If None, the default region is used.

    Returns:
        object: A boto3 client instance for the specified AWS service.

    Notes:
        - The client is configured with a custom user agent string for identification.
        - Requires valid AWS credentials to be configured in the environment.
    """
    boto_config = Config(user_agent_extra=f'awslabs/mcp/aws-serverless-mcp-server/{__version__}')
    session = boto3.Session(region_name=region) if region else boto3.Session()
    return session.client(service_name, config=boto_config)
