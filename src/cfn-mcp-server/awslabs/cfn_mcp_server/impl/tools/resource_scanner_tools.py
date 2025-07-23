# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Resource-related tools for the CFN MCP Server."""

from awslabs.cfn_mcp_server.errors import ClientError, PromptUser, handle_aws_api_error
from awslabs.cfn_mcp_server.stack_analysis.cloudformation_utils import CloudFormationUtils
from typing import Any, Dict, List, Optional


async def handle_start_resource_scan(
    resource_types: Optional[List[str]] = None,
    region: Optional[str] = None,
) -> Dict[str, Any]:
    """Start a resource scan for specific AWS resource types or the entire account.

    Args:
        resource_types: List of AWS resource types to scan (e.g., ["AWS::S3::Bucket", "AWS::RDS::DBInstance"])
                       Provide an empty list [] to scan the entire account
        region: AWS region to use (e.g., "us-east-1", "us-west-2")

    Returns:
        Dict containing the scan information:
        {
            "scan_id": The unique identifier for the started scan
        }
    """
    # Prompt user for input if no resource type is provided
    if resource_types is None:
        common_resource_types = [
            'AWS::S3::Bucket',
            'AWS::EC2::Instance',
            'AWS::RDS::DBInstance',
            'AWS::Lambda::Function',
            'AWS::IAM::Role',
        ]

        raise PromptUser(
            'Please specify resource types to scan. Options:\n\n'
            '1. Provide specific resource types)\n'
            '2. Provide an empty list [] to scan the entire account\n\n'
            'Common resource types include:\n'
            + '\n'.join([f'- {rt}' for rt in common_resource_types])
            + f'\n\nExample usage:\n'
            f'- Single resource type: ["AWS::S3::Bucket"]\n'
            f'- Multiple types: {common_resource_types}\n'
            f'- Entire account: []'
        )

    try:
        cfn_utils = CloudFormationUtils(region=region or 'us-east-1')
    except Exception as e:
        raise handle_aws_api_error(e)

    try:
        scan_id = cfn_utils.start_resource_scan(resource_types)
        return {
            'scan_id': scan_id,
        }
    except Exception as e:
        raise handle_aws_api_error(e)


async def list_resources_by_filter_impl(
    resource_identifier: Optional[str] = None,
    resource_type_prefix: Optional[str] = None,
    tag_key: Optional[str] = None,
    tag_value: Optional[str] = None,
    limit: int = 100,
    next_token: Optional[str] = None,
    region: Optional[str] = None,
) -> Dict[str, Any]:
    """Simple implementation for listing AWS resources with filtering.

    Args:
        resource_identifier: Filter by specific resource identifier (e.g., physical ID)
        resource_type_prefix: Filter by resource type prefix (e.g., "AWS::S3::")
        tag_key: Filter resources by tag key
        tag_value: Filter resources by tag value (requires tag_key)
        limit: Maximum number of resources to return (1-100)
        next_token: AWS pagination token from previous response
        region: AWS region to use

    Returns:
        Dict containing filtered resources and pagination info
    """
    # Basic validation
    if limit < 1 or limit > 100:
        raise ClientError('Limit must be between 1 and 100')

    try:
        cfn_utils = CloudFormationUtils(region=region or 'us-east-1')

        # Get latest completed scan
        scans = cfn_utils.list_resource_scans()
        latest_scan = next((s for s in scans if s.get('Status') == 'COMPLETE'), None)
        if not scans:
            raise ClientError('No resource scans found in account. Please start a resource scan.')
        if not latest_scan:
            raise ClientError(
                'No completed resource scans found. Scan could still be in progress or start a resource scan if you none exists.'
            )

        # Get filtered resources from AWS API
        if resource_type_prefix or tag_key or tag_value or resource_identifier:
            result = cfn_utils.list_resource_scan_resources_with_filters(
                scan_id=latest_scan['ResourceScanId'],
                resource_identifier=resource_identifier,
                resource_type_prefix=resource_type_prefix,
                tag_key=tag_key,
                tag_value=tag_value,
                max_results=limit,
                next_token=next_token,
            )
            resources = result['resources']
        else:
            # Get all resources if no filters
            all_resources = cfn_utils.list_resource_scan_resources(latest_scan['ResourceScanId'])
            resources = all_resources[:limit]
            # If more than limit, set next_token (has more boolean)
            result = {'next_token': None if len(all_resources) <= limit else 'has_more'}

        # Format output
        managed_resources = []
        unmanaged_resources = []

        for resource in resources:
            resource_entry = {
                'identifier': resource.get('ResourceIdentifier', {}),
                'resource_type': resource.get('ResourceType'),
            }

            if resource.get('ManagedByStack'):
                managed_resources.append(resource_entry)
            else:
                unmanaged_resources.append(resource_entry)

        return {
            'managed_resources': managed_resources,
            'unmanaged_resources': unmanaged_resources,
            'count': {
                'managed': len(managed_resources),
                'unmanaged': len(unmanaged_resources),
                'total': len(resources),
            },
            'pagination': {
                'limit': limit,
                'next_token': result.get('next_token'),
                'has_more': bool(result.get('next_token')),
            },
        }

    except Exception as e:
        raise handle_aws_api_error(e)


async def list_related_resources_impl(
    resources: List[Dict[str, Any]],
    max_results: int = 100,
    next_token: Optional[str] = None,
    region: Optional[str] = None,
) -> Dict[str, Any]:
    """Simple implementation for listing AWS resources related to specified resources.

    Args:
        resources: List of resources to find related resources for, each resource should be a dictionary
                   with 'resource_type' and 'resource_identifier' keys.
                   Example: [{'resource_type': 'AWS::S3::Bucket', 'resource_identifier': 'my-bucket-123'}]

        max_results: Maximum number of related resources to return (1-100)
        next_token: AWS pagination token from previous response
        region: AWS region to use

    Returns:
        Dict containing related resources and pagination info
    """
    # Basic validation
    if not resources:
        raise ClientError('Please provide at least one resource')

    if len(resources) > 100:
        raise ClientError('Maximum of 100 resources allowed')

    if max_results < 1 or max_results > 100:
        raise ClientError('max_results must be between 1 and 100')

    try:
        cfn_utils = CloudFormationUtils(region=region or 'us-east-1')

        # Get latest completed scan
        scans = cfn_utils.list_resource_scans()
        latest_scan = next((s for s in scans if s.get('Status') == 'COMPLETE'), None)
        if not scans:
            raise ClientError('No resource scans found in account. Please start a resource scan.')
        if not latest_scan:
            raise ClientError(
                'No completed resource scans found. Scan could still be in progress or start a resource scan if you none exists.'
            )

        # Format resources for API call
        formatted_resources = []
        for resource in resources:
            if not isinstance(resource, Dict):
                raise ClientError('Each resource must be a dictionary')

            resource_type = resource.get('resource_type')
            resource_identifier = resource.get('resource_identifier')

            if not resource_type or not resource_identifier:
                raise ClientError('Each resource must have resource_type and resource_identifier')

            formatted_resources.append(
                {'ResourceType': resource_type, 'ResourceIdentifier': resource_identifier}
            )

        # Call AWS API
        response = cfn_utils.cfn_client.list_resource_scan_related_resources(
            ResourceScanId=latest_scan['ResourceScanId'],
            Resources=formatted_resources,
            MaxResults=max_results,
            **({'NextToken': next_token} if next_token else {}),
        )

        related_resources = response.get('RelatedResources', [])

        managed_resources = []
        unmanaged_resources = []

        for resource in related_resources:
            resource_entry = {
                'resource_type': resource.get('ResourceType'),
                'resource_identifier': resource.get('ResourceIdentifier', {}),
                'managed_by_stack': resource.get('ManagedByStack', False),
            }

            if resource.get('ManagedByStack'):
                managed_resources.append(resource_entry)
            else:
                unmanaged_resources.append(resource_entry)

        return {
            'related_resources': {'managed': managed_resources, 'unmanaged': unmanaged_resources},
            'count': {
                'managed': len(managed_resources),
                'unmanaged': len(unmanaged_resources),
                'total': len(related_resources),
            },
            'pagination': {
                'max_results': max_results,
                'next_token': response.get('NextToken'),
                'has_more': bool(response.get('NextToken')),
            },
        }

    except Exception as e:
        raise handle_aws_api_error(e)
