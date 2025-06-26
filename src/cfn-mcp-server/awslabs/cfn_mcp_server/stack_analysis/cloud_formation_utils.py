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

import logging
from awslabs.cfn_mcp_server.aws_client import get_aws_client
from awslabs.cfn_mcp_server.errors import ClientError, handle_aws_api_error
from typing import Any, Dict, List, Optional


logger = logging.getLogger(__name__)


class CloudFormationUtils:
    """Utility class for CloudFormation API operations."""

    def __init__(self, region: Optional[str] = None):
        """Initialize the CloudFormationUtils with the specified AWS region and store the resource scan ID."""
        self.region = region
        self._cfn_client = None
        self.resource_scan_id: Optional[str] = None

    @property
    def cfn_client(self):
        """Lazy-loaded CloudFormation client."""
        if self._cfn_client is None:
            try:
                self._cfn_client = get_aws_client('cloudformation', self.region)
            except Exception as e:
                error = handle_aws_api_error(e)
                raise error
        return self._cfn_client

    # Cloudformation API's Access point: Helper methods
    def list_stacks(self) -> List[Dict[str, Any]]:
        """List CloudFormation stacks in the AWS account.

        Returns:
            List of active stacks (excludes deleted stacks)
        """
        response = self.cfn_client.list_stacks(
            StackStatusFilter=[
                'CREATE_COMPLETE',
                'UPDATE_COMPLETE',
                'UPDATE_ROLLBACK_COMPLETE',
                'CREATE_IN_PROGRESS',
                'UPDATE_IN_PROGRESS',
                'UPDATE_ROLLBACK_IN_PROGRESS',
                'ROLLBACK_COMPLETE',
                'CREATE_FAILED',
                'UPDATE_FAILED',
                'UPDATE_ROLLBACK_FAILED',
                'ROLLBACK_FAILED',
            ]
        )
        return response.get('StackSummaries', [])

    def describe_stack(self, stack_name: str) -> Dict[str, Any]:
        """Describe a CloudFormation stack.

        Args:
            stack_name: Name of the stack to describe

        Returns:
            Stack description
        """
        response = self.cfn_client.describe_stacks(StackName=stack_name)
        return response.get('Stacks', [{}])[0]

    def list_stack_resources(self, stack_name: str) -> List[Dict[str, Any]]:
        """List resources in a CloudFormation stack.

        Args:
            stack_name: Name of the stack
        Returns:
            List of stack resources
        """
        response = self.cfn_client.list_stack_resources(StackName=stack_name)
        return response.get('StackResourceSummaries', [])

    def get_stack_template(self, stack_name: str) -> Dict[str, Any]:
        """Get the template for a CloudFormation stack.

        Args:
            stack_name: Name of the stack

        Returns:
            Dict containing the stack template
        """
        response = self.cfn_client.get_template(StackName=stack_name)
        return response.get('TemplateBody', {})

    # Resource Scan API methods
    def start_resource_scan(self) -> str:
        """Start a new resource scan and return the scan ID.

        Returns:
            Resource scan ID
        """
        try:
            logger.info('Starting resource scan...')
            response = self.cfn_client.start_resource_scan()
            scan_id: str = response['ResourceScanId']
            self.resource_scan_id = scan_id
            logger.info(f'Resource scan started with ID: {scan_id}')
            return scan_id
        except Exception as e:
            logger.error(f'Error starting resource scan: {str(e)}')
            raise handle_aws_api_error(e)

    def get_resource_scan_status(self, scan_id: Optional[str] = None) -> Dict[str, Any]:
        """Get the status of a resource scan.

        Args:
            scan_id: Resource scan ID (uses stored ID if not provided)

        Returns:
            Resource scan status information
        """
        if scan_id is not None:
            effective_scan_id = scan_id
        elif self.resource_scan_id is not None:
            effective_scan_id = self.resource_scan_id
        else:
            raise ClientError('No resource scan ID available')

        try:
            response = self.cfn_client.describe_resource_scan(ResourceScanId=effective_scan_id)
            return response
        except Exception as e:
            logger.error(f'Error getting resource scan status: {str(e)}')
            raise handle_aws_api_error(e)

    def list_resource_scan_resources(self, scan_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """List all resources found in the resource scan.

        Args:
            scan_id: Resource scan ID (uses stored ID if not provided)

        Returns:
            List of all resources found in the scan
        """
        if scan_id is not None:
            effective_scan_id = scan_id
        elif self.resource_scan_id is not None:
            effective_scan_id = self.resource_scan_id
        else:
            raise ClientError('No resource scan ID available')

        try:
            logger.info(f'Listing resources from scan {effective_scan_id}')

            # Use paginator to handle large result sets
            paginator = self.cfn_client.get_paginator('list_resource_scan_resources')
            page_iterator = paginator.paginate(ResourceScanId=effective_scan_id)

            all_resources = []
            for page in page_iterator:
                resources = page.get('Resources', [])
                all_resources.extend(resources)
                logger.debug(f'Retrieved {len(resources)} resources from page')

            logger.info(f'Total resources found in scan: {len(all_resources)}')
            return all_resources

        except Exception as e:
            logger.error(f'Error listing resource scan resources: {str(e)}')
            raise handle_aws_api_error(e)
