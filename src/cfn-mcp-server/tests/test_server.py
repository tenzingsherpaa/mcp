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
"""Tests for the cfn MCP Server."""

import pytest
from awslabs.cfn_mcp_server.context import Context
from awslabs.cfn_mcp_server.errors import ClientError
from awslabs.cfn_mcp_server.server import (
    analyze_stack,
    create_resource,
    create_template,
    delete_resource,
    get_resource,
    get_resource_request_status,
    get_resource_schema_information,
    list_resources,
    update_resource,
)
from unittest.mock import AsyncMock, MagicMock, patch


@pytest.mark.asyncio
class TestReadonly:
    """Test tools for server in readonly."""

    Context.initialize(True)

    async def test_update_resource(self):
        """Testing testing update."""
        with pytest.raises(ClientError):
            await update_resource(
                resource_type='AWS::CodeStarConnections::Connection',
                identifier='identifier',
                patch_document=[],
            )

    async def test_create_resource(self):
        """Testing testing create."""
        with pytest.raises(ClientError):
            await create_resource(
                resource_type='AWS::CodeStarConnections::Connection', properties={}
            )

    async def test_delete_resource(self):
        """Testing testing delete."""
        with pytest.raises(ClientError):
            await delete_resource(
                resource_type='AWS::CodeStarConnections::Connection', identifier='identifier'
            )


@pytest.mark.asyncio
class TestTools:
    """Test tools for server."""

    Context.initialize(False)

    async def test_get_resource_schema_no_type(self):
        """Testing no type provided."""
        with pytest.raises(ClientError):
            await get_resource_schema_information(resource_type=None)

    @patch('awslabs.cfn_mcp_server.server.schema_manager')
    async def test_get_resource_schema(self, mock_schema_manager):
        """Testing getting the schema."""
        # Setup the mock
        mock_instance = MagicMock()
        mock_instance.get_schema = AsyncMock(return_value={'properties': []})
        mock_schema_manager.return_value = mock_instance

        # Call the function
        result = await get_resource_schema_information(
            resource_type='AWS::CodeStarConnections::Connection'
        )

        # Check the result
        assert result == {
            'properties': [],
        }

    async def test_list_resources_no_type(self):
        """Testing no type provided."""
        with pytest.raises(ClientError):
            await list_resources(resource_type=None)

    @patch('awslabs.cfn_mcp_server.server.get_aws_client')
    async def test_list_resources(self, mock_get_aws_client):
        """Testing testing simple list."""
        # Setup the mock
        page = {'ResourceDescriptions': [{'Identifier': 'Identifier'}]}

        # Create a proper mock iterator
        mock_paginator = MagicMock()
        mock_paginator.paginate = MagicMock(
            return_value=[page]
        )  # This returns an iterable with the page

        # Set up the client chain
        mock_client = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_get_aws_client.return_value = mock_client

        # Call the function
        result = await list_resources(resource_type='AWS::CodeStarConnections::Connection')

        # Check the result
        assert result == ['Identifier']

    async def test_get_resource_no_type(self):
        """Testing no type provided."""
        with pytest.raises(ClientError):
            await get_resource(resource_type=None, identifier='identifier')

    async def test_get_resource_no_identifier(self):
        """Testing no identifier provided."""
        with pytest.raises(ClientError):
            await get_resource(
                resource_type='AWS::CodeStarConnections::Connection', identifier=None
            )

    @patch('awslabs.cfn_mcp_server.server.get_aws_client')
    async def test_get_resource(self, mock_get_aws_client):
        """Testing simple get."""
        # Setup the mock
        mock_get_resource_return_value = MagicMock(
            return_value={
                'ResourceDescription': {'Identifier': 'Identifier', 'Properties': 'Properties'}
            }
        )
        mock_cloudcontrol_client = MagicMock(get_resource=mock_get_resource_return_value)
        mock_get_aws_client.return_value = mock_cloudcontrol_client

        # Call the function
        result = await get_resource(
            resource_type='AWS::CodeStarConnections::Connection', identifier='identifier'
        )

        # Check the result
        assert result == {
            'properties': 'Properties',
            'identifier': 'Identifier',
        }

    async def test_update_resource_no_type(self):
        """Testing testing update with no type."""
        with pytest.raises(ClientError):
            await update_resource(resource_type=None, identifier='identifier', patch_document=[])

    async def test_update_resource_no_identifier(self):
        """Testing no identifier provided."""
        with pytest.raises(ClientError):
            await update_resource(
                resource_type='AWS::CodeStarConnections::Connection',
                identifier=None,
                patch_document=[],
            )

    async def test_update_resource_no_patch(self):
        """Testing no patch provided."""
        with pytest.raises(ClientError):
            await update_resource(
                identifier='identifier',
                resource_type='AWS::CodeStarConnections::Connection',
                patch_document=None,
            )

    @patch('awslabs.cfn_mcp_server.server.get_aws_client')
    async def test_update_resource(self, mock_get_aws_client):
        """Testing simple update."""
        # Setup the mock
        response = {
            'ProgressEvent': {
                'OperationStatus': 'SUCCESS',
                'TypeName': 'AWS::CodeStarConnections::Connection',
                'RequestToken': 'RequestToken',
            }
        }
        mock_update_resource_return_value = MagicMock(return_value=response)
        mock_cloudcontrol_client = MagicMock(update_resource=mock_update_resource_return_value)
        mock_get_aws_client.return_value = mock_cloudcontrol_client

        # Call the function
        result = await update_resource(
            resource_type='AWS::CodeStarConnections::Connection',
            identifier='identifier',
            patch_document=[{'op': 'remove', 'path': '/item'}],
        )

        # Check the result
        assert result == {
            'status': 'SUCCESS',
            'resource_type': 'AWS::CodeStarConnections::Connection',
            'is_complete': True,
            'request_token': 'RequestToken',
        }

    async def test_create_resource_no_type(self):
        """Testing no type provided."""
        with pytest.raises(ClientError):
            await create_resource(resource_type=None, properties={})

    async def test_create_resource_no_properties(self):
        """Testing no properties provided."""
        with pytest.raises(ClientError):
            await create_resource(
                resource_type='AWS::CodeStarConnections::Connection', properties=None
            )

    @patch('awslabs.cfn_mcp_server.server.get_aws_client')
    async def test_create_resource(self, mock_get_aws_client):
        """Testing simple create."""
        # Setup the mock
        response = {
            'ProgressEvent': {
                'OperationStatus': 'SUCCESS',
                'TypeName': 'AWS::CodeStarConnections::Connection',
                'RequestToken': 'RequestToken',
            }
        }
        mock_create_resource_return_value = MagicMock(return_value=response)
        mock_cloudcontrol_client = MagicMock(create_resource=mock_create_resource_return_value)
        mock_get_aws_client.return_value = mock_cloudcontrol_client

        # Call the function
        result = await create_resource(
            resource_type='AWS::CodeStarConnections::Connection',
            properties={'ConnectionName': 'Name'},
        )

        # Check the result
        assert result == {
            'status': 'SUCCESS',
            'resource_type': 'AWS::CodeStarConnections::Connection',
            'is_complete': True,
            'request_token': 'RequestToken',
        }

    async def test_delete_resource_no_type(self):
        """Testing simple delete."""
        with pytest.raises(ClientError):
            await delete_resource(resource_type=None, identifier='Identifier')

    async def test_delete_resource_no_identifier(self):
        """Testing no identifier on delete."""
        with pytest.raises(ClientError):
            await delete_resource(
                resource_type='AWS::CodeStarConnections::Connection', identifier=None
            )

    @patch('awslabs.cfn_mcp_server.server.get_aws_client')
    async def test_delete_resource(self, mock_get_aws_client):
        """Testing simple delete."""
        # Setup the mock
        response = {
            'ProgressEvent': {
                'OperationStatus': 'SUCCESS',
                'TypeName': 'AWS::CodeStarConnections::Connection',
                'RequestToken': 'RequestToken',
            }
        }
        mock_delete_resource_return_value = MagicMock(return_value=response)
        mock_cloudcontrol_client = MagicMock(delete_resource=mock_delete_resource_return_value)
        mock_get_aws_client.return_value = mock_cloudcontrol_client

        # Call the function
        result = await delete_resource(
            resource_type='AWS::CodeStarConnections::Connection', identifier='Identifier'
        )

        # Check the result
        assert result == {
            'status': 'SUCCESS',
            'resource_type': 'AWS::CodeStarConnections::Connection',
            'is_complete': True,
            'request_token': 'RequestToken',
        }

    async def test_get_request_type_no_token(self):
        """Testing no token."""
        with pytest.raises(ClientError):
            await get_resource_request_status(request_token='Token')

    @patch('awslabs.cfn_mcp_server.server.create_template_impl')
    async def test_create_template(self, mock_create_template_impl):
        """Testing create_template function."""
        # Setup the mock
        mock_create_template_impl.return_value = {
            'status': 'INITIATED',
            'template_id': 'test-template-id',
            'message': 'Template generation initiated.',
        }

        # Call the function
        result = await create_template(
            template_name='test-template',
            resources=[{'ResourceType': 'AWS::S3::Bucket', 'ResourceIdentifier': 'test-bucket'}],
            output_format='YAML',
            deletion_policy='RETAIN',
            update_replace_policy='RETAIN',
        )

        # Check the result
        assert result == {
            'status': 'INITIATED',
            'template_id': 'test-template-id',
            'message': 'Template generation initiated.',
        }

        # Verify the implementation was called with the correct parameters
        mock_create_template_impl.assert_called_once()

    """Test cases for the CloudFormation Stack Analysis MCP Server."""

    @patch('awslabs.cfn_mcp_server.server.StackAnalyzer')
    async def test_analyze_stack_success(self, mock_stack_analyzer_class):
        """Test analyze_stack with successful stack analysis."""
        # Mock the StackAnalyzer instance
        mock_analyzer = MagicMock()
        mock_stack_analyzer_class.return_value = mock_analyzer

        # Mock the get_best_cfn_practices method
        mock_stack_analyzer_class.get_best_cfn_practices.return_value = {
            'resource_management': 'Manage all stack resources through CloudFormation.',
            'stack_policies': 'Use stack policies to prevent unintentional updates.',
        }

        # Mock the analyze_stack method with the new structure
        mock_analyzer.analyze_stack.return_value = {
            'stack_info': {
                'StackName': 'test-stack',
                'StackStatus': 'CREATE_COMPLETE',
                'CreationTime': '2023-01-01T00:00:00Z',
                'LastUpdatedTime': '2023-01-02T00:00:00Z',
            },
            'stack_status': 'CREATE_COMPLETE',
            'creation_time': '2023-01-01T00:00:00Z',
            'last_updated_time': '2023-01-02T00:00:00Z',
            'outputs': [{'OutputKey': 'BucketName', 'OutputValue': 'test-bucket'}],
            'parameters': [{'ParameterKey': 'Environment', 'ParameterValue': 'test'}],
            'resources': {
                'stack_name': 'test-stack',
                'resource_scan_id': 'test-scan-id',
                'matched_resources': [
                    {
                        'logical_resource_id': 'MyBucket',
                        'physical_resource_id': 'test-bucket',
                        'resource_type': 'AWS::S3::Bucket',
                        'resource_status': 'CREATE_COMPLETE',
                        'matched': True,
                        'resource_identifier': {'BucketName': 'test-bucket'},
                    }
                ],
                'unmatched_resources': [],
            },
            'related_resources': [
                {
                    'ResourceType': 'AWS::IAM::Role',
                    'ResourceIdentifier': {'RoleName': 'test-role'},
                    'ManagedByStack': False,
                }
            ],
            'account_summary': {
                'overall_summary': {
                    'total_resources': 100,
                    'managed_resources': 80,
                    'unmanaged_resources': 20,
                    'managed_percentage': 80.0,
                    'unmanaged_percentage': 20.0,
                }
            },
        }

        # Call the function
        result = await analyze_stack(stack_name='test-stack', region='us-east-1')

        # Verify the StackAnalyzer was created with the correct region
        mock_stack_analyzer_class.assert_called_once_with('us-east-1')

        # Verify analyze_stack was called with the correct stack name
        mock_analyzer.analyze_stack.assert_called_once_with('test-stack')

        # Verify the result structure matches the new implementation
        assert result['stack_info']['StackName'] == 'test-stack'
        assert result['stack_status'] == 'CREATE_COMPLETE'
        assert result['creation_time'] == '2023-01-01T00:00:00Z'
        assert result['last_updated_time'] == '2023-01-02T00:00:00Z'
        assert result['outputs'] == [{'OutputKey': 'BucketName', 'OutputValue': 'test-bucket'}]
        assert result['parameters'] == [{'ParameterKey': 'Environment', 'ParameterValue': 'test'}]

        # Verify stack name and resource scan ID
        assert result['stack_name'] == 'test-stack'
        assert result['resource_scan_id'] == 'test-scan-id'

        # Verify matched and unmatched resources
        assert len(result['matched_resources']) == 1
        assert result['matched_resources'][0]['logical_resource_id'] == 'MyBucket'
        assert len(result['unmatched_resources']) == 0

        # Verify related resources
        assert len(result['related_resources']) == 1
        assert result['related_resources'][0]['ResourceType'] == 'AWS::IAM::Role'

        # Verify related resources summary
        assert result['related_resources_summary']['total_count'] == 1
        assert 'AWS::IAM::Role' in result['related_resources_summary']['resource_types']

        # Verify account summary
        assert result['account_summary']['overall_summary']['total_resources'] == 100
        assert result['account_summary']['overall_summary']['managed_percentage'] == 80.0

        # Verify best practices
        assert 'resource_management' in result['best_practices']
        assert 'stack_policies' in result['best_practices']

        # Verify analysis highlights
        assert result['analysis_highlights']['stack_resources']['total_in_stack'] == 1
        assert result['analysis_highlights']['stack_resources']['matched_in_scan'] == 1
        assert result['analysis_highlights']['related_resources']['total_found'] == 1
        assert result['analysis_highlights']['account_overview']['total_resources'] == 100
