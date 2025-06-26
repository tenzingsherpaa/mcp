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

"""Tests for the StackAnalyzer class."""

import pytest
from awslabs.cfn_mcp_server.stack_analysis.stack_analyzer import StackAnalyzer
from unittest.mock import MagicMock, patch


class TestStackAnalyzerPytest:
    """Pytest tests for StackAnalyzer."""

    @pytest.fixture
    def mock_cfn_client(self):
        """Create a mock CloudFormation client."""
        return MagicMock()

    @pytest.fixture
    def stack_analyzer(self, mock_cfn_client):
        """Create StackAnalyzer with mocked client."""
        with patch(
            'awslabs.cfn_mcp_server.stack_analysis.cloud_formation_utils.get_aws_client'
        ) as mock_get_client:
            mock_get_client.return_value = mock_cfn_client
            analyzer = StackAnalyzer(region='us-east-1')
            analyzer.cfn_utils._cfn_client = (
                mock_cfn_client  # Manually set since property might be missing
            )
            yield analyzer

    def test_get_best_cfn_practices(self):
        """Test getting CloudFormation best practices."""
        best_practices = StackAnalyzer.get_best_cfn_practices()

        expected_keys = [
            'nested_stacks',
            'cross_stack_references',
            'resource_management',
            'stack_policies',
            'iam_access_control',
            'parameter_constraints',
            'resource_dependencies',
            'resource_cleanup',
            'common_components',
        ]

        for key in expected_keys:
            assert key in best_practices
            assert isinstance(best_practices[key], str)

    def test_analyze_stack_success_pytest(self, stack_analyzer, mock_cfn_client):
        """Test analyzing a stack successfully."""
        stack_name = 'test-stack'

        stack_details = {
            'StackName': stack_name,
            'StackStatus': 'CREATE_COMPLETE',
            'CreationTime': '2023-01-01T00:00:00Z',
        }
        mock_cfn_client.describe_stacks.return_value = {'Stacks': [stack_details]}

        stack_resources = [
            {
                'LogicalResourceId': 'MyBucket',
                'PhysicalResourceId': 'my-bucket',
                'ResourceType': 'AWS::S3::Bucket',
            },
        ]
        mock_cfn_client.list_stack_resources.return_value = {
            'StackResourceSummaries': stack_resources
        }

        result = stack_analyzer.analyze_stack(stack_name)

        assert result['stack_info'] == stack_details
        assert result['resources'] == stack_resources
        assert result['resource_count'] == 1
        assert result['stack_status'] == 'CREATE_COMPLETE'

    def test_analyze_stack_error_pytest(self, stack_analyzer, mock_cfn_client):
        """Test analyzing a stack with error."""
        stack_name = 'test-stack'
        error_msg = 'Stack does not exist'
        mock_cfn_client.describe_stacks.side_effect = Exception(error_msg)

        result = stack_analyzer.analyze_stack(stack_name)

        assert 'error' in result
        assert error_msg in result['error']

    def test_analyze_unmanaged_resources_pytest(self, stack_analyzer):
        """Test analyzing unmanaged resources."""
        result = stack_analyzer.analyze_unmanaged_resources()

        assert 'message' in result
        assert result['message'] == 'Unmanaged resource analysis not implemented yet'


# For pytest compatibility
@pytest.mark.asyncio
class TestStackAnalyzerAsync:
    """Async tests for the StackAnalyzer class."""

    @pytest.fixture
    def stack_analyzer(self):
        """Create a StackAnalyzer instance for testing."""
        with patch('awslabs.cfn_mcp_server.aws_client.get_aws_client') as mock_get_aws_client:
            mock_cfn_client = MagicMock()
            mock_get_aws_client.return_value = mock_cfn_client
            analyzer = StackAnalyzer(region='us-east-1')
            analyzer.cfn_client = mock_cfn_client
            yield analyzer
