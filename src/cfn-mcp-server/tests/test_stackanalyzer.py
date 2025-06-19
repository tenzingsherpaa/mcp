# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance
# with the License. A copy of the License is located at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# or in the 'license' file accompanying this file. This file is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES
# OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions
# and limitations under the License.

"""Tests for the StackAnalyzer class."""

import unittest
from unittest.mock import patch, MagicMock
import pytest
from awslabs.cfn_mcp_server.stack_analysis.stack_analyzer import StackAnalyzer
from awslabs.cfn_mcp_server.errors import ClientError


class TestStackAnalyzer(unittest.TestCase):
    """Tests for the StackAnalyzer class."""

    @patch('awslabs.cfn_mcp_server.stack_analysis.stack_analyzer.get_aws_client')
    def setUp(self, mock_get_aws_client):
        """Set up each test."""
        # Create the mock client
        self.mock_cfn_client = MagicMock()
        
        # Configure the mock to return our mock client
        mock_get_aws_client.return_value = self.mock_cfn_client
        
        # Create the stack analyzer instance
        self.stack_analyzer = StackAnalyzer(region='us-east-1')

    def test_get_best_cfn_practices(self):
        """Test getting CloudFormation best practices."""
        best_practices = StackAnalyzer.get_best_cfn_practices()
        
        # Verify the result contains expected keys
        self.assertIn("nested_stacks", best_practices)
        self.assertIn("cross_stack_references", best_practices)
        self.assertIn("resource_management", best_practices)
        self.assertIn("stack_policies", best_practices)
        self.assertIn("iam_access_control", best_practices)
        self.assertIn("parameter_constraints", best_practices)
        self.assertIn("resource_dependencies", best_practices)
        self.assertIn("resource_cleanup", best_practices)
        self.assertIn("common_components", best_practices)

    def test_list_stacks(self):
        """Test listing CloudFormation stacks."""
        # Setup mock response
        expected_stacks = [
            {'StackName': 'stack1', 'StackStatus': 'CREATE_COMPLETE'},
            {'StackName': 'stack2', 'StackStatus': 'UPDATE_COMPLETE'}
        ]
        
        # Update this to match the actual implementation's expected structure
        self.mock_cfn_client.list_stacks.return_value = {
            'StackSummaries': expected_stacks
        }
        
        # Call the method
        result = self.stack_analyzer.list_stacks()
        
        # Update assertion to match what the implementation actually returns
        # If the implementation returns the 'StackSummaries' directly:
        self.assertEqual(result, expected_stacks)
        # Or if it returns the whole response:
        # self.assertEqual(result, {'StackSummaries': expected_stacks})

    def test_describe_stack(self):
        """Test describing a CloudFormation stack."""
        # Setup mock response
        stack_name = 'test-stack'
        expected_description = {
            'StackName': stack_name,
            'StackStatus': 'CREATE_COMPLETE',
            'Parameters': [{'ParameterKey': 'key1', 'ParameterValue': 'value1'}]
        }
        self.mock_cfn_client.describe_stacks.return_value = {
            'Stacks': [expected_description]
        }
        
        # Call the method
        result = self.stack_analyzer.describe_stack(stack_name)
        
        # Verify the result
        self.assertEqual(result, expected_description)
        self.mock_cfn_client.describe_stacks.assert_called_once_with(StackName=stack_name)

    def test_list_stack_resources(self):
        """Test listing resources in a CloudFormation stack."""
        # Setup mock response
        stack_name = 'test-stack'
        expected_resources = [
            {'LogicalResourceId': 'resource1', 'PhysicalResourceId': 'id1', 'ResourceType': 'AWS::S3::Bucket'},
            {'LogicalResourceId': 'resource2', 'PhysicalResourceId': 'id2', 'ResourceType': 'AWS::Lambda::Function'}
        ]
        self.mock_cfn_client.list_stack_resources.return_value = {
            'StackResourceSummaries': expected_resources
        }
        
        # Call the method
        result = self.stack_analyzer.list_stack_resources(stack_name)
        
        # Verify the result
        self.assertEqual(result, expected_resources)
        self.mock_cfn_client.list_stack_resources.assert_called_once_with(StackName=stack_name)

    def test_get_stack_template(self):
        """Test getting a CloudFormation stack template."""
        # Setup mock response
        stack_name = 'test-stack'
        expected_template_body = '{"Resources": {"MyBucket": {"Type": "AWS::S3::Bucket"}}}'
        self.mock_cfn_client.get_template.return_value = {
            'TemplateBody': expected_template_body
        }
        
        # Call the method
        result = self.stack_analyzer.get_stack_template(stack_name)
        
        # Verify the result
        self.assertEqual(result, expected_template_body)
        self.mock_cfn_client.get_template.assert_called_once_with(StackName=stack_name)

    def test_analyze_stack(self):
        """Test analyzing a CloudFormation stack."""
        # Setup mock responses
        stack_name = 'test-stack'

        # Mock describe_stacks
        stack_details = {
            'StackName': stack_name,
            'StackStatus': 'CREATE_COMPLETE',
            'CreationTime': '2023-01-01T00:00:00Z',
            'LastUpdatedTime': '2023-01-02T00:00:00Z',
            'Outputs': [{'OutputKey': 'BucketName', 'OutputValue': 'my-bucket'}],
            'Parameters': [{'ParameterKey': 'key1', 'ParameterValue': 'value1'}],
            'Tags': [{'Key': 'Environment', 'Value': 'Production'}]
        }
        self.mock_cfn_client.describe_stacks.return_value = {
            'Stacks': [stack_details]
        }

        # Mock list_stack_resources
        stack_resources = [
            {'LogicalResourceId': 'MyBucket', 'PhysicalResourceId': 'my-bucket', 'ResourceType': 'AWS::S3::Bucket'},
            {'LogicalResourceId': 'MyFunction', 'PhysicalResourceId': 'my-function', 'ResourceType': 'AWS::Lambda::Function'}
        ]
        self.mock_cfn_client.list_stack_resources.return_value = {
            'StackResourceSummaries': stack_resources
        }

        # Call the method
        result = self.stack_analyzer.analyze_stack(stack_name)

        # Update assertion to match the actual implementation
        self.assertEqual(result['stack_info'], stack_details)
        self.assertEqual(result['resources'], stack_resources)
        self.assertEqual(result['resource_count'], 2)
        self.assertEqual(result['stack_status'], 'CREATE_COMPLETE')

    def test_analyze_stack_error(self):
        """Test analyzing a CloudFormation stack with an error."""
        # Setup mock to raise an exception
        stack_name = 'test-stack'
        
        # Use your custom ClientError class
        error_msg = 'Stack with id test-stack does not exist'
        self.mock_cfn_client.describe_stacks.side_effect = ClientError(error_msg)
        
        # Call the method
        result = self.stack_analyzer.analyze_stack(stack_name)
        
        # Verify the result contains an error
        self.assertIn('error', result)
        # Check that the error message matches
        self.assertIn(error_msg, result['error'])
        
        
        # Call the method
        result = self.stack_analyzer.analyze_stack(stack_name)
        
        # Verify the result contains an error
        self.assertIn('error', result)
        # The exact error message might vary, so check for a substring
        self.assertIn('Stack with id test-stack does not exist', result['error'])

    def test_analyze_unmanaged_resources(self):
        """Test analyzing unmanaged resources."""
        # Call the method
        result = self.stack_analyzer.analyze_unmanaged_resources()
        
        # Verify the result
        self.assertIn('message', result)
        self.assertEqual(result['message'], 'Unmanaged resource analysis not implemented yet')


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
