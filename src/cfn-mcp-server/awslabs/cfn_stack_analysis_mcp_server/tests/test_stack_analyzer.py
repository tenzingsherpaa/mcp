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
"""Tests for the cfn MCP Server."""


import unittest
from unittest.mock import patch, MagicMock
from awslabs.cfn_stack_analysis_mcp_server.stack_analyzer import StackAnalyzer



class TestStackAnalyzer(unittest.TestCase):
    """Tests for the cfn MCP Server."""

    @patch('awslabs.cfn_stack_analysis_mcp_server.stack_analyzer.get_aws_client')
    def setUp(self, mock_get_aws_client):
        """Set up each test."""
        # Mock AWS clients
        self.mock_cfn_client = MagicMock()

        # Configure mock get_aws_client to return our mock clients
        mock_get_aws_client.side_effect = lambda service, region=None: {
            'cloudformation': self.mock_cfn_client
        }[service]

        # Create the stack analyzer instance
        self.stack_analyzer = StackAnalyzer(region='us-east-1')
        
        # Add this line to make aws_client point to cfn_client
        self.stack_analyzer.aws_client = self.mock_cfn_client

    def test_list_stacks(self):
        """Test listing CloudFormation stacks."""
        # Setup mock response
        expected_stacks = [
            {'StackName': 'stack1', 'StackStatus': 'CREATE_COMPLETE'},
            {'StackName': 'stack2', 'StackStatus': 'UPDATE_COMPLETE'}
        ]
        self.mock_cfn_client.list_stacks.return_value = expected_stacks
        
        # Call the method
        result = self.stack_analyzer.list_stacks()
        
        # Verify the result
        self.assertEqual(result, expected_stacks)
        self.mock_cfn_client.list_stacks.assert_called_once()

    def test_describe_stack(self):
        """Test describing a CloudFormation stack."""
        # Setup mock response
        stack_name = 'test-stack'
        expected_description = {
            'StackName': stack_name,
            'StackStatus': 'CREATE_COMPLETE',
            'Parameters': [{'ParameterKey': 'key1', 'ParameterValue': 'value1'}]
        }
        self.mock_cfn_client.describe_stack.return_value = expected_description
        
        # Call the method
        result = self.stack_analyzer.describe_stack(stack_name)
        
        # Verify the result
        self.assertEqual(result, expected_description)
        self.mock_cfn_client.describe_stack.assert_called_once_with(stack_name)

    def test_list_stack_resources(self):
        """Test listing resources in a CloudFormation stack."""
        # Setup mock response
        stack_name = 'test-stack'
        expected_resources = [
            {'LogicalResourceId': 'resource1', 'PhysicalResourceId': 'id1', 'ResourceType': 'AWS::S3::Bucket'},
            {'LogicalResourceId': 'resource2', 'PhysicalResourceId': 'id2', 'ResourceType': 'AWS::Lambda::Function'}
        ]
        self.mock_cfn_client.list_stack_resources.return_value = expected_resources
        
        # Call the method
        result = self.stack_analyzer.list_stack_resources(stack_name)
        
        # Verify the result
        self.assertEqual(result, expected_resources)
        self.mock_cfn_client.list_stack_resources.assert_called_once_with(stack_name)

    def test_get_stack_template(self):
        """Test getting a CloudFormation stack template."""
        # Setup mock response
        stack_name = 'test-stack'
        expected_template = {
            'TemplateBody': '{"Resources": {"MyBucket": {"Type": "AWS::S3::Bucket"}}}'
        }
        self.mock_cfn_client.get_template.return_value = expected_template
        
        # Call the method
        result = self.stack_analyzer.get_stack_template(stack_name)
        
        # Verify the result
        self.assertEqual(result, expected_template)
        self.mock_cfn_client.get_template.assert_called_once_with(stack_name)

    def test_analyze_stack(self):
        """Test analyzing a CloudFormation stack."""
        # Since the method returns None, we're just testing that it doesn't raise an exception
        stack_name = 'test-stack'
        result = self.stack_analyzer.analyze_stack(stack_name)
        
        self.assertIsNone(result)

    def test_analyze_unmanaged_resources(self):
        """Test analyzing unmanaged resources."""
        # Since the method returns None, we're just testing that it doesn't raise an exception
        result = self.stack_analyzer.analyze_unmanaged_resources()
        
        self.assertIsNone(result)