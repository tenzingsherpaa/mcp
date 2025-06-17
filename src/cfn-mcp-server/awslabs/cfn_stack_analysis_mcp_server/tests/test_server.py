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

"""Tests for the CloudFormation Stack Analysis MCP Server."""

import unittest
from unittest.mock import patch, MagicMock
import json
from awslabs.cfn_stack_analysis_mcp_server.server import analyze_stack


class TestServer(unittest.TestCase):
    """Test cases for the CloudFormation Stack Analysis MCP Server."""

    @patch('awslabs.cfn_stack_analysis_mcp_server.server.StackAnalyzer')
    async def test_analyze_stack(self, mock_stack_analyzer_class):
        """Test the analyze_stack function."""
        # Mock the StackAnalyzer instance
        mock_analyzer = MagicMock()
        mock_stack_analyzer_class.return_value = mock_analyzer
        
        # Mock the get_stack_resources method
        mock_analyzer.get_stack_resources.return_value = [
            {
                'LogicalResourceId': 'MyBucket',
                'PhysicalResourceId': 'my-bucket',
                'ResourceType': 'AWS::S3::Bucket',
                'ResourceStatus': 'CREATE_COMPLETE'
            }
        ]
        
        # Mock the get_stack_outputs method
        mock_analyzer.get_stack_outputs.return_value = [
            {
                'OutputKey': 'BucketName',
                'OutputValue': 'my-bucket',
                'Description': 'Name of the S3 bucket'
            }
        ]
        
        # Call the function
        result = await analyze_stack(stack_name='my-stack', region='us-east-1')
        
        # Verify the results
        self.assertEqual(result['stack_name'], 'my-stack')
        self.assertEqual(len(result['resources']), 1)
        self.assertEqual(len(result['outputs']), 1)
        self.assertEqual(result['resource_count'], 1)
        self.assertEqual(result['resource_types'], ['AWS::S3::Bucket'])
        
        # Verify that the StackAnalyzer was created correctly
        mock_stack_analyzer_class.assert_called_once_with('us-east-1')
        
        # Verify that the methods were called correctly
        mock_analyzer.get_stack_resources.assert_called_once_with('my-stack')
        mock_analyzer.get_stack_outputs.assert_called_once_with('my-stack')
    