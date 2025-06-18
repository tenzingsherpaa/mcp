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
import random
import string
from awslabs.cfn_mcp_server.schema_manager import schema_manager
from unittest.mock import MagicMock, patch


@pytest.mark.asyncio
class TestSchemaManager:
    """Tests on the schema_manager module."""

    @patch('awslabs.cfn_mcp_server.schema_manager.get_aws_client')
    async def test_download_schema(self, mock_get_aws_client):
        """Testing getting a schema from download."""
        # Setup the mock
        type_final = ''.join(
            random.choice(string.ascii_uppercase + string.digits) for _ in range(5)
        )
        type_name = f'AWS::Fake::{type_final}'

        response = {
            'Schema': '{"properties": {}, "readOnlyProperties": [], "primaryIdentifier": []}'
        }
        mock_cfn_client = MagicMock(describe_type=MagicMock(return_value=response))
        mock_get_aws_client.return_value = mock_cfn_client

        sm = schema_manager()

        result = await sm.get_schema(type_name)
        assert result['properties'] == {}

    @patch('awslabs.cfn_mcp_server.schema_manager.get_aws_client')
    async def test_load_schema(self, mock_get_aws_client):
        """Testing testing a schema that was already in the registry."""
        # Setup the mock
        type_final = ''.join(
            random.choice(string.ascii_uppercase + string.digits) for _ in range(5)
        )
        type_name = f'AWS::Fake::{type_final}'

        response = {
            'Schema': '{"properties": {}, "readOnlyProperties": [], "primaryIdentifier": []}'
        }
        mock_cfn_client = MagicMock(describe_type=MagicMock(return_value=response))
        mock_get_aws_client.return_value = mock_cfn_client

        sm = schema_manager()

        result1 = await sm.get_schema(type_name)
        result2 = await sm.get_schema(type_name)
        assert result1 == result2
