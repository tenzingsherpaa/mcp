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
"""Tests for the sam_init module."""

import os
import pytest
import subprocess
import tempfile
from awslabs.aws_serverless_mcp_server.models import SamInitRequest
from awslabs.aws_serverless_mcp_server.tools.sam.sam_init import handle_sam_init
from unittest.mock import MagicMock, patch


class TestSamInit:
    """Tests for the sam_init function."""

    @pytest.mark.asyncio
    async def test_sam_init_success(self):
        """Test successful SAM initialization."""
        # Create a mock request
        request = SamInitRequest(
            project_name='test-project',
            runtime='nodejs18.x',
            project_directory=os.path.join(tempfile.gettempdir(), 'test-project'),
            dependency_manager='npm',
            architecture='x86_64',
            package_type='zip',
            application_template='hello-world',
            application_insights=None,
            no_application_insights=None,
            base_image=None,
            config_env=None,
            config_file=None,
            debug=None,
            extra_content=None,
            location=None,
            save_params=None,
            tracing=None,
            no_tracing=None,
        )

        # Mock the subprocess.run function
        mock_result = MagicMock()
        mock_result.stdout = b'Successfully initialized SAM project'
        mock_result.stderr = b''

        with patch(
            'awslabs.aws_serverless_mcp_server.tools.sam.sam_init.run_command',
            return_value=(mock_result.stdout, mock_result.stderr),
        ) as mock_run:
            # Call the function
            result = await handle_sam_init(request)
            print(result)
            # Verify the result
            assert result['success'] is True
            assert 'Successfully initialized SAM project' in result['message']
            assert result['output'] == 'Successfully initialized SAM project'

            # Verify subprocess.run was called with the correct arguments
            mock_run.assert_called_once()
            args, kwargs = mock_run.call_args
            cmd = args[0]

            # Check required parameters
            assert 'sam' in cmd
            assert 'init' in cmd
            assert '--name' in cmd
            assert 'test-project' in cmd
            assert '--runtime' in cmd
            assert 'nodejs18.x' in cmd
            assert '--dependency-manager' in cmd
            assert 'npm' in cmd
            assert '--output-dir' in cmd
            assert os.path.join(tempfile.gettempdir(), 'test-project') in cmd
            assert '--no-interactive' in cmd

    @pytest.mark.asyncio
    async def test_sam_init_with_optional_params(self):
        """Test SAM initialization with optional parameters."""
        # Create a mock request with optional parameters
        request = SamInitRequest(
            project_name='test-project',
            runtime='python3.9',
            project_directory=os.path.join(tempfile.gettempdir(), 'test-project'),
            dependency_manager='pip',
            architecture='arm64',
            package_type='zip',
            application_template='hello-world',
            application_insights=True,
            no_application_insights=None,
            base_image=None,
            config_env=None,
            config_file=None,
            debug=True,
            extra_content=None,
            location=None,
            save_params=True,
            tracing=True,
            no_tracing=None,
        )

        # Mock the subprocess.run function
        mock_result = MagicMock()
        mock_result.stdout = b'Successfully initialized SAM project'
        mock_result.stderr = b''

        with patch(
            'awslabs.aws_serverless_mcp_server.tools.sam.sam_init.run_command',
            return_value=(mock_result.stdout, mock_result.stderr),
        ) as mock_run:
            # Call the function
            result = await handle_sam_init(request)

            # Verify the result
            assert result['success'] is True

            # Verify subprocess.run was called with the correct arguments
            mock_run.assert_called_once()
            args, kwargs = mock_run.call_args
            cmd = args[0]

            # Check optional parameters
            assert '--architecture' in cmd
            assert 'arm64' in cmd
            assert '--app-template' in cmd
            assert 'hello-world' in cmd
            assert '--application-insights' in cmd
            assert '--debug' in cmd
            assert '--save-params' in cmd
            assert '--tracing' in cmd

    @pytest.mark.asyncio
    async def test_sam_init_failure(self):
        """Test SAM initialization failure."""
        # Create a mock request
        request = SamInitRequest(
            project_name='test-project',
            runtime='nodejs18.x',
            project_directory=os.path.join(tempfile.gettempdir(), 'test-project'),
            dependency_manager='npm',
            architecture='x86_64',
            package_type='zip',
            application_template='hello-world',
            application_insights=None,
            no_application_insights=None,
            base_image=None,
            config_env=None,
            config_file=None,
            debug=None,
            extra_content=None,
            location=None,
            save_params=None,
            tracing=None,
            no_tracing=None,
        )

        # Mock the subprocess.run function to raise an exception
        error_message = 'Command failed with exit code 1'
        with patch(
            'awslabs.aws_serverless_mcp_server.tools.sam.sam_init.run_command',
            side_effect=subprocess.CalledProcessError(1, 'sam init', stderr=error_message),
        ):
            # Call the function
            result = await handle_sam_init(request)

            # Verify the result
            assert result['success'] is False
            assert 'Failed to initialize SAM project' in result['message']
            assert error_message in result['message']

    @pytest.mark.asyncio
    async def test_sam_init_general_exception(self):
        """Test SAM initialization with a general exception."""
        # Create a mock request
        request = SamInitRequest(
            project_name='test-project',
            runtime='nodejs18.x',
            project_directory=os.path.join(tempfile.gettempdir(), 'test-project'),
            dependency_manager='npm',
            architecture='x86_64',
            package_type='zip',
            application_template='hello-world',
            application_insights=None,
            no_application_insights=None,
            base_image=None,
            config_env=None,
            config_file=None,
            debug=None,
            extra_content=None,
            location=None,
            save_params=None,
            tracing=None,
            no_tracing=None,
        )

        # Mock the subprocess.run function to raise a general exception
        error_message = 'Some unexpected error'
        with patch(
            'awslabs.aws_serverless_mcp_server.tools.sam.sam_init.run_command',
            side_effect=Exception(error_message),
        ):
            # Call the function
            result = await handle_sam_init(request)

            # Verify the result
            assert result['success'] is False
            assert 'Failed to initialize SAM project' in result['message']
            assert error_message in result['message']
