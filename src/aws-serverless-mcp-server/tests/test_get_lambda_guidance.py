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
"""Tests for the get_lambda_guidance module."""

import json
import pytest
from awslabs.aws_serverless_mcp_server.models import GetLambdaGuidanceRequest
from awslabs.aws_serverless_mcp_server.tools.guidance.get_lambda_guidance import (
    get_lambda_guidance,
)


class TestGetLambdaGuidance:
    """Tests for the get_lambda_guidance function."""

    @pytest.mark.asyncio
    async def test_get_lambda_guidance_with_examples(self):
        """Test getting Lambda guidance with examples included."""
        # Create a mock request
        request = GetLambdaGuidanceRequest(use_case='web-app', include_examples=True)

        # Call the function
        result = await get_lambda_guidance(request)

        # Verify the result structure
        assert 'title' in result
        assert 'overview' in result
        assert 'whenToUse' in result
        assert 'whenNotToUse' in result
        assert 'pros' in result
        assert 'cons' in result
        assert 'decisionCriteria' in result

        # Parse JSON strings
        when_to_use = json.loads(result['whenToUse'])
        assert isinstance(when_to_use, list)
        assert len(when_to_use) > 0

        # Check that examples are included in scenarios
        for scenario in when_to_use:
            assert 'scenario' in scenario
            assert 'description' in scenario
            if 'examples' in scenario:
                assert isinstance(json.loads(scenario['examples']), list)

    @pytest.mark.asyncio
    async def test_get_lambda_guidance_without_examples(self):
        """Test getting Lambda guidance without examples."""
        # Create a mock request without examples
        request = GetLambdaGuidanceRequest(use_case='data-processing', include_examples=False)

        # Call the function
        result = await get_lambda_guidance(request)

        # Verify the result structure
        assert 'title' in result
        assert 'overview' in result
        assert 'whenToUse' in result
        assert 'whenNotToUse' in result
        assert 'pros' in result
        assert 'cons' in result
        assert 'decisionCriteria' in result

        # Parse JSON string
        when_to_use = json.loads(result['whenToUse'])

        # Check that examples are not included in scenarios when not requested
        for scenario in when_to_use:
            assert 'scenario' in scenario
            assert 'description' in scenario
            # Should not have examples when include_examples=False
            assert 'examples' not in scenario

    @pytest.mark.asyncio
    async def test_get_lambda_guidance_default_examples(self):
        """Test getting Lambda guidance with default examples setting."""
        # Create a mock request with default include_examples (should be True)
        request = GetLambdaGuidanceRequest(use_case='api', include_examples=True)

        # Call the function
        result = await get_lambda_guidance(request)

        # Verify the result structure
        assert 'title' in result
        assert 'overview' in result
        assert 'whenToUse' in result
        assert 'whenNotToUse' in result
        assert 'pros' in result
        assert 'cons' in result
        assert 'decisionCriteria' in result

        # Check that use case specific guidance is included
        assert 'useCaseSpecificGuidance' in result
        use_case_guidance = json.loads(result['useCaseSpecificGuidance'])
        assert 'title' in use_case_guidance
        assert 'suitability' in use_case_guidance
        assert 'description' in use_case_guidance

    @pytest.mark.asyncio
    async def test_get_lambda_guidance_various_use_cases(self):
        """Test Lambda guidance for various use cases."""
        use_cases = [
            'api',
            'data-processing',
            'real-time',
            'scheduled-tasks',
            'web-app',
            'mobile-backend',
            'iot',
        ]

        for use_case in use_cases:
            request = GetLambdaGuidanceRequest(use_case=use_case, include_examples=True)

            # Call the function
            result = await get_lambda_guidance(request)

            # Verify the result structure
            assert 'title' in result
            assert 'overview' in result
            assert 'whenToUse' in result
            assert 'whenNotToUse' in result
            assert 'pros' in result
            assert 'cons' in result
            assert 'decisionCriteria' in result

            # Should have use case specific guidance for known use cases
            assert 'useCaseSpecificGuidance' in result
            use_case_guidance = json.loads(result['useCaseSpecificGuidance'])
            assert 'title' in use_case_guidance
            assert 'suitability' in use_case_guidance

    @pytest.mark.asyncio
    async def test_get_lambda_guidance_content_structure(self):
        """Test that Lambda guidance contains expected content structure."""
        request = GetLambdaGuidanceRequest(use_case='api', include_examples=True)

        # Call the function
        result = await get_lambda_guidance(request)

        # Verify the result structure
        assert 'title' in result
        assert 'overview' in result

        # Check required fields
        required_fields = ['whenToUse', 'whenNotToUse', 'pros', 'cons', 'decisionCriteria']

        for field in required_fields:
            assert field in result
            parsed_field = json.loads(result[field])
            assert isinstance(parsed_field, list)
            assert len(parsed_field) > 0

        # Check that lists contain meaningful content
        when_to_use = json.loads(result['whenToUse'])
        for scenario in when_to_use:
            assert isinstance(scenario, dict)
            assert 'scenario' in scenario
            assert 'description' in scenario
            assert len(scenario['description']) > 10

        decision_criteria = json.loads(result['decisionCriteria'])
        for criterion in decision_criteria:
            assert isinstance(criterion, dict)
            assert 'criterion' in criterion
            assert 'description' in criterion

    @pytest.mark.asyncio
    async def test_get_lambda_guidance_empty_use_case(self):
        """Test Lambda guidance with empty use case."""
        request = GetLambdaGuidanceRequest(use_case='', include_examples=False)

        # Call the function
        result = await get_lambda_guidance(request)

        # Should still provide general guidance
        assert 'title' in result
        assert 'overview' in result
        assert 'whenToUse' in result
        assert 'whenNotToUse' in result
        assert 'pros' in result
        assert 'cons' in result
        assert 'decisionCriteria' in result

        # Should not have use case specific guidance for empty use case
        assert 'useCaseSpecificGuidance' not in result

    @pytest.mark.asyncio
    async def test_get_lambda_guidance_unknown_use_case(self):
        """Test Lambda guidance with unknown use case."""
        request = GetLambdaGuidanceRequest(use_case='unknown-use-case', include_examples=True)

        # Call the function
        result = await get_lambda_guidance(request)

        # Should still provide general guidance
        assert 'title' in result
        assert 'overview' in result
        assert 'whenToUse' in result
        assert 'whenNotToUse' in result
        assert 'pros' in result
        assert 'cons' in result
        assert 'decisionCriteria' in result

        # Should not have use case specific guidance for unknown use case
        assert 'useCaseSpecificGuidance' not in result
