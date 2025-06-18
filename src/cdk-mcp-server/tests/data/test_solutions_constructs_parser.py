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

import pytest
from awslabs.cdk_mcp_server.data.solutions_constructs_parser import (
    ADOC_TITLE_AND_PARAGRAPH_PATTERN,
    MD_TITLE_PATTERN,
    extract_code_example,
    extract_default_settings,
    extract_description,
    extract_properties,
    extract_props,
    extract_props_markdown,
    extract_services_from_pattern_name,
    extract_use_cases,
    fetch_pattern_list,
    get_all_patterns_info,
    get_pattern_info,
    get_pattern_raw,
    parse_readme_content,
    search_patterns,
)
from unittest.mock import AsyncMock, MagicMock, patch


# Test data
SAMPLE_README = """
# aws-lambda-dynamodb

This pattern creates a Lambda function that is triggered by API Gateway and writes to DynamoDB.

## Description
This pattern creates a Lambda function that is triggered by API Gateway and writes to DynamoDB. It includes all necessary permissions and configurations.

## Pattern Construct Props

| Name | Description |
|------|-------------|
| `lambdaFunctionProps` | Properties for the Lambda function. Defaults to `lambda.FunctionProps()`. |
| `dynamoTableProps` | Properties for the DynamoDB table. Required. |
| `apiGatewayProps` | Properties for the API Gateway. Optional. |

## Pattern Properties

| Name | Description |
|------|-------------|
| `lambdaFunction` | The Lambda function. Access via `pattern.lambdaFunction`. |
| `dynamoTable` | The DynamoDB table. Access via `pattern.dynamoTable`. |
| `apiGateway` | The API Gateway. Access via `pattern.apiGateway`. |

## Default Settings
* Lambda function with Node.js 18 runtime
* DynamoDB table with on-demand capacity
* API Gateway with default settings

## Use Cases
* Building serverless APIs with DynamoDB backend
* Creating data processing pipelines
* Implementing REST APIs with persistent storage

```typescript
import { Construct } from 'constructs';
import { Stack, StackProps } from 'aws-cdk-lib';
import { LambdaToDynamoDB } from '@aws-solutions-constructs/aws-lambda-dynamodb';

export class MyStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    new LambdaToDynamoDB(this, 'LambdaToDynamoDBPattern', {
      lambdaFunctionProps: {
        runtime: lambda.Runtime.NODEJS_18_X,
        handler: 'index.handler',
        code: lambda.Code.fromAsset(`${__dirname}/lambda`)
      },
      dynamoTableProps: {
        partitionKey: { name: 'id', type: dynamodb.AttributeType.STRING }
      }
    });
  }
}
```
"""

# Sample AsciiDoc content for testing
SAMPLE_ADOC = """
//!!NODE_ROOT <section>
//== aws-alb-lambda module

[.topic]
= aws-alb-lambda
:info_doctype: section
:info_title: aws-alb-lambda

= Overview

This AWS Solutions Construct implements an an Application Load Balancer
to an AWS Lambda function

Here is a minimal deployable pattern definition:

====
[role="tablist"]
Typescript::
+
[source,typescript]
----
import { Construct } from 'constructs';
import { Stack, StackProps } from 'aws-cdk-lib';
import { AlbToLambda, AlbToLambdaProps } from '@aws-solutions-constructs/aws-alb-lambda';
import * as acm from 'aws-cdk-lib/aws-certificatemanager';
import * as lambda from 'aws-cdk-lib/aws-lambda';
----
====
"""

# Sample AsciiDoc with multi-paragraph Overview section
SAMPLE_ADOC_WITH_MULTI_PARAGRAPH_OVERVIEW = """
//!!NODE_ROOT <section>
//== aws-apigateway-sqs module

[.topic]
= aws-apigateway-sqs
:info_doctype: section
:info_title: aws-apigateway-sqs

= Overview

This AWS Solutions Construct implements an API Gateway connected to an SQS queue.
It provides a serverless architecture for message processing.

This is a second paragraph that should not be included in the description.
It contains additional details about the implementation.

====
[role="tablist"]
Typescript::
+
[source,typescript]
----
import { Construct } from 'constructs';
----
====
"""

# Sample AsciiDoc with Overview section but no first paragraph match
SAMPLE_ADOC_WITH_OVERVIEW_NO_FIRST_PARA = """
//!!NODE_ROOT <section>
//== aws-lambda-step-function module

[.topic]
= aws-lambda-step-function
:info_doctype: section
:info_title: aws-lambda-step-function

= Overview
This is a single line overview with no paragraph break.
====
[role="tablist"]
Typescript::
+
[source,typescript]
----
import { Construct } from 'constructs';
----
====
"""

# Sample AsciiDoc with no first paragraph match but with title and content
SAMPLE_ADOC_WITH_TITLE_CONTENT = """
//!!NODE_ROOT <section>
//== aws-lambda-sns module

[.topic]
= aws-lambda-sns
:info_doctype: section
:info_title: aws-lambda-sns

= aws-lambda-sns

This AWS Solutions Construct implements a Lambda function that publishes messages to an SNS topic.
The Lambda function is triggered by events and sends notifications through SNS.

====
[role="tablist"]
Typescript::
+
[source,typescript]
----
import { Construct } from 'constructs';
----
====
"""

# Sample AsciiDoc with Description section
SAMPLE_ADOC_WITH_DESCRIPTION = """
//!!NODE_ROOT <section>
//== aws-lambda-s3 module

[.topic]
= aws-lambda-s3
:info_doctype: section
:info_title: aws-lambda-s3

= Description

This AWS Solutions Construct implements an AWS Lambda function
connected to an Amazon S3 bucket for event processing.

= Overview

Additional overview information here.

====
[role="tablist"]
Typescript::
+
[source,typescript]
----
import { Construct } from 'constructs';
import { Stack, StackProps } from 'aws-cdk-lib';
----
====
"""

# Sample AsciiDoc with title match
SAMPLE_ADOC_WITH_TITLE_MATCH = """
//!!NODE_ROOT <section>
//== aws-lambda-dynamodb module

= aws-lambda-dynamodb

This AWS Solutions Construct implements a Lambda function
that writes to a DynamoDB table.

====
[role="tablist"]
Typescript::
+
[source,typescript]
----
import { Construct } from 'constructs';
----
====
"""

# Sample AsciiDoc with title and paragraph matching ADOC_TITLE_AND_PARAGRAPH_PATTERN
SAMPLE_ADOC_WITH_TITLE_PARAGRAPH_PATTERN = """
//!!NODE_ROOT <section>
//== aws-lambda-eventbridge module

[.topic]
= aws-lambda-eventbridge
:info_doctype: section
:info_title: aws-lambda-eventbridge

This AWS Solutions Construct implements a Lambda function that is triggered by EventBridge events.
The pattern provides a serverless event-driven architecture.

====
[role="tablist"]
Typescript::
+
[source,typescript]
----
import { Construct } from 'constructs';
----
====
"""

# Sample README with Overview section
SAMPLE_README_WITH_OVERVIEW = """
# aws-apigateway-sqs

This pattern creates an API Gateway that sends messages to an SQS queue.

## Overview
This pattern creates an API Gateway REST API that sends messages to an SQS queue.
It provides a simple way to integrate API Gateway with SQS for asynchronous processing.

## Pattern Construct Props
...
"""

# Sample README with only a title (for testing title fallback)
SAMPLE_README_WITH_ONLY_TITLE = """
# aws-lambda-sns

## Pattern Construct Props
...

## Pattern Properties
...
"""

# Sample README with no description but properly formatted for title fallback
SAMPLE_README_FOR_TITLE_FALLBACK = """
# aws-lambda-sns

"""


@pytest.mark.asyncio
async def test_fetch_pattern_list():
    """Test fetching pattern list."""
    # Create a mock response with a regular method (not a coroutine)
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = [
        {'name': 'aws-lambda-dynamodb', 'type': 'dir'},
        {'name': 'aws-apigateway-lambda', 'type': 'dir'},
        {'name': 'core', 'type': 'dir'},  # Should be filtered out
    ]

    # Create a mock client context manager
    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.get.return_value = mock_response

    # Mock the httpx.AsyncClient constructor
    with patch('httpx.AsyncClient', return_value=mock_client):
        # Reset the cache to ensure we're not using cached data
        from awslabs.cdk_mcp_server.data.solutions_constructs_parser import _pattern_list_cache

        _pattern_list_cache['timestamp'] = None
        _pattern_list_cache['data'] = []

        # Call the function
        patterns = await fetch_pattern_list()

        # Verify the results
        assert len(patterns) == 2
        assert 'aws-lambda-dynamodb' in patterns
        assert 'aws-apigateway-lambda' in patterns
        assert 'core' not in patterns


@pytest.mark.asyncio
async def test_get_pattern_info():
    """Test getting pattern info."""
    # Mock the httpx.AsyncClient.get method directly
    with patch('httpx.AsyncClient.get') as mock_get:
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.text = SAMPLE_README
        mock_get.return_value = mock_response

        info = await get_pattern_info('aws-lambda-dynamodb')
        assert info['pattern_name'] == 'aws-lambda-dynamodb'
        assert 'Lambda' in info['services']
        assert 'DynamoDB' in info['services']
        assert 'description' in info
        assert 'use_cases' in info


@pytest.mark.asyncio
async def test_get_pattern_info_with_adoc():
    """Test getting pattern info with AsciiDoc content."""
    # Mock the httpx.AsyncClient.get method directly
    with patch('httpx.AsyncClient.get') as mock_get:
        # First response for README.adoc
        adoc_response = AsyncMock()
        adoc_response.status_code = 200
        adoc_response.text = SAMPLE_ADOC

        # Set up the mock to return the adoc response
        mock_get.return_value = adoc_response

        info = await get_pattern_info('aws-alb-lambda')
        assert info['pattern_name'] == 'aws-alb-lambda'
        assert 'Application Load Balancer' in info['services']
        assert 'Lambda' in info['services']
        assert 'description' in info
        assert (
            'This AWS Solutions Construct implements an an Application Load Balancer to an AWS Lambda function'
            in info['description']
        )


@pytest.mark.asyncio
async def test_get_pattern_info_fallback_to_md():
    """Test getting pattern info with fallback from README.adoc to README.md."""
    # Clear the pattern details cache to ensure we're not using cached data
    from awslabs.cdk_mcp_server.data.solutions_constructs_parser import _pattern_details_cache

    _pattern_details_cache.clear()

    # Mock the httpx.AsyncClient.get method directly
    with (
        patch('httpx.AsyncClient.get') as mock_get,
        patch(
            'awslabs.cdk_mcp_server.data.solutions_constructs_parser.logger.info'
        ) as mock_logger,
    ):
        # First response for README.adoc (404 Not Found)
        adoc_response = AsyncMock()
        adoc_response.status_code = 404

        # Second response for README.md (200 OK)
        md_response = AsyncMock()
        md_response.status_code = 200
        md_response.text = SAMPLE_README

        # Set up the mock to return different responses on consecutive calls
        mock_get.side_effect = [adoc_response, md_response]

        info = await get_pattern_info('aws-lambda-dynamodb')
        assert info['pattern_name'] == 'aws-lambda-dynamodb'
        assert 'Lambda' in info['services']
        assert 'DynamoDB' in info['services']
        assert 'description' in info
        assert 'use_cases' in info

        # Verify that the logger.info was called with the correct messages
        # We can't check the exact URL since it's constructed inside the function,
        # but we can check that the log messages contain the expected substrings
        log_calls = [call[0][0] for call in mock_logger.call_args_list]

        # Print the actual log calls for debugging
        print('Actual log calls:', log_calls)

        # Check for the expected log messages
        assert any('README.adoc not found, trying README.md from' in call for call in log_calls)
        assert any(
            'Successfully fetched README.md for aws-lambda-dynamodb' in call for call in log_calls
        )


@pytest.mark.asyncio
async def test_get_pattern_info_not_found():
    """Test getting pattern info when pattern is not found."""
    # Mock the httpx.AsyncClient.get method directly
    with patch('httpx.AsyncClient.get') as mock_get:
        mock_response = AsyncMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        info = await get_pattern_info('non-existent-pattern')
        assert 'error' in info
        assert 'status_code' in info
        assert info['status_code'] == 404


@pytest.mark.asyncio
async def test_get_pattern_raw():
    """Test getting raw pattern content."""
    # Mock the httpx.AsyncClient.get method directly
    with patch('httpx.AsyncClient.get') as mock_get:
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.text = SAMPLE_README
        mock_get.return_value = mock_response

        result = await get_pattern_raw('aws-lambda-dynamodb')
        assert result['status'] == 'success'
        assert result['pattern_name'] == 'aws-lambda-dynamodb'
        assert 'Lambda' in result['services']
        assert 'DynamoDB' in result['services']
        assert result['content'] == SAMPLE_README
        assert 'message' in result


@pytest.mark.asyncio
async def test_get_pattern_raw_not_found():
    """Test getting raw pattern content when pattern is not found."""
    # Mock the httpx.AsyncClient.get method directly
    with patch('httpx.AsyncClient.get') as mock_get:
        mock_response = AsyncMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        result = await get_pattern_raw('non-existent-pattern')
        assert 'error' in result
        assert 'status_code' in result
        assert result['status_code'] == 404


def test_extract_services_from_pattern_name():
    """Test extracting services from pattern name."""
    services = extract_services_from_pattern_name('aws-lambda-dynamodb')
    assert services == ['Lambda', 'DynamoDB']

    services = extract_services_from_pattern_name('aws-apigateway-lambda')
    assert services == ['API Gateway', 'Lambda']

    services = extract_services_from_pattern_name('aws-s3-lambda')
    assert services == ['S3', 'Lambda']


def test_extract_description():
    """Test extracting description from README content with Description section."""
    description = extract_description(SAMPLE_README)
    assert 'creates a Lambda function' in description
    assert 'triggered by API Gateway' in description


def test_extract_description_from_overview_section():
    """Test extracting description from README content with Overview section."""
    description = extract_description(SAMPLE_README_WITH_OVERVIEW)
    assert 'creates an API Gateway REST API that sends messages to an SQS queue' in description
    assert 'simple way to integrate API Gateway with SQS' in description


def test_extract_description_from_adoc():
    """Test extracting description from AsciiDoc content with Overview section."""
    description = extract_description(SAMPLE_ADOC)
    assert (
        'This AWS Solutions Construct implements an an Application Load Balancer to an AWS Lambda function'
        in description
    )


def test_extract_description_from_adoc_with_multi_paragraph_overview():
    """Test extracting description from AsciiDoc content with multi-paragraph Overview section."""
    description = extract_description(SAMPLE_ADOC_WITH_MULTI_PARAGRAPH_OVERVIEW)
    # Should only include the first paragraph of the overview
    assert (
        'This AWS Solutions Construct implements an API Gateway connected to an SQS queue'
        in description
    )
    assert 'It provides a serverless architecture for message processing' in description
    # Should not include the second paragraph
    assert 'This is a second paragraph' not in description


def test_extract_description_from_adoc_with_overview_no_first_para():
    """Test extracting description from AsciiDoc content with Overview section but no first paragraph match."""
    description = extract_description(SAMPLE_ADOC_WITH_OVERVIEW_NO_FIRST_PARA)
    # Should return the entire overview section with newlines replaced by spaces
    assert 'This is a single line overview with no paragraph break' in description


def test_extract_description_from_adoc_with_title_and_paragraph():
    """Test extracting description from AsciiDoc content with title and paragraph."""
    description = extract_description(SAMPLE_ADOC_WITH_TITLE_CONTENT)
    # Should extract the paragraph after the title
    assert (
        'This AWS Solutions Construct implements a Lambda function that publishes messages to an SNS topic'
        in description
    )
    assert (
        'The Lambda function is triggered by events and sends notifications through SNS'
        in description
    )


def test_extract_description_from_adoc_with_description_section():
    """Test extracting description from AsciiDoc content with Description section."""
    description = extract_description(SAMPLE_ADOC_WITH_DESCRIPTION)
    assert (
        'This AWS Solutions Construct implements an AWS Lambda function connected to an Amazon S3 bucket for event processing'
        in description
    )


def test_extract_description_from_adoc_with_title_match():
    """Test extracting description from AsciiDoc content with title match."""
    description = extract_description(SAMPLE_ADOC_WITH_TITLE_MATCH)
    assert 'Lambda function' in description
    assert 'DynamoDB table' in description


def test_extract_description_from_adoc_with_title_paragraph_pattern():
    """Test extracting description from AsciiDoc content with title and paragraph matching ADOC_TITLE_AND_PARAGRAPH_PATTERN."""
    description = extract_description(SAMPLE_ADOC_WITH_TITLE_PARAGRAPH_PATTERN)
    # Should extract the paragraph after the title using ADOC_TITLE_AND_PARAGRAPH_PATTERN
    assert 'Lambda function that is triggered by EventBridge events' in description
    assert 'serverless event-driven architecture' in description


def test_extract_description_adoc_title_paragraph_pattern_direct():
    """Test the specific code path for ADOC_TITLE_AND_PARAGRAPH_PATTERN in extract_description."""
    # Create a test content that will be recognized as AsciiDoc
    test_content = '= Overview\n\nThis is just a marker to identify as AsciiDoc'

    # Mock the regex search to force the code to go through the ADOC_TITLE_AND_PARAGRAPH_PATTERN path
    with patch('re.search') as mock_search:
        # Set up the mock to return None for all searches except for:
        # 1. The check if it's an AsciiDoc file (any marker in ['= Overview', '= Description'])
        # 2. The ADOC_TITLE_AND_PARAGRAPH_PATTERN search
        def mock_search_side_effect(pattern, content, flags=0):
            if pattern == ADOC_TITLE_AND_PARAGRAPH_PATTERN:
                # Create a mock match object for the ADOC_TITLE_AND_PARAGRAPH_PATTERN
                mock_match = MagicMock()
                # group(1) should return the title
                # group(2) should return the paragraph after the title
                mock_match.group.side_effect = (
                    lambda x: 'aws-lambda-eventbridge'
                    if x == 1
                    else 'This AWS Solutions Construct implements a Lambda function that is triggered by EventBridge events.'
                )
                return mock_match
            # Return None for all other patterns to force the code to use ADOC_TITLE_AND_PARAGRAPH_PATTERN
            return None

        mock_search.side_effect = mock_search_side_effect

        # Use patch.object to mock the 'any' function call that checks if it's an AsciiDoc file
        with patch('builtins.any', return_value=True):
            # Call the function with our test content
            description = extract_description(test_content)

            # Verify the result
            assert 'Lambda function that is triggered by EventBridge events' in description


def test_extract_description_title_fallback():
    """Test extracting description with fallback to title when no description is found."""
    # Mock the behavior of the function by patching the regex search
    with patch('re.search') as mock_search:
        # Set up the mock to return None for all searches except the title pattern
        def mock_search_side_effect(pattern, content, flags=0):
            if pattern == MD_TITLE_PATTERN:
                # Create a mock match object for the title pattern
                mock_match = MagicMock()
                mock_match.group.return_value = 'aws-lambda-sns'
                return mock_match
            return None

        mock_search.side_effect = mock_search_side_effect

        # Call the function with any content since we're mocking the regex search
        description = extract_description('# aws-lambda-sns')
        assert description == 'A pattern for integrating aws-lambda-sns services'


def test_extract_props_markdown():
    """Test extracting props markdown from README content."""
    props_markdown = extract_props_markdown(SAMPLE_README)
    assert '| Name | Description |' in props_markdown
    assert (
        '| `lambdaFunctionProps` | Properties for the Lambda function. Defaults to `lambda.FunctionProps()`. |'
        in props_markdown
    )
    assert (
        '| `dynamoTableProps` | Properties for the DynamoDB table. Required. |' in props_markdown
    )


def test_extract_props_markdown_not_found():
    """Test extracting props markdown when not found."""
    props_markdown = extract_props_markdown('# Test\n\nNo props section here.')
    assert props_markdown == 'No props section found'


def test_extract_props():
    """Test extracting props from README content."""
    props = extract_props(SAMPLE_README)
    assert 'lambdaFunctionProps' in props
    assert 'dynamoTableProps' in props
    assert 'apiGatewayProps' in props
    assert props['dynamoTableProps']['required'] is True
    assert props['apiGatewayProps']['required'] is False


def test_extract_properties():
    """Test extracting properties from README content."""
    properties = extract_properties(SAMPLE_README)
    assert 'lambdaFunction' in properties
    assert 'dynamoTable' in properties
    assert 'apiGateway' in properties
    assert properties['lambdaFunction']['access_method'] == 'pattern.lambdaFunction'


def test_extract_default_settings():
    """Test extracting default settings from README content."""
    defaults = extract_default_settings(SAMPLE_README)
    assert len(defaults) == 3
    assert 'Lambda function with Node.js 18 runtime' in defaults
    assert 'DynamoDB table with on-demand capacity' in defaults


def test_extract_code_example():
    """Test extracting code example from README content."""
    code_example = extract_code_example(SAMPLE_README)
    assert 'import { Construct } from' in code_example
    assert 'new LambdaToDynamoDB(' in code_example
    assert 'lambdaFunctionProps:' in code_example


def test_extract_code_example_not_found():
    """Test extracting code example when not found."""
    code_example = extract_code_example('# Test\n\nNo code example here.')
    assert code_example == 'No code example available'


def test_extract_use_cases():
    """Test extracting use cases from README content."""
    use_cases = extract_use_cases(SAMPLE_README)
    assert len(use_cases) == 3
    assert 'Building serverless APIs with DynamoDB backend' in use_cases
    assert 'Creating data processing pipelines' in use_cases


def test_parse_readme_content():
    """Test parsing complete README content."""
    result = parse_readme_content('aws-lambda-dynamodb', SAMPLE_README)
    assert result['pattern_name'] == 'aws-lambda-dynamodb'
    assert 'Lambda' in result['services']
    assert 'DynamoDB' in result['services']
    assert 'description' in result
    assert 'props' in result
    assert 'properties' in result
    assert 'default_settings' in result
    assert 'use_cases' in result


@pytest.mark.asyncio
async def test_search_patterns():
    """Test searching patterns by services."""
    # Mock the search_utils.search_items_with_terms function to control the search results
    with patch(
        'awslabs.cdk_mcp_server.data.solutions_constructs_parser.search_utils.search_items_with_terms'
    ) as mock_search:
        # Set up the mock to return only one matching pattern
        mock_search.return_value = [
            {'item': 'aws-lambda-dynamodb', 'matched_terms': ['lambda', 'dynamodb']}
        ]

        # Mock get_pattern_info to return consistent data
        with patch(
            'awslabs.cdk_mcp_server.data.solutions_constructs_parser.get_pattern_info'
        ) as mock_get_info:
            mock_get_info.return_value = {
                'pattern_name': 'aws-lambda-dynamodb',
                'services': ['Lambda', 'DynamoDB'],
                'description': 'Test description',
            }

            results = await search_patterns(['lambda', 'dynamodb'])
            assert len(results) == 1
            assert results[0]['pattern_name'] == 'aws-lambda-dynamodb'
            assert 'Lambda' in results[0]['services']
            assert 'DynamoDB' in results[0]['services']


@pytest.mark.asyncio
async def test_search_patterns_error():
    """Test searching patterns with an error."""
    # Mock the search_utils.search_items_with_terms function to raise an exception
    with patch(
        'awslabs.cdk_mcp_server.data.solutions_constructs_parser.search_utils.search_items_with_terms'
    ) as mock_search:
        mock_search.side_effect = Exception('Test error')

        results = await search_patterns(['lambda', 'dynamodb'])
        assert len(results) == 0


@pytest.mark.asyncio
async def test_get_all_patterns_info():
    """Test getting info for all patterns."""
    # Mock fetch_pattern_list to return a list of patterns
    with patch(
        'awslabs.cdk_mcp_server.data.solutions_constructs_parser.fetch_pattern_list'
    ) as mock_fetch:
        mock_fetch.return_value = ['aws-lambda-dynamodb', 'aws-apigateway-lambda']

        # Mock get_pattern_info to return consistent data
        with patch(
            'awslabs.cdk_mcp_server.data.solutions_constructs_parser.get_pattern_info'
        ) as mock_get_info:
            mock_get_info.side_effect = [
                {
                    'pattern_name': 'aws-lambda-dynamodb',
                    'services': ['Lambda', 'DynamoDB'],
                    'description': 'Test description 1',
                },
                {
                    'pattern_name': 'aws-apigateway-lambda',
                    'services': ['API Gateway', 'Lambda'],
                    'description': 'Test description 2',
                },
            ]

            results = await get_all_patterns_info()
            assert len(results) == 2
            assert results[0]['pattern_name'] == 'aws-lambda-dynamodb'
            assert results[1]['pattern_name'] == 'aws-apigateway-lambda'


@pytest.mark.asyncio
async def test_get_all_patterns_info_with_error():
    """Test getting info for all patterns with an error for one pattern."""
    # Mock fetch_pattern_list to return a list of patterns
    with patch(
        'awslabs.cdk_mcp_server.data.solutions_constructs_parser.fetch_pattern_list'
    ) as mock_fetch:
        mock_fetch.return_value = ['aws-lambda-dynamodb', 'aws-apigateway-lambda']

        # Mock get_pattern_info to return data for first pattern and raise exception for second
        with patch(
            'awslabs.cdk_mcp_server.data.solutions_constructs_parser.get_pattern_info'
        ) as mock_get_info:
            mock_get_info.side_effect = [
                {
                    'pattern_name': 'aws-lambda-dynamodb',
                    'services': ['Lambda', 'DynamoDB'],
                    'description': 'Test description 1',
                },
                Exception('Test error'),
            ]

            results = await get_all_patterns_info()
            assert len(results) == 2
            assert results[0]['pattern_name'] == 'aws-lambda-dynamodb'
            assert 'error' in results[1]
            assert results[1]['pattern_name'] == 'aws-apigateway-lambda'


@pytest.mark.asyncio
async def test_get_all_patterns_info_with_fetch_error():
    """Test getting info for all patterns with an error in fetch_pattern_list."""
    # Mock fetch_pattern_list to raise an exception
    with patch(
        'awslabs.cdk_mcp_server.data.solutions_constructs_parser.fetch_pattern_list'
    ) as mock_fetch:
        mock_fetch.side_effect = Exception('Test error')

        results = await get_all_patterns_info()
        assert len(results) == 0
