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

"""AWS CDK MCP server implementation."""

import logging
from awslabs.cdk_mcp_server.core import resources, tools
from mcp.server.fastmcp import FastMCP


# Set up logging
logger = logging.getLogger(__name__)


# Create MCP server
mcp = FastMCP(
    'AWS CDK MCP Server',
    dependencies=[
        'pydantic',
        'aws-lambda-powertools',
        'httpx',
    ],
)


# Register resources
mcp.resource('cdk-nag://rules/{rule_pack}')(resources.get_all_cdk_nag_rules)
mcp.resource('cdk-nag://warnings/{rule_pack}')(resources.get_cdk_nag_warnings)
mcp.resource('cdk-nag://errors/{rule_pack}')(resources.get_cdk_nag_errors)
mcp.resource('lambda-powertools://{topic}')(resources.get_lambda_powertools_guidance)
mcp.resource('lambda-powertools://')(resources.get_lambda_powertools_index)
mcp.resource('aws-solutions-constructs://{pattern_name}')(
    resources.get_solutions_construct_pattern_resource
)
# Fixed the ordering - more specific routes first
mcp.resource('genai-cdk-constructs://{construct_type}/{construct_name}/sections')(
    resources.get_available_sections_resource
)
mcp.resource('genai-cdk-constructs://{construct_type}/{construct_name}/{section}')(
    resources.get_genai_cdk_construct_section_resource
)
mcp.resource('genai-cdk-constructs://{construct_type}/{construct_name}/{parent}/{child}')(
    resources.get_genai_cdk_construct_nested_section_resource
)
mcp.resource('genai-cdk-constructs://{construct_type}/{construct_name}')(
    resources.get_genai_cdk_construct_resource
)
mcp.resource('genai-cdk-constructs://{construct_type}')(resources.get_genai_cdk_overview_resource)


# Register tools
mcp.tool(name='CDKGeneralGuidance')(tools.cdk_guidance)
mcp.tool(name='ExplainCDKNagRule')(tools.explain_cdk_nag_rule)
mcp.tool(name='CheckCDKNagSuppressions')(tools.check_cdk_nag_suppressions_tool)
mcp.tool(name='GenerateBedrockAgentSchema')(tools.bedrock_schema_generator_from_file)
mcp.tool(name='GetAwsSolutionsConstructPattern')(tools.get_aws_solutions_construct_pattern)
mcp.tool(name='SearchGenAICDKConstructs')(tools.search_genai_cdk_constructs)
mcp.tool(name='LambdaLayerDocumentationProvider')(tools.lambda_layer_documentation_provider)


def main():
    """Run the MCP server with CLI argument support."""
    mcp.run()


if __name__ == '__main__':
    main()
