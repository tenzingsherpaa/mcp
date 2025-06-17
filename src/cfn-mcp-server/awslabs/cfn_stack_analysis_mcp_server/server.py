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

"""
CloudFormation Stack Analysis MCP Server

This module implements an MCP server for analyzing CloudFormation stacks.
"""

import argparse
import logging
import concurrent.futures
from typing import Dict, List, Any, Optional
from awslabs.cfn_stack_analysis_mcp_server.errors import ClientError
from awslabs.cfn_stack_analysis_mcp_server.errors import handle_aws_api_error
from awslabs.cfn_stack_analysis_mcp_server.stack_analyzer import StackAnalyzer

#This is Version 2.0 of the MCP Server
# from fastmcp import FastMCP

from mcp.server.fastmcp import FastMCP
from pydantic import Field


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# CloudFormation best practices || Retreived from online 
CF_BEST_PRACTICES = {
    "nested_stacks": "Use nested stacks to organize related resources that are part of a single solution. Nested stacks are stacks created as part of other stacks. As your infrastructure grows, common patterns can emerge in which you declare the same components in multiple templates. You can separate out these common components and create dedicated templates for them.",
    
    "cross_stack_references": "Use cross-stack references to export shared resources. Cross-stack references let you share resources between stacks. By using cross-stack references, you don't need to hard-code values or use custom scripts to get output values from one stack to another.",
    
    "resource_management": "Manage all stack resources through CloudFormation. After you launch a stack, use the CloudFormation console, API, or CLI to update resources in your stacks. This ensures that your changes are synchronized with your stack templates and related stack resources.",
    
    "stack_policies": "Use stack policies to prevent unintentional updates to critical stack resources. Stack policies help protect resources from unintentional updates that could cause disruption or data loss.",
    
    "iam_access_control": "Use IAM to control access to CloudFormation resources. IAM lets you securely control who can access your CloudFormation stacks and what actions they can perform on them.",
    
    "parameter_constraints": "Use parameter constraints to enforce proper input validation. Parameter constraints help ensure that input values meet your requirements before CloudFormation creates or updates any resources.",
    
    "resource_dependencies": "Explicitly define resource dependencies when needed. CloudFormation automatically determines the correct order to create or delete resources based on their dependencies. However, in some cases, you might need to explicitly define these dependencies.",
    
    "resource_cleanup": "Delete unused resources to avoid unnecessary costs. CloudFormation makes it easy to delete an entire stack, but you should also monitor for and remove individual resources that are no longer needed.",
    
    "common_components": "Extract common components into reusable templates or modules. This promotes consistency and reduces duplication across your infrastructure."
}



mcp = FastMCP(
    'awslabs.cfn-stack-analysis-mcp-server',
    instructions="""
    # CloudFormation Stack Analysis MCP

    This MCP allows you to:
    1. Analyze CloudFormation stacks and their resources
    2. Find unmanaged resources related to a stack
    3. Find resources in other stacks that are related to a given stack
    4. Get recommendations for stack refactoring
    5. List and analyze your stacks with "analyze my stacks" command
    6. Analyze multiple stacks with "please analyze my stacks" command
    """,
    dependencies=['pydantic', 'loguru', 'boto3', 'botocore'],
)



@mcp.tool()
async def analyze_stack(
    stack_name: str = Field(
        description='The name of the CloudFormation stack to analyze'
    ),
    region: str | None = Field(
        description='The AWS region that the operation should be performed in', default=None
    ),
) -> Dict[str, Any]:
    """Analyze a CloudFormation stack and return detailed information about its resources.

    Parameters:
        stack_name: The name of the CloudFormation stack to analyze
        region: AWS region to use (e.g., "us-east-1", "us-west-2")

    Returns:
        Detailed information about the stack and its resources in three distinct sections:
        1. Resources in the given stack
        2. Related resources that are not managed by CloudFormation
        3. Related resources that are managed by different stacks
        
        The output is formatted with clear section dividers for readability.
    """
    if not stack_name:
        raise ClientError('Please provide a stack name')
    


