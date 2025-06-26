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


import logging
from awslabs.cfn_mcp_server.stack_analysis.cloud_formation_utils import CloudFormationUtils
from typing import Any, Dict


logger = logging.getLogger(__name__)


class StackAnalyzer:
    """A class to analyze CloudFormation stacks and resources."""

    # CloudFormation best practices || Retrieved from online
    # https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/best-practices.html
    _CF_BEST_PRACTICES = {
        'nested_stacks': 'Use nested stacks to organize related resources that are part of a single solution. Nested stacks are stacks created as part of other stacks. As your infrastructure grows, common patterns can emerge in which you declare the same components in multiple templates. You can separate out these common components and create dedicated templates for them.',
        'cross_stack_references': "Use cross-stack references to export shared resources. Cross-stack references let you share resources between stacks. By using cross-stack references, you don't need to hard-code values or use custom scripts to get output values from one stack to another.",
        'resource_management': 'Manage all stack resources through CloudFormation. After you launch a stack, use the CloudFormation console, API, or CLI to update resources in your stacks. This ensures that your changes are synchronized with your stack templates and related stack resources.',
        'stack_policies': 'Use stack policies to prevent unintentional updates to critical stack resources. Stack policies help protect resources from unintentional updates that could cause disruption or data loss.',
        'iam_access_control': 'Use IAM to control access to CloudFormation resources. IAM lets you securely control who can access your CloudFormation stacks and what actions they can perform on them.',
        'parameter_constraints': 'Use parameter constraints to enforce proper input validation. Parameter constraints help ensure that input values meet your requirements before CloudFormation creates or updates any resources.',
        'resource_dependencies': 'Explicitly define resource dependencies when needed. CloudFormation automatically determines the correct order to create or delete resources based on their dependencies. However, in some cases, you might need to explicitly define these dependencies.',
        'resource_cleanup': 'Delete unused resources to avoid unnecessary costs. CloudFormation makes it easy to delete an entire stack, but you should also monitor for and remove individual resources that are no longer needed.',
        'common_components': 'Extract common components into reusable templates or modules. This promotes consistency and reduces duplication across your infrastructure.',
    }

    @classmethod
    def get_best_cfn_practices(cls) -> Dict[str, str]:
        """Get CloudFormation best practices.

        Returns:
            Dictionary of CloudFormation best practices
        """
        return cls._CF_BEST_PRACTICES

    def __init__(self, region: str):
        """Initialize the StackAnalyzer with the specified region.

        Args:
            region: The AWS region to use for API calls.
        """
        self.region = region
        self.cfn_utils = CloudFormationUtils(region)

    """" Start of the Stack Analysis Algorithm """

    def analyze_stack(self, stack_name: str) -> Dict[str, Any]:
        """Analyze a CloudFormation stack.

        Args:
            stack_name: Name of the stack

        Returns:
            Dict containing stack analysis
        """
        try:
            # Get stack details
            stack_details = self.cfn_utils.describe_stack(stack_name)

            # Get stack resources
            stack_resources = self.cfn_utils.list_stack_resources(stack_name)

            # Basic analysis
            analysis = {
                'stack_info': stack_details,
                'resources': stack_resources,
                'resource_count': len(stack_resources),
                'stack_status': stack_details.get('StackStatus'),
                'creation_time': stack_details.get('CreationTime'),
                'last_updated_time': stack_details.get('LastUpdatedTime'),
                'outputs': stack_details.get('Outputs', []),
                'parameters': stack_details.get('Parameters', []),
                'tags': stack_details.get('Tags', []),
            }

            return analysis
        except Exception as e:
            logger.error(f'Error analyzing stack {stack_name}: {str(e)}')
            return {'error': str(e)}

    def analyze_unmanaged_resources(self) -> Dict[str, Any]:
        """Analyze unmanaged resources in the AWS account.

        Returns:
            Dict containing analysis of unmanaged resources
        """
        # This is a placeholder - actual implementation would require scanning resources
        return {'message': 'Unmanaged resource analysis not implemented yet'}
