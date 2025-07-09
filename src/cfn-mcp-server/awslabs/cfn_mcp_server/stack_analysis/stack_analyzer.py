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
from awslabs.cfn_mcp_server.errors import ClientError, ServerError
from awslabs.cfn_mcp_server.stack_analysis.cloudformation_utils import CloudFormationUtils
from awslabs.cfn_mcp_server.stack_analysis.resource_analyzer import ResourceAnalyzer
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
        self.resource_matcher = ResourceAnalyzer(region)

    """" Start of the Stack Analysis Algorithm """

    def analyze_stack(self, stack_name: str) -> Dict[str, Any]:
        """Analyze a CloudFormation stack.

        Args:
            stack_name: Name of the stack

        Returns:
            Dict containing stack analysis including matched resources and account summary
        """
        try:
            logger.info(f'Starting analysis of stack: {stack_name}')

            # Phase 1: Verify Stack Details
            logger.info('Getting stack details...')
            stack_details = self.cfn_utils.describe_stack(stack_name)
            logger.info(
                f'Stack details retrieved: {stack_details.get("StackName", "Unknown")} - Status: {stack_details.get("StackStatus", "Unknown")}'
            )

            # Phase 2: Match stack resources to scanned resources and perform resource analysis
            logger.info('Matching stack resources to scanned resources...')
            try:
                resource_analysis_results = self.resource_matcher.match_stack_to_scan(stack_name)
                logger.info(f'Resource analysis completed: {resource_analysis_results}')
            except ServerError as e:
                logger.error(f'Error in resource matching: {str(e)}')
                resource_analysis_results = {'error': str(e)}

            # Phase 3: Get related resources and account summary
            stack_resources = []
            if (
                'matched_resources' in resource_analysis_results
                and 'error' not in resource_analysis_results
            ):
                matched_resources = resource_analysis_results['matched_resources']
                if matched_resources and isinstance(matched_resources, list):
                    for resource in matched_resources:
                        # Ensure resource has the expected attributes (ResourceMatchResult object)
                        if hasattr(resource, 'scanned_resource_type') and hasattr(
                            resource, 'resource_identifier'
                        ):
                            stack_resources.append(
                                {
                                    'ResourceType': resource.scanned_resource_type,
                                    'ResourceIdentifier': resource.resource_identifier or {},
                                }
                            )

            logger.info('Getting related resources...')
            try:
                related_resources = self.resource_matcher.get_related_resources(stack_resources)
                logger.info(f'Related resources found: {len(related_resources)}')
            except ServerError as e:
                logger.error(f'Error getting related resources: {str(e)}')
                related_resources = []

            # Get account resource summary
            # Creating a summary like this allows for better structured output for Q's ingestion
            # and analysis, including stack details, resource analysis results, related resources,
            # and account summary.
            # This will help in understanding the overall state of the stack and its resources.
            logger.info('Getting account resource summary...')
            try:
                account_summary = self.account_resource_summary()
                logger.info(f'Account summary completed: {account_summary}')
            except ServerError as e:
                logger.error(f'Error getting account summary: {str(e)}')
                account_summary = {'error': str(e)}

            # Final analysis structure
            # This structure includes all relevant information about the stack,
            analysis = {
                'stack_info': stack_details,
                'stack_status': stack_details.get('StackStatus'),
                'creation_time': stack_details.get('CreationTime'),
                'last_updated_time': stack_details.get('LastUpdatedTime'),
                'outputs': stack_details.get('Outputs', []),
                'parameters': stack_details.get('Parameters', []),
                'resources': resource_analysis_results,
                'related_resources': related_resources,
                'account_summary': account_summary,
            }

            logger.info('Stack analysis completed successfully')
            return analysis
        except Exception as e:
            logger.error(f'Error analyzing stack {stack_name}: {str(e)}')
            # Return a structured error response instead of just an error dict
            return {
                'stack_info': None,
                'stack_status': None,
                'creation_time': None,
                'last_updated_time': None,
                'outputs': [],
                'parameters': [],
                'resources': None,
                'related_resources': [],
                'account_summary': {},
                'error': str(e),
            }

    def account_resource_summary(self) -> Dict[str, Any]:
        """Analyze managed and unmanaged resources in the AWS account after a resource scan.

        Creates a detailed account summary filtered by resource types, showing managed/unmanaged
        counts for each resource type, and returns results ranked by most unmanaged to least.

        Returns:
            Dict[str, Any]: Analysis of managed/unmanaged resources by type with ranking
        """
        try:
            if not self._validate_resource_scan_id():
                return {'error': 'No existing resource scans available'}

            logger.info(
                f'Starting account resource summary analysis using scan ID: {self.cfn_utils.resource_scan_id}'
            )

            # Get all resources from the scan with pagination handling
            scan_results = self.cfn_utils.list_resource_scan_resources()
            logger.info(f'Retrieved {len(scan_results)} total resources from scan')

            if not scan_results:
                logger.warning('No resources found in scan results')
                return {
                    'error': 'No resources found in the resource scan',
                    'scan_id': self.cfn_utils.resource_scan_id,
                }

            # Initialize summary structure
            summary = {
                'scan_metadata': {
                    'scan_id': self.cfn_utils.resource_scan_id,
                    'total_resources_scanned': len(scan_results),
                },
                'overall_summary': {
                    'total_resources': 0,
                    'managed_resources': 0,
                    'unmanaged_resources': 0,
                    'managed_percentage': 0.0,
                    'unmanaged_percentage': 0.0,
                    'unique_resource_types': 0,
                },
                'resources_by_type': {},
                'resources_by_type_ranked': [],
                'top_unmanaged_types': [],
                'unmanaged_resources_detail': [],
            }

            # Process all resources in a single pass for efficiency
            resource_type_stats = {}
            unmanaged_resources = []

            for resource in scan_results:
                resource_type = resource.get('ResourceType', 'Unknown')
                resource_id = resource.get('ResourceIdentifier', {})
                is_managed = resource.get('ManagedByStack', False)

                # Initialize resource type stats if not exists
                if resource_type not in resource_type_stats:
                    resource_type_stats[resource_type] = {
                        'total': 0,
                        'managed': 0,
                        'unmanaged': 0,
                        'managed_resources': [],
                        'unmanaged_resources': [],
                    }

                # Update counts
                resource_type_stats[resource_type]['total'] += 1
                summary['overall_summary']['total_resources'] += 1

                if is_managed:
                    resource_type_stats[resource_type]['managed'] += 1
                    resource_type_stats[resource_type]['managed_resources'].append(resource_id)
                    summary['overall_summary']['managed_resources'] += 1
                else:
                    resource_type_stats[resource_type]['unmanaged'] += 1
                    resource_type_stats[resource_type]['unmanaged_resources'].append(resource_id)
                    summary['overall_summary']['unmanaged_resources'] += 1

                    # Add to detailed unmanaged list
                    unmanaged_resources.append(
                        {
                            'resource_type': resource_type,
                            'resource_identifier': resource_id,
                            'resource_status': resource.get('ResourceStatus', 'Unknown'),
                        }
                    )

            # Calculate overall percentages
            total = summary['overall_summary']['total_resources']
            if total > 0:
                summary['overall_summary']['managed_percentage'] = (
                    summary['overall_summary']['managed_resources'] / total
                ) * 100
                summary['overall_summary']['unmanaged_percentage'] = (
                    summary['overall_summary']['unmanaged_resources'] / total
                ) * 100

            summary['overall_summary']['unique_resource_types'] = len(resource_type_stats)

            # Process resource type statistics and calculate percentages
            for resource_type, stats in resource_type_stats.items():
                total_for_type = stats['total']
                managed_pct = (
                    (stats['managed'] / total_for_type) * 100 if total_for_type > 0 else 0
                )
                unmanaged_pct = (
                    (stats['unmanaged'] / total_for_type) * 100 if total_for_type > 0 else 0
                )

                summary['resources_by_type'][resource_type] = {
                    'total': stats['total'],
                    'managed': stats['managed'],
                    'unmanaged': stats['unmanaged'],
                    'managed_percentage': round(managed_pct, 2),
                    'unmanaged_percentage': round(unmanaged_pct, 2),
                    'managed_resources_count': len(stats['managed_resources']),
                    'unmanaged_resources_count': len(stats['unmanaged_resources']),
                }

            # Create ranked list by most unmanaged resources
            ranked_types = []
            for resource_type, data in summary['resources_by_type'].items():
                ranked_types.append(
                    {
                        'resource_type': resource_type,
                        'total_resources': data['total'],
                        'unmanaged_count': data['unmanaged'],
                        'managed_count': data['managed'],
                        'unmanaged_percentage': data['unmanaged_percentage'],
                        'managed_percentage': data['managed_percentage'],
                    }
                )

            # Sort by unmanaged count (descending), then by total count (descending)
            ranked_types.sort(
                key=lambda x: (x['unmanaged_count'], x['total_resources']), reverse=True
            )
            summary['resources_by_type_ranked'] = ranked_types

            # Get top unmanaged resource types
            summary['top_unmanaged_types'] = ranked_types

            # Add detailed unmanaged resources (limit to prevent huge responses)
            summary['unmanaged_resources_detail'] = unmanaged_resources[
                :50
            ]  # Limit to first 50 for now
            if len(unmanaged_resources) > 50:
                summary['unmanaged_resources_detail_note'] = (
                    f'Showing first 50 of {len(unmanaged_resources)} unmanaged resources'
                )

            logger.info(
                f'Account summary completed: {total} total resources, {summary["overall_summary"]["unmanaged_resources"]} unmanaged ({summary["overall_summary"]["unmanaged_percentage"]:.1f}%)'
            )
            logger.info(f'Found {len(resource_type_stats)} unique resource types')

            return summary

        except ServerError as e:
            logger.error(f'Error analyzing account resources: {str(e)}')
            return {
                'error': str(e),
                'scan_id': getattr(self.cfn_utils, 'resource_scan_id', 'Unknown'),
            }

    # Validate and set resource scan ID if not available.
    # Returns True if valid scan ID is available, False otherwise.
    def _validate_resource_scan_id(self) -> bool:
        """Validate and set resource scan ID if not available.

        Returns:
            bool: True if valid scan ID is available, False otherwise
        """
        if not self.cfn_utils.resource_scan_id:
            logger.info('No resource scan ID available, looking for latest scan...')
            try:
                scans = self.cfn_utils.list_resource_scans()
                if scans and len(scans) > 0:
                    latest_scan = scans[0]
                    self.cfn_utils.resource_scan_id = latest_scan.get('ResourceScanId')
                    logger.info(
                        f'Using latest resource scan with ID: {self.cfn_utils.resource_scan_id}'
                    )
                    return True
                else:
                    logger.error('No existing resource scans found')
                    return False
            except ClientError as e:
                logger.error(f'Failed to get latest resource scan: {str(e)}')
                return False
        return True
