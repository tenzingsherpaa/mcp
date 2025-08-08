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

import json
import logging
from awslabs.cfn_mcp_server.errors import ClientError, ServerError
from awslabs.cfn_mcp_server.stack_analysis.cloudformation_utils import CloudFormationUtils
from awslabs.cfn_mcp_server.stack_analysis.recommendation_generator import RecommendationGenerator
from awslabs.cfn_mcp_server.stack_analysis.resource_analyzer import ResourceAnalyzer
from awslabs.cfn_mcp_server.stack_analysis.simple_rag import get_rag_instance
from awslabs.cfn_mcp_server.stack_analysis.utils.common_utils import save_template_file
from typing import Any, Dict, List, Optional, Tuple


logger = logging.getLogger(__name__)


class StackAnalyzer:
    """Analyze CloudFormation stacks and resources with enhanced functionality."""

    # CloudFormation best practices constants
    _CF_BEST_PRACTICES = {
        'nested_stacks': 'Use nested stacks to organize related resources that are part of a single solution.',
        'cross_stack_references': 'Use cross-stack references to export shared resources between stacks.',
        'resource_management': 'Manage all stack resources through CloudFormation for consistency.',
        'stack_policies': 'Use stack policies to prevent unintentional updates to critical resources.',
        'iam_access_control': 'Use IAM to control access to CloudFormation resources securely.',
        'parameter_constraints': 'Use parameter constraints to enforce proper input validation.',
        'resource_dependencies': 'Explicitly define resource dependencies when needed.',
        'resource_cleanup': 'Delete unused resources to avoid unnecessary costs.',
        'common_components': 'Extract common components into reusable templates or modules.',
    }

    # Summary field mappings for efficiency
    _SUMMARY_FIELDS = [
        'total_resources',
        'managed_resources',
        'unmanaged_resources',
        'managed_percentage',
        'unmanaged_percentage',
        'unique_resource_types',
    ]

    @classmethod
    def get_best_cfn_practices(cls) -> Dict[str, str]:
        """Get CloudFormation best practices."""
        return cls._CF_BEST_PRACTICES.copy()

    def __init__(self, region: str):
        """Initialize the StackAnalyzer with the specified region."""
        self.region = region
        self.cfn_utils = CloudFormationUtils(region)
        self.resource_matcher = ResourceAnalyzer(region)
        self._rag_instance = None

    @property
    def rag_instance(self):
        """Lazy load RAG instance."""
        if self._rag_instance is None:
            self._rag_instance = get_rag_instance()
        return self._rag_instance

    def analyze_stack(self, stack_name: str, store_in_rag: bool = True) -> Dict[str, Any]:
        """Analyze a CloudFormation stack comprehensively.

        Args:
            stack_name: Name of the stack to analyze
            store_in_rag: Whether to store results in RAG (defaults to True to ensure data is stored)
        """
        try:
            logger.info(f'Starting analysis of stack: {stack_name}')

            # Get basic stack information
            stack_details = self._get_stack_details(stack_name)

            # Perform resource analysis
            stack_resources, resource_analysis_results = self._analyze_stack_resources(stack_name)

            # Get related resources
            related_resources = self._get_related_resources(stack_resources)

            # Generate augmentation recommendation if applicable
            augment_recommendation, related_unmanaged_resources = (
                self._generate_augmentation_recommendation(stack_name, related_resources)
            )

            # Get account summary - always get full summary for accuracy
            account_summary = self._get_account_summary(minimal=False)

            # Build comprehensive analysis result
            analysis = self._build_analysis_result(
                stack_details,
                resource_analysis_results,
                related_resources,
                account_summary,
                augment_recommendation,
                related_unmanaged_resources,
            )

            # Store template file if available
            self._save_template_file(stack_name, augment_recommendation)

            # Store results in RAG only if requested
            if store_in_rag:
                self._store_analysis_in_rag(
                    stack_name,
                    stack_details,
                    stack_resources,
                    related_resources,
                    account_summary,
                    augment_recommendation,
                    related_unmanaged_resources,
                )
                logger.info('Analysis results stored in RAG')

            logger.info('Stack analysis completed successfully')
            return analysis

        except Exception as e:
            logger.error(f'Error analyzing stack {stack_name}: {str(e)}')
            return self._create_error_analysis(str(e))

    def _get_stack_details(self, stack_name: str) -> Dict[str, Any]:
        """Get basic stack details from CloudFormation."""
        stack_details = self.cfn_utils.describe_stack(stack_name)
        logger.info(
            f'Stack details retrieved: {stack_details.get("StackName", "Unknown")} - '
            f'Status: {stack_details.get("StackStatus", "Unknown")}'
        )
        return stack_details

    def _analyze_stack_resources(self, stack_name: str) -> Tuple[List[Dict], Dict]:
        """Analyze stack resources and return processed data."""
        try:
            resource_analysis_results = self.resource_matcher.match_stack_to_scan(stack_name)
            logger.info(f'Resource analysis completed: {resource_analysis_results}')
        except ServerError as e:
            logger.error(f'Error in resource matching: {str(e)}')
            return [], {'error': str(e)}

        # Process matched resources into stack_resources format
        stack_resources = []
        if (
            'matched_resources' in resource_analysis_results
            and 'error' not in resource_analysis_results
        ):
            matched_resources = resource_analysis_results['matched_resources']
            if matched_resources and isinstance(matched_resources, list):
                stack_resources = [
                    {
                        'ResourceType': resource.scanned_resource_type,
                        'ResourceIdentifier': resource.resource_identifier or {},
                    }
                    for resource in matched_resources
                    if (
                        hasattr(resource, 'scanned_resource_type')
                        and hasattr(resource, 'resource_identifier')
                    )
                ]

        return stack_resources, resource_analysis_results

    def _get_related_resources(self, stack_resources: List[Dict]) -> List[Dict]:
        """Get resources related to the stack resources."""
        try:
            related_resources = self.resource_matcher.get_related_resources(stack_resources)
            logger.info(f'Related resources found: {len(related_resources)}')
            return related_resources
        except ServerError as e:
            logger.error(f'Error getting related resources: {str(e)}')
            return []

    def _generate_augmentation_recommendation(
        self, stack_name: str, related_resources: List[Dict]
    ) -> Tuple[Optional[Any], List[Dict]]:
        """Generate augmentation recommendations for unmanaged related resources."""
        if not related_resources or not isinstance(related_resources, list):
            return None, []

        # Filter for unmanaged resources
        related_unmanaged_resources = [
            {
                'ResourceType': resource['ResourceType'],
                'ResourceIdentifier': resource['ResourceIdentifier'],
            }
            for resource in related_resources
            if (
                'ResourceType' in resource
                and 'ResourceIdentifier' in resource
                and resource['ResourceIdentifier']
                and not resource.get('ManagedByStack', False)
            )
        ]

        if not related_unmanaged_resources:
            return None, []

        logger.info(f'Found {len(related_unmanaged_resources)} unmanaged related resources')

        try:
            augment_recommendation_generator = RecommendationGenerator(region=self.region)
            augment_recommendation = augment_recommendation_generator.build_augment_template(
                stack_name=stack_name,
                related_unmanaged_resources=related_unmanaged_resources,
            )
            return augment_recommendation, related_unmanaged_resources
        except Exception as e:
            logger.error(f'Error creating augment recommendation: {str(e)}')
            return None, related_unmanaged_resources

    def _get_account_summary(self, minimal: bool = False) -> Dict[str, Any]:
        """Get account resource summary.

        Args:
            minimal: If True, return a minimal summary with just essential fields
        """
        try:
            account_summary = self.account_resource_summary(minimal=minimal)
            logger.info(f'Account summary completed: {len(account_summary)} fields')
            return account_summary
        except ServerError as e:
            logger.error(f'Error getting account summary: {str(e)}')
            return {'error': str(e)}

    def _build_analysis_result(
        self,
        stack_details: Dict,
        resource_analysis_results: Dict,
        related_resources: List,
        account_summary: Dict,
        augment_recommendation: Optional[Any],
        related_unmanaged_resources: List,
    ) -> Dict[str, Any]:
        """Build the comprehensive analysis result."""
        # Generate resource summary counts by managed status
        resource_summary = self._summarize_resources_by_managed_status(resource_analysis_results)

        # Generate related resources summary by managed status and product type
        related_resources_summary = self._summarize_related_resources(related_resources)

        return {
            'stack_info': stack_details,
            'stack_status': stack_details.get('StackStatus'),
            'creation_time': stack_details.get('CreationTime'),
            'last_updated_time': stack_details.get('LastUpdatedTime'),
            'outputs': stack_details.get('Outputs', []),
            'parameters': stack_details.get('Parameters', []),
            'resource_summary': resource_summary,
            'related_resources_summary': related_resources_summary,
            'account_summary': account_summary,
            'augment_recommendation': (
                augment_recommendation.generated_template_id if augment_recommendation else None
            ),
            'related_unmanaged_count': len(related_unmanaged_resources),
        }

    def _save_template_file(self, stack_name: str, augment_recommendation: Optional[Any]) -> None:
        """Save template file if augment recommendation is available."""
        if not (augment_recommendation and augment_recommendation.template_body):
            return

        try:
            template_body = augment_recommendation.template_body
            save_template_file(stack_name, template_body)
        except Exception as e:
            logger.error(f'Error writing template to file: {str(e)}')

    def _create_error_analysis(self, error_message: str) -> Dict[str, Any]:
        """Create error analysis result structure."""
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
            'error': error_message,
        }

    def account_resource_summary(self, minimal: bool = False) -> Dict[str, Any]:
        """Analyze managed and unmanaged resources in the AWS account.

        Args:
            minimal: If True, return a minimal summary with just essential fields
        """
        try:
            if not self._validate_resource_scan_id():
                return {'error': 'No existing resource scans available'}

            logger.info(
                f'Starting account resource summary using scan ID: {self.cfn_utils.resource_scan_id}'
            )

            # Always fetch fresh scan results
            scan_results = self.cfn_utils.list_resource_scan_resources()
            logger.info(f'Retrieved {len(scan_results)} total resources from scan')

            if not scan_results:
                logger.warning('No resources found in scan results')
                return {
                    'error': 'No resources found in the resource scan',
                    'scan_id': self.cfn_utils.resource_scan_id,
                }

            return self._process_account_summary(scan_results, minimal)

        except ServerError as e:
            logger.error(f'Error analyzing account resources: {str(e)}')
            return {
                'error': str(e),
                'scan_id': getattr(self.cfn_utils, 'resource_scan_id', 'Unknown'),
            }

    def _process_account_summary(
        self, scan_results: List[Dict], minimal: bool = False
    ) -> Dict[str, Any]:
        """Process scan results into account summary.

        Args:
            scan_results: List of resource scan results
            minimal: If True, return a minimal summary with just essential fields
        """
        # For minimal response, just return basic stats
        if minimal:
            total_resources = len(scan_results)
            managed = sum(1 for r in scan_results if r.get('ManagedByStack', False))
            unmanaged = total_resources - managed

            minimal_summary = {
                'scan_metadata': {
                    'scan_id': self.cfn_utils.resource_scan_id,
                    'total_resources_scanned': total_resources,
                },
                'overall_summary': {
                    'total_resources': total_resources,
                    'managed_resources': managed,
                    'unmanaged_resources': unmanaged,
                    'managed_percentage': (managed / total_resources * 100)
                    if total_resources > 0
                    else 0,
                    'unmanaged_percentage': (unmanaged / total_resources * 100)
                    if total_resources > 0
                    else 0,
                },
            }

            logger.info(
                f'Minimal account summary: {total_resources} total resources, '
                f'{unmanaged} unmanaged ({minimal_summary["overall_summary"]["unmanaged_percentage"]:.1f}%)'
            )

            return minimal_summary

        # For full response, process complete summary
        summary = self._initialize_summary(scan_results)
        resource_type_stats, unmanaged_resources = self._process_scan_results(
            scan_results, summary
        )
        self._finalize_summary(summary, resource_type_stats, unmanaged_resources)

        logger.info(
            f'Full account summary: {summary["overall_summary"]["total_resources"]} total resources, '
            f'{summary["overall_summary"]["unmanaged_resources"]} unmanaged '
            f'({summary["overall_summary"]["unmanaged_percentage"]:.1f}%)'
        )

        return summary

    def _initialize_summary(self, scan_results: List[Dict]) -> Dict[str, Any]:
        """Initialize the summary structure."""
        return {
            'scan_metadata': {
                'scan_id': self.cfn_utils.resource_scan_id,
                'total_resources_scanned': len(scan_results),
            },
            'overall_summary': dict.fromkeys(self._SUMMARY_FIELDS, 0),
            'resources_by_type': {},
            'resources_by_type_ranked': [],
            'top_unmanaged_types': [],
            'unmanaged_resources_detail': [],
        }

    def _process_scan_results(
        self, scan_results: List[Dict], summary: Dict
    ) -> Tuple[Dict[str, Dict], List[Dict]]:
        """Process scan results and update summary statistics."""
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

            # Update statistics
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
                unmanaged_resources.append(
                    {
                        'resource_type': resource_type,
                        'resource_identifier': resource_id,
                        'resource_status': resource.get('ResourceStatus', 'Unknown'),
                    }
                )

        return resource_type_stats, unmanaged_resources

    def _finalize_summary(
        self, summary: Dict, resource_type_stats: Dict, unmanaged_resources: List[Dict]
    ) -> None:
        """Finalize summary with calculated percentages and rankings."""
        total = summary['overall_summary']['total_resources']

        if total > 0:
            managed = summary['overall_summary']['managed_resources']
            summary['overall_summary']['managed_percentage'] = (managed / total) * 100
            summary['overall_summary']['unmanaged_percentage'] = ((total - managed) / total) * 100

        summary['overall_summary']['unique_resource_types'] = len(resource_type_stats)

        # Process resource type statistics
        for resource_type, stats in resource_type_stats.items():
            total_for_type = stats['total']
            managed_pct = (stats['managed'] / total_for_type) * 100 if total_for_type > 0 else 0
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

        # Create rankings
        ranked_types = sorted(
            [{'resource_type': rt, **data} for rt, data in summary['resources_by_type'].items()],
            key=lambda x: (x['unmanaged'], x['total']),
            reverse=True,
        )

        summary['resources_by_type_ranked'] = ranked_types
        summary['top_unmanaged_types'] = ranked_types
        summary['unmanaged_resources_detail'] = unmanaged_resources[:50]

        if len(unmanaged_resources) > 50:
            summary['unmanaged_resources_detail_note'] = (
                f'Showing first 50 of {len(unmanaged_resources)} unmanaged resources'
            )

    def _validate_resource_scan_id(self) -> bool:
        """Validate and set resource scan ID if not available."""
        if self.cfn_utils.resource_scan_id:
            return True

        logger.info('No resource scan ID available, looking for latest scan...')
        try:
            scans = self.cfn_utils.list_resource_scans()
            if scans:
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

    # RAG-related methods
    def _store_analysis_in_rag(
        self,
        stack_name: str,
        stack_details: Dict,
        stack_resources: List,
        related_resources: List,
        account_summary: Dict,
        augment_recommendation: Any,
        related_unmanaged_resources: List,
    ) -> None:
        """Store analysis results in the RAG system."""
        try:
            last_updated_time = stack_details.get('LastUpdatedTime') or stack_details.get(
                'CreationTime'
            )

            # Store different types of data

            self._store_related_resources_data(stack_name, related_resources, last_updated_time)
            self._store_account_resources_data(account_summary)

        except Exception as e:
            logger.error(f'Error storing data in RAG system: {str(e)}')

    def _store_related_resources_data(
        self, stack_name: str, related_resources: List, last_updated_time: Any
    ) -> None:
        """Store related resources information in RAG."""
        if not related_resources:
            return

        managed_count = sum(1 for r in related_resources if r.get('ManagedByStack', False))
        unmanaged_count = len(related_resources) - managed_count

        related_data = {
            'scan_metadata': {'scan_id': f'related-{stack_name}', 'end_time': last_updated_time},
            'resources': related_resources,
            'summary': {
                'total_count': len(related_resources),
                'managed_count': managed_count,
                'unmanaged_count': unmanaged_count,
            },
        }
        self._store_rag_data(related_data, 'related resources')

    def _store_account_resources_data(self, account_summary: Dict) -> None:
        """Store account resources information in RAG."""
        if not account_summary or 'error' in account_summary:
            return

        # Get fresh scan results for RAG storage
        try:
            scan_results = self.cfn_utils.list_resource_scan_resources()
        except Exception as e:
            logger.error(f'Failed to get scan results for RAG storage: {str(e)}')
            return

        # Build resources list directly from scan results - more efficient
        resources_list = []
        existing_ids = set()

        # Add unmanaged resources first
        for resource in scan_results:
            if not resource.get('ManagedByStack', False):
                resource_id = json.dumps(resource.get('ResourceIdentifier', {}))
                if resource_id not in existing_ids:
                    existing_ids.add(resource_id)
                    resources_list.append(resource)

        # Then add managed resources if needed (limited to a reasonable number)
        managed_count = 0
        for resource in scan_results:
            if (
                resource.get('ManagedByStack', False) and managed_count < 100
            ):  # Limit to avoid token usage
                resource_id = json.dumps(resource.get('ResourceIdentifier', {}))
                if resource_id not in existing_ids:
                    existing_ids.add(resource_id)
                    resources_list.append(resource)
                    managed_count += 1

        account_data = {
            'scan_metadata': {
                'scan_id': account_summary.get('scan_metadata', {}).get(
                    'scan_id', f'account-{self.region}'
                ),
                'end_time': account_summary.get('scan_metadata', {}).get('end_time'),
            },
            'resources': resources_list,
            'summary': {
                'total_count': account_summary.get('overall_summary', {}).get(
                    'total_resources', 0
                ),
                'managed_count': account_summary.get('overall_summary', {}).get(
                    'managed_resources', 0
                ),
                'unmanaged_count': account_summary.get('overall_summary', {}).get(
                    'unmanaged_resources', 0
                ),
            },
        }
        self._store_rag_data(account_data, 'account resources')

    def _store_rag_data(self, data: Dict, description: str) -> None:
        """Helper to store data in RAG with logging."""
        try:
            rag_result = self.rag_instance.store_scan_data(data, self.region)
            logger.info(f'Stored {description} in RAG: {rag_result}')
        except Exception as e:
            logger.error(f'Failed to store {description} in RAG: {str(e)}')

    # Utility methods for template
    def _summarize_resources_by_managed_status(
        self, resource_analysis_results: Dict
    ) -> Dict[str, Any]:
        """Summarize stack resources by managed status."""
        if not resource_analysis_results or 'matched_resources' not in resource_analysis_results:
            return {'total_resources': 0, 'managed_resources': 0, 'unmanaged_resources': 0}

        matched_resources = resource_analysis_results.get('matched_resources', [])
        unmatched_resources = resource_analysis_results.get('unmanaged_resources', [])

        # Count resources by type
        resource_type_counts = {}
        for resource in matched_resources:
            resource_type = (
                resource.get('resource_type')
                if isinstance(resource, dict)
                else getattr(
                    resource,
                    'resource_type',
                    getattr(resource, 'scanned_resource_type', 'Unknown'),
                )
            )
            if resource_type not in resource_type_counts:
                resource_type_counts[resource_type] = {'managed': 0, 'unmanaged': 0, 'total': 0}
            resource_type_counts[resource_type]['managed'] += 1
            resource_type_counts[resource_type]['total'] += 1

        for resource in unmatched_resources:
            resource_type = (
                resource.get('resource_type')
                if isinstance(resource, dict)
                else getattr(
                    resource,
                    'resource_type',
                    getattr(resource, 'scanned_resource_type', 'Unknown'),
                )
            )
            if resource_type not in resource_type_counts:
                resource_type_counts[resource_type] = {'managed': 0, 'unmanaged': 0, 'total': 0}
            resource_type_counts[resource_type]['unmanaged'] += 1
            resource_type_counts[resource_type]['total'] += 1

        # Sort resource types by total count
        sorted_resource_types = sorted(
            [{'resource_type': rt, **counts} for rt, counts in resource_type_counts.items()],
            key=lambda x: x['total'],
            reverse=True,
        )

        return {
            'total_resources': len(matched_resources) + len(unmatched_resources),
            'managed_resources': len(matched_resources),
            'unmanaged_resources': len(unmatched_resources),
            'by_resource_type': sorted_resource_types,
        }

    def _summarize_related_resources(self, related_resources: List) -> Dict[str, Any]:
        """Summarize related resources by managed status and product type."""
        if not related_resources:
            return {
                'total_resources': 0,
                'managed_resources': 0,
                'unmanaged_resources': 0,
                'by_product_type': {},
            }

        managed_resources = [r for r in related_resources if r.get('ManagedByStack', False)]
        unmanaged_resources = [r for r in related_resources if not r.get('ManagedByStack', False)]

        # Group by product type
        product_type_groups = self._group_resources_by_product_type(related_resources)

        # Build summary by product type
        product_type_summary = {}
        for product_type, resources in product_type_groups.items():
            managed = [r for r in resources if r.get('ManagedByStack', False)]
            unmanaged = [r for r in resources if not r.get('ManagedByStack', False)]
            product_type_summary[product_type] = {
                'total': len(resources),
                'managed': len(managed),
                'unmanaged': len(unmanaged),
            }

        # Sort product types by total count
        sorted_product_types = []
        for product_type, counts in product_type_summary.items():
            product_type_data = {'product_type': product_type}
            product_type_data.update(counts)
            sorted_product_types.append(product_type_data)
        sorted_product_types.sort(key=lambda x: x['total'], reverse=True)

        return {
            'total_resources': len(related_resources),
            'managed_resources': len(managed_resources),
            'unmanaged_resources': len(unmanaged_resources),
            'by_product_type': sorted_product_types,
        }

    def _group_resources_by_product_type(self, resources: List) -> Dict[str, List]:
        """Group resources by AWS product type."""
        recommendation_generator = RecommendationGenerator(region=self.region)
        return recommendation_generator._categorize_resources_by_product_type(resources=resources)
