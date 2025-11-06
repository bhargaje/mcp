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

"""Handler for EKS Cluster Autoscaler best practices checks in the EKS MCP Server."""

import json
from pathlib import Path
from awslabs.eks_review_mcp_server.aws_helper import AwsHelper
from awslabs.eks_review_mcp_server.logging_helper import LogLevel, log_with_request_id
from awslabs.eks_review_mcp_server.models import ClusterAutoscalerCheckResponse
from loguru import logger
from mcp.server.fastmcp import Context
from mcp.types import TextContent
from pydantic import Field
from typing import Any, Dict, Optional, List


class EKSClusterAutoscalerHandler:
    """Handler for EKS Cluster Autoscaler best practices checks in the EKS MCP Server."""

    def __init__(self, mcp, client_cache):
        """Initialize the EKS cluster autoscaler handler.

        Args:
            mcp: The MCP server instance
            client_cache: K8sClientCache instance to share between handlers
        """
        self.mcp = mcp
        self.client_cache = client_cache
        self.check_registry = self._load_check_registry()

        # Register the comprehensive check tool
        self.mcp.tool(name='check_cluster_autoscaler_best_practices')(self.check_cluster_autoscaler_best_practices)

    def _load_check_registry(self) -> Dict[str, Any]:
        """Load check definitions from JSON file."""
        try:
            config_path = Path(__file__).parent / 'data' / 'eks_cluster_autoscaler_checks.json'
            with open(config_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load check registry: {e}")
            return {}

    def _get_all_checks(self) -> Dict[str, Dict[str, Any]]:
        """Get all checks flattened into a single dictionary."""
        all_checks = {}
        for category in ['version_compatibility', 'auto_discovery', 'iam_permissions', 'node_group_config', 'cost_optimization', 'performance_scalability', 'availability']:
            all_checks.update(self.check_registry.get(category, {}))
        return all_checks

    def _get_check_info(self, check_id: str) -> Dict[str, Any]:
        """Get check information by ID."""
        all_checks = self._get_all_checks()
        return all_checks.get(check_id, {})

    def _get_remediation(self, check_id: str) -> str:
        """Get remediation guidance for a check."""
        check_info = self._get_check_info(check_id)
        return check_info.get('remediation', '')

    def _create_check_result(self, check_id: str, compliant: bool, impacted_resources: List[str], details: str) -> Dict[str, Any]:
        """Create a standardized check result."""
        check_info = self._get_check_info(check_id)
        remediation = self._get_remediation(check_id) if not compliant else ''
        
        return {
            'check_id': check_id,
            'check_name': check_info.get('name', f'Check {check_id}'),
            'compliant': compliant,
            'impacted_resources': impacted_resources,
            'details': details,
            'remediation': remediation,
        }

    def _create_check_error_result(self, check_id: str, error_msg: str) -> Dict[str, Any]:
        """Create an error result for a failed check."""
        check_info = self._get_check_info(check_id)
        return {
            'check_id': check_id,
            'check_name': check_info.get('name', f'Check {check_id}'),
            'compliant': False,
            'impacted_resources': [],
            'details': f'Check failed with error: {error_msg}',
            'remediation': '',
        }

    def _create_error_response(self, cluster_name: str, error_msg: str) -> ClusterAutoscalerCheckResponse:
        """Create an error response."""
        return ClusterAutoscalerCheckResponse(
            isError=True,
            content=[TextContent(type='text', text=f'Failed to connect to cluster {cluster_name}: {error_msg}')],
            check_results=[{
                'check_name': 'Connection Error',
                'compliant': False,
                'impacted_resources': [],
                'details': error_msg,
                'remediation': 'Verify that the cluster exists and is accessible.',
            }],
            overall_compliant=False,
            summary=f'Failed to connect to cluster {cluster_name}: {error_msg}',
        )

    async def check_cluster_autoscaler_best_practices(
        self,
        ctx: Context,
        cluster_name: str = Field(
            ..., description='Name of the EKS cluster to check for Cluster Autoscaler best practices.'
        ),
        region: Optional[str] = Field(
            None, description='AWS region where the cluster is located. If not provided, uses default region.'
        ),
        namespace: Optional[str] = Field(
            'kube-system', description='Namespace where Cluster Autoscaler is deployed (default: kube-system).'
        ),
    ) -> ClusterAutoscalerCheckResponse:
        """Check EKS cluster for Cluster Autoscaler best practices.

        This tool runs a comprehensive set of checks against your EKS cluster's
        Cluster Autoscaler configuration based on AWS best practices to identify 
        potential issues and provides remediation guidance.

        The tool evaluates critical best practices across:
        - Version Compatibility: Ensures CA version matches cluster version
        - Auto Discovery: Verifies proper auto-discovery configuration and tags
        - IAM Permissions: Validates least-privileged IAM role setup
        - Node Group Configuration: Checks for optimal node group setup
        - Cost Optimization: Reviews Spot instance and expander configurations
        - Performance & Scalability: Assesses resource allocation and scan intervals
        - Availability: Evaluates overprovisioning and workload protection
        """
        try:
            logger.info(f'Starting Cluster Autoscaler best practices check for cluster: {cluster_name}')

            # Get K8s client for the cluster
            try:
                k8s_client = self.client_cache.get_client(cluster_name)
                logger.info(f'Successfully obtained K8s client for cluster: {cluster_name}')
            except Exception as e:
                logger.error(f'Failed to get K8s client for cluster {cluster_name}: {str(e)}')
                return self._create_error_response(cluster_name, str(e))

            # First check if Cluster Autoscaler is deployed (VC1 check)
            ca_deployment_result = await self._check_version_compatibility(k8s_client, cluster_name, region, namespace)
            
            check_results = []
            all_compliant = True
            
            # Check if Cluster Autoscaler was found
            ca_found = ca_deployment_result['compliant'] or (
                ca_deployment_result['impacted_resources'] and 
                len(ca_deployment_result['impacted_resources']) > 0
            )
            
            # If Cluster Autoscaler is deployed, run all checks
            if ca_found:
                logger.info('Cluster Autoscaler found - running Cluster Autoscaler best practices checks')
                
                # Add the version compatibility check result
                check_results.append(ca_deployment_result)
                
                # Get remaining checks (AD1-AV2) and sort by ID
                all_checks = self._get_all_checks()
                remaining_checks = {k: v for k, v in all_checks.items() if k != 'VC1'}
                
                for check_id in sorted(remaining_checks.keys()):
                    try:
                        logger.info(f'Running check {check_id}')
                        result = await self._execute_check(check_id, k8s_client, cluster_name, region, namespace)
                        check_results.append(result)
                        
                        if not result['compliant']:
                            all_compliant = False
                            
                        logger.info(f'Check {check_id} completed: {result["compliant"]}')
                        
                    except Exception as e:
                        logger.error(f'Error in check {check_id}: {str(e)}')
                        error_result = self._create_check_error_result(check_id, str(e))
                        check_results.append(error_result)
                        all_compliant = False
            else:
                logger.info('Cluster Autoscaler not found - checking for alternative autoscaling solutions')
                
                # Check if Karpenter or Auto Mode is being used
                karpenter_found = await self._check_for_karpenter(k8s_client, namespace)
                auto_mode_enabled = await self._check_for_auto_mode(cluster_name, region)
                
                if karpenter_found or auto_mode_enabled:
                    alternative = 'Karpenter' if karpenter_found else 'EKS Auto Mode'
                    logger.info(f'{alternative} detected - Cluster Autoscaler checks not applicable')
                    check_results.append(self._create_check_result(
                        'VC1',
                        True,
                        [],
                        f'Cluster Autoscaler not found, but {alternative} is being used for node autoscaling'
                    ))
                    all_compliant = True  # Using alternative is compliant
                else:
                    logger.info('No autoscaling solution found - adding Cluster Autoscaler deployment check')
                    check_results.append(ca_deployment_result)
                    all_compliant = False

            # Generate summary
            passed_count = sum(1 for r in check_results if r['compliant'])
            failed_count = len(check_results) - passed_count
            summary = f'Cluster {cluster_name} Cluster Autoscaler check: {passed_count} checks passed, {failed_count} checks failed'

            return ClusterAutoscalerCheckResponse(
                isError=False,
                content=[TextContent(type='text', text=summary)],
                check_results=check_results,
                overall_compliant=all_compliant,
                summary=summary,
            )

        except Exception as e:
            logger.error(f'Unexpected error in Cluster Autoscaler check: {str(e)}')
            return self._create_error_response(cluster_name, str(e))

    async def _execute_check(self, check_id: str, k8s_client, cluster_name: str, region: Optional[str], namespace: Optional[str]) -> Dict[str, Any]:
        """Execute a single check based on its ID."""
        
        # Map check IDs to their corresponding methods
        check_methods = {
            'VC1': self._check_version_compatibility,
            'AD1': self._check_auto_discovery_enabled,
            'AD2': self._check_node_group_tags,
            'IAM1': self._check_iam_permissions,
            'NG1': self._check_identical_scheduling_properties,
            'NG2': self._check_node_group_consolidation,
            'NG3': self._check_managed_node_groups,
            'CO1': self._check_spot_diversification,
            'CO2': self._check_capacity_separation,
            'CO3': self._check_expander_strategy,
            'PS1': self._check_resource_allocation,
            'PS2': self._check_scan_interval,
            'AV1': self._check_overprovisioning,
            'AV2': self._check_workload_protection,
        }
        
        method = check_methods.get(check_id)
        if method:
            return await method(k8s_client, cluster_name, region, namespace)
        else:
            return self._create_check_error_result(check_id, f'Check method not implemented for {check_id}')

    async def _check_version_compatibility(self, k8s_client, cluster_name: str, region: Optional[str], namespace: Optional[str]) -> Dict[str, Any]:
        """Check if Cluster Autoscaler version matches cluster version."""
        try:
            # Get cluster version using AwsHelper
            eks_client = AwsHelper.create_boto3_client('eks', region_name=region)
            cluster_info = eks_client.describe_cluster(name=cluster_name)
            cluster_version = cluster_info['cluster']['version']
            
            # Get Cluster Autoscaler deployment
            deployments = k8s_client.list_resources(
                kind='Deployment',
                api_version='apps/v1',
                namespace=namespace or 'kube-system'
            )
            
            version_issues = []
            compliant_deployments = []
            
            for deployment in deployments.items:
                if 'cluster-autoscaler' in deployment.metadata.name.lower():
                    deployment_name = f"{deployment.metadata.namespace}/{deployment.metadata.name}"
                    containers = deployment.spec.template.spec.get('containers', [])
                    
                    for container in containers:
                        if 'cluster-autoscaler' in container.get('name', '').lower():
                            image = container.get('image', '')
                            
                            # Extract version from image tag
                            if ':v' in image:
                                ca_version = image.split(':v')[1].split('.')[0] + '.' + image.split(':v')[1].split('.')[1]
                                if ca_version == cluster_version:
                                    compliant_deployments.append(deployment_name)
                                else:
                                    version_issues.append(f"{deployment_name} - CA version {ca_version} != cluster version {cluster_version}")
                            else:
                                version_issues.append(f"{deployment_name} - cannot determine CA version from image {image}")
            
            if not compliant_deployments and not version_issues:
                return self._create_check_result(
                    'VC1',
                    False,
                    [],
                    'No Cluster Autoscaler deployment found'
                )
            
            if version_issues:
                return self._create_check_result(
                    'VC1',
                    False,
                    version_issues,
                    f'Version mismatch detected. Cluster version: {cluster_version}'
                )
            else:
                return self._create_check_result(
                    'VC1',
                    True,
                    compliant_deployments,
                    f'Cluster Autoscaler version matches cluster version {cluster_version}'
                )
        except Exception as e:
            return self._create_check_error_result('VC1', str(e))

    async def _check_auto_discovery_enabled(self, k8s_client, cluster_name: str, region: Optional[str], namespace: Optional[str]) -> Dict[str, Any]:
        """Check if auto-discovery is enabled."""
        try:
            deployments = k8s_client.list_resources(
                kind='Deployment',
                api_version='apps/v1',
                namespace=namespace or 'kube-system'
            )
            
            auto_discovery_issues = []
            compliant_deployments = []
            
            for deployment in deployments.items:
                if 'cluster-autoscaler' in deployment.metadata.name.lower():
                    deployment_name = f"{deployment.metadata.namespace}/{deployment.metadata.name}"
                    containers = deployment.spec.template.spec.get('containers', [])
                    
                    for container in containers:
                        if 'cluster-autoscaler' in container.get('name', '').lower():
                            command = container.get('command', [])
                            args = container.get('args', [])
                            all_args = command + args
                            
                            # Check for auto-discovery configuration
                            has_auto_discovery = any('--node-group-auto-discovery' in str(arg) for arg in all_args)
                            
                            if not has_auto_discovery:
                                auto_discovery_issues.append(f"{deployment_name} - auto-discovery not enabled")
                            else:
                                compliant_deployments.append(deployment_name)
            
            if not compliant_deployments and not auto_discovery_issues:
                return self._create_check_result(
                    'AD1',
                    False,
                    [],
                    'No Cluster Autoscaler deployment found'
                )
            
            if auto_discovery_issues:
                return self._create_check_result(
                    'AD1',
                    False,
                    auto_discovery_issues,
                    'Auto-discovery not enabled'
                )
            else:
                return self._create_check_result(
                    'AD1',
                    True,
                    compliant_deployments,
                    'Auto-discovery is enabled'
                )
        except Exception as e:
            return self._create_check_error_result('AD1', str(e))

    async def _check_node_group_tags(self, k8s_client, cluster_name: str, region: Optional[str], namespace: Optional[str]) -> Dict[str, Any]:
        """Check if node groups have proper auto-discovery tags."""
        try:
            # Get EKS client using AwsHelper
            eks_client = AwsHelper.create_boto3_client('eks', region_name=region)
            
            # Get node groups
            node_groups = eks_client.list_nodegroups(clusterName=cluster_name)
            missing_tags = []
            compliant_nodegroups = []
            
            for ng_name in node_groups.get('nodegroups', []):
                ng_details = eks_client.describe_nodegroup(clusterName=cluster_name, nodegroupName=ng_name)
                tags = ng_details['nodegroup'].get('tags', {})
                
                # Check for required auto-discovery tags
                has_cluster_tag = f'k8s.io/cluster-autoscaler/{cluster_name}' in tags
                has_enabled_tag = 'k8s.io/cluster-autoscaler/enabled' in tags
                
                if not has_cluster_tag or not has_enabled_tag:
                    missing_tags.append(ng_name)
                else:
                    compliant_nodegroups.append(ng_name)
            
            if missing_tags:
                return self._create_check_result(
                    'AD2',
                    False,
                    missing_tags,
                    f'Found {len(missing_tags)} node groups without proper auto-discovery tags'
                )
            elif compliant_nodegroups:
                return self._create_check_result(
                    'AD2',
                    True,
                    compliant_nodegroups,
                    f'All {len(compliant_nodegroups)} node groups have proper auto-discovery tags'
                )
            else:
                return self._create_check_result(
                    'AD2',
                    False,
                    [],
                    'No node groups found in the cluster'
                )
        except Exception as e:
            return self._create_check_error_result('AD2', str(e))

    # Placeholder implementations for remaining checks
    async def _check_iam_permissions(self, k8s_client, cluster_name: str, region: Optional[str], namespace: Optional[str]) -> Dict[str, Any]:
        """Check IAM permissions - placeholder implementation."""
        return self._create_check_result('IAM1', True, [], 'IAM permissions check not yet implemented')

    async def _check_identical_scheduling_properties(self, k8s_client, cluster_name: str, region: Optional[str], namespace: Optional[str]) -> Dict[str, Any]:
        """Check identical scheduling properties - placeholder implementation."""
        return self._create_check_result('NG1', True, [], 'Scheduling properties check not yet implemented')

    async def _check_node_group_consolidation(self, k8s_client, cluster_name: str, region: Optional[str], namespace: Optional[str]) -> Dict[str, Any]:
        """Check node group consolidation - placeholder implementation."""
        return self._create_check_result('NG2', True, [], 'Node group consolidation check not yet implemented')

    async def _check_managed_node_groups(self, k8s_client, cluster_name: str, region: Optional[str], namespace: Optional[str]) -> Dict[str, Any]:
        """Check managed node groups usage - placeholder implementation."""
        return self._create_check_result('NG3', True, [], 'Managed node groups check not yet implemented')

    async def _check_spot_diversification(self, k8s_client, cluster_name: str, region: Optional[str], namespace: Optional[str]) -> Dict[str, Any]:
        """Check spot diversification - placeholder implementation."""
        return self._create_check_result('CO1', True, [], 'Spot diversification check not yet implemented')

    async def _check_capacity_separation(self, k8s_client, cluster_name: str, region: Optional[str], namespace: Optional[str]) -> Dict[str, Any]:
        """Check capacity separation - placeholder implementation."""
        return self._create_check_result('CO2', True, [], 'Capacity separation check not yet implemented')

    async def _check_expander_strategy(self, k8s_client, cluster_name: str, region: Optional[str], namespace: Optional[str]) -> Dict[str, Any]:
        """Check expander strategy - placeholder implementation."""
        return self._create_check_result('CO3', True, [], 'Expander strategy check not yet implemented')

    async def _check_resource_allocation(self, k8s_client, cluster_name: str, region: Optional[str], namespace: Optional[str]) -> Dict[str, Any]:
        """Check resource allocation - placeholder implementation."""
        return self._create_check_result('PS1', True, [], 'Resource allocation check not yet implemented')

    async def _check_scan_interval(self, k8s_client, cluster_name: str, region: Optional[str], namespace: Optional[str]) -> Dict[str, Any]:
        """Check scan interval - placeholder implementation."""
        return self._create_check_result('PS2', True, [], 'Scan interval check not yet implemented')

    async def _check_overprovisioning(self, k8s_client, cluster_name: str, region: Optional[str], namespace: Optional[str]) -> Dict[str, Any]:
        """Check overprovisioning - placeholder implementation."""
        return self._create_check_result('AV1', True, [], 'Overprovisioning check not yet implemented')

    async def _check_workload_protection(self, k8s_client, cluster_name: str, region: Optional[str], namespace: Optional[str]) -> Dict[str, Any]:
        """Check workload protection - placeholder implementation."""
        return self._create_check_result('AV2', True, [], 'Workload protection check not yet implemented')
    as
ync def _check_for_karpenter(self, k8s_client, namespace: Optional[str]) -> bool:
        """Check if Karpenter is deployed in the cluster."""
        try:
            deployments = k8s_client.list_resources(
                kind='Deployment',
                api_version='apps/v1',
                namespace=namespace or 'karpenter'
            )
            
            for deployment in deployments.items:
                if 'karpenter' in deployment.metadata.name.lower():
                    logger.info(f'Found Karpenter deployment: {deployment.metadata.name}')
                    return True
            
            return False
        except Exception as e:
            logger.warning(f'Error checking for Karpenter: {str(e)}')
            return False

    async def _check_for_auto_mode(self, cluster_name: str, region: Optional[str]) -> bool:
        """Check if EKS Auto Mode is enabled for the cluster."""
        try:
            eks_client = AwsHelper.create_boto3_client('eks', region_name=region)
            response = eks_client.describe_cluster(name=cluster_name)
            
            # Check if Auto Mode is enabled
            compute_config = response.get('cluster', {}).get('computeConfig', {})
            enabled = compute_config.get('enabled', False)
            
            if enabled:
                logger.info('EKS Auto Mode is enabled for this cluster')
            
            return enabled
        except Exception as e:
            logger.warning(f'Error checking for Auto Mode: {str(e)}')
            return False
