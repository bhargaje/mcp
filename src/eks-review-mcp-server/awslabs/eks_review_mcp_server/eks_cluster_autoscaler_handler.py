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
        return self.check_registry.get('cluster_autoscaler_checks', {})

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

            # Pre-initialize clients and fetch shared data for efficiency
            clients = await self._initialize_clients(cluster_name, region, namespace)
            if not clients:
                return self._create_error_response(cluster_name, "Failed to initialize required clients")

            # Get cluster and node group info once for sharing between checks
            shared_data = await self._get_cluster_and_nodegroup_info(
                clients['eks'], 
                clients['ec2'], 
                clients['autoscaling'], 
                clients['k8s'], 
                cluster_name, 
                namespace
            )
            if shared_data:
                clients['shared_data'] = shared_data
                logger.info(
                    f'Retrieved cluster info: version={shared_data.get("cluster_version")}, '
                    f'managed={shared_data.get("managed_count", 0)}, '
                    f'self-managed={shared_data.get("self_managed_count", 0)}, '
                    f'total={shared_data.get("total_node_groups", 0)}'
                )

            # First check if Cluster Autoscaler is deployed (C1 check)
            ca_deployment_result = await self._check_version_compatibility(clients, cluster_name, namespace)
            
            check_results = []
            all_compliant = True
            
            # Check if Cluster Autoscaler was found
            ca_found = ca_deployment_result['compliant'] or (
                ca_deployment_result['impacted_resources'] and 
                len(ca_deployment_result['impacted_resources']) > 0
            )
            
            # Early exit if Auto Mode is detected (optimization #4)
            if shared_data and shared_data.get('skip_ca_checks'):
                logger.info('Auto Mode detected - skipping Cluster Autoscaler checks')
                auto_mode_features = shared_data.get('auto_mode_features', {})
                enabled_features = [k for k, v in auto_mode_features.items() if v]
                
                check_results.append(self._create_check_result(
                    'C1',
                    True,
                    [],
                    f'EKS Auto Mode is enabled ({", ".join(enabled_features)}) - Cluster Autoscaler checks not applicable'
                ))
                all_compliant = True
                
                passed_count = 1
                failed_count = 0
                summary = f'Cluster {cluster_name} uses EKS Auto Mode - Cluster Autoscaler checks not applicable'
                
                return ClusterAutoscalerCheckResponse(
                    isError=False,
                    content=[TextContent(type='text', text=summary)],
                    check_results=check_results,
                    overall_compliant=all_compliant,
                    summary=summary,
                )
            
            # If Cluster Autoscaler is deployed, run all checks
            if ca_found:
                logger.info('Cluster Autoscaler found - running Cluster Autoscaler best practices checks')
                
                # Add the version compatibility check result
                check_results.append(ca_deployment_result)
                
                # Get remaining checks (C2-C14) and sort by ID
                all_checks = self._get_all_checks()
                remaining_checks = {k: v for k, v in all_checks.items() if k != 'C1'}
                
                for check_id in sorted(remaining_checks.keys()):
                    try:
                        logger.info(f'Running check {check_id}')
                        result = await self._execute_check(check_id, clients, cluster_name, namespace)
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
                
                # Check if Karpenter or Auto Mode is being used (reuse shared_data)
                karpenter_found = await self._check_for_karpenter(clients['k8s'], namespace)
                auto_mode_enabled = await self._check_for_auto_mode(clients['eks'], cluster_name, shared_data)
                
                if karpenter_found or auto_mode_enabled:
                    alternative = 'Karpenter' if karpenter_found else 'EKS Auto Mode'
                    logger.info(f'{alternative} detected - Cluster Autoscaler checks not applicable')
                    check_results.append(self._create_check_result(
                        'C1',
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

    async def _initialize_clients(self, cluster_name: str, region: Optional[str], namespace: Optional[str]) -> Optional[Dict[str, Any]]:
        """Initialize all required clients for Cluster Autoscaler checks."""
        try:
            clients = {}
            
            # Initialize AWS EKS client
            try:
                clients['eks'] = AwsHelper.create_boto3_client('eks', region_name=region)
                logger.info('Successfully initialized EKS client')
            except Exception as e:
                logger.error(f'Failed to initialize EKS client: {str(e)}')
                return None
            
            # Initialize AWS EC2 client (for self-managed node groups)
            try:
                clients['ec2'] = AwsHelper.create_boto3_client('ec2', region_name=region)
                logger.info('Successfully initialized EC2 client')
            except Exception as e:
                logger.error(f'Failed to initialize EC2 client: {str(e)}')
                return None
            
            # Initialize AWS Auto Scaling client (for self-managed node groups)
            try:
                clients['autoscaling'] = AwsHelper.create_boto3_client('autoscaling', region_name=region)
                logger.info('Successfully initialized Auto Scaling client')
            except Exception as e:
                logger.error(f'Failed to initialize Auto Scaling client: {str(e)}')
                return None
            
            # Initialize Kubernetes client
            try:
                clients['k8s'] = self.client_cache.get_client(cluster_name)
                logger.info('Successfully initialized Kubernetes client')
            except Exception as e:
                logger.error(f'Failed to initialize Kubernetes client: {str(e)}')
                return None
            
            return clients
            
        except Exception as e:
            logger.error(f'Error initializing clients: {str(e)}')
            return None

    async def _get_cluster_and_nodegroup_info(self, eks_client, ec2_client, autoscaling_client, k8s_client, cluster_name: str, namespace: Optional[str]) -> Optional[Dict[str, Any]]:
        """Fetch cluster and all node group details (managed + self-managed) once for sharing between checks."""
        try:
            shared_data = {}
            
            # Get cluster info (single API call - reused throughout)
            try:
                cluster_response = eks_client.describe_cluster(name=cluster_name)
                cluster_info = cluster_response['cluster']
                shared_data['cluster_version'] = cluster_info['version']
                shared_data['cluster_info'] = cluster_info  # Store full cluster object for reuse
                logger.info(f'Cluster version: {shared_data["cluster_version"]}')
                
                # Check for Auto Mode early (optimization #4)
                compute_config = cluster_info.get('computeConfig', {})
                storage_config = cluster_info.get('storageConfig', {})
                kubernetes_network_config = cluster_info.get('kubernetesNetworkConfig', {})
                elastic_load_balancing = kubernetes_network_config.get('elasticLoadBalancing', {})
                
                is_auto_mode = (
                    compute_config.get('enabled', False) or
                    storage_config.get('blockStorage', {}).get('enabled', False) or
                    elastic_load_balancing.get('enabled', False)
                )
                
                shared_data['is_auto_mode'] = is_auto_mode
                
                if is_auto_mode:
                    logger.info('EKS Auto Mode detected - Cluster Autoscaler checks not applicable')
                    shared_data['skip_ca_checks'] = True
                    shared_data['auto_mode_features'] = {
                        'compute_enabled': compute_config.get('enabled', False),
                        'storage_enabled': storage_config.get('blockStorage', {}).get('enabled', False),
                        'elastic_load_balancing_enabled': elastic_load_balancing.get('enabled', False)
                    }
                    # Early exit - no need to fetch node groups for Auto Mode
                    return shared_data
                    
            except Exception as e:
                logger.warning(f'Failed to get cluster info: {str(e)}')
                shared_data['cluster_version'] = None
                shared_data['cluster_info'] = None
                shared_data['is_auto_mode'] = False
            
            # Get all EKS managed node groups (optimization #5: extract only needed fields)
            managed_node_groups = []
            managed_asg_names = set()
            try:
                ng_list = eks_client.list_nodegroups(clusterName=cluster_name)
                node_group_names = ng_list.get('nodegroups', [])
                logger.info(f'Found {len(node_group_names)} EKS managed node groups')
                
                # Fetch details for all managed node groups
                for ng_name in node_group_names:
                    try:
                        ng_details = eks_client.describe_nodegroup(
                            clusterName=cluster_name,
                            nodegroupName=ng_name
                        )
                        nodegroup = ng_details['nodegroup']
                        
                        # Extract only needed fields (optimization #5)
                        managed_node_groups.append({
                            'type': 'managed',
                            'name': ng_name,
                            'tags': nodegroup.get('tags', {}),
                            'capacity_type': nodegroup.get('capacityType'),
                            'instance_types': nodegroup.get('instanceTypes', []),
                            'scaling_config': nodegroup.get('scalingConfig', {}),
                            'labels': nodegroup.get('labels', {}),
                            'taints': nodegroup.get('taints', []),
                            'ami_type': nodegroup.get('amiType'),
                            'node_role': nodegroup.get('nodeRole'),
                            'resources': nodegroup.get('resources', {})
                        })
                        
                        # Track managed ASG names to exclude them from self-managed list
                        resources = nodegroup.get('resources', {})
                        for asg in resources.get('autoScalingGroups', []):
                            managed_asg_names.add(asg.get('name'))
                            
                    except Exception as ng_error:
                        logger.warning(f'Failed to get details for managed node group {ng_name}: {str(ng_error)}')
                
            except Exception as e:
                logger.warning(f'Failed to get managed node groups: {str(e)}')
            
            # Get self-managed node groups using Kubernetes + EC2 approach (networking handler pattern)
            self_managed_node_groups = []
            try:
                # Step 1: Get all nodes from Kubernetes (works for all node types)
                nodes = k8s_client.list_resources(kind='Node', api_version='v1')
                logger.info(f'Found {len(nodes.items)} total nodes in cluster')
                
                # Step 2: Extract instance IDs from node labels
                instance_ids = []
                for node in nodes.items:
                    node_dict = node.to_dict() if hasattr(node, 'to_dict') else node
                    labels = node_dict.get('metadata', {}).get('labels', {})
                    instance_id = labels.get('node.kubernetes.io/instance-id')
                    if instance_id:
                        instance_ids.append(instance_id)
                
                logger.info(f'Extracted {len(instance_ids)} instance IDs from nodes')
                
                # Step 3: Query EC2 for instance details with pagination (optimization #6)
                if instance_ids:
                    asg_names = set()
                    
                    # Use paginator for large clusters (optimization #6)
                    paginator = ec2_client.get_paginator('describe_instances')
                    page_iterator = paginator.paginate(InstanceIds=instance_ids)
                    
                    # Extract ASG names from instances
                    for page in page_iterator:
                        for reservation in page['Reservations']:
                            for instance in reservation['Instances']:
                                for tag in instance.get('Tags', []):
                                    if tag['Key'] == 'aws:autoscaling:groupName':
                                        asg_names.add(tag['Value'])
                                        break
                    
                    logger.info(f'Found {len(asg_names)} total ASGs from instance tags')
                    
                    # Step 4: Filter out managed ASGs to get only self-managed
                    self_managed_asg_names = asg_names - managed_asg_names
                    logger.info(f'Identified {len(self_managed_asg_names)} self-managed ASGs')
                    
                    # Step 5: Query Auto Scaling API for self-managed ASG details
                    if self_managed_asg_names:
                        asgs_response = autoscaling_client.describe_auto_scaling_groups(
                            AutoScalingGroupNames=list(self_managed_asg_names)
                        )
                        
                        for asg in asgs_response['AutoScalingGroups']:
                            tags = {tag['Key']: tag['Value'] for tag in asg.get('Tags', [])}
                            
                            self_managed_node_groups.append({
                                'type': 'self_managed',
                                'name': asg['AutoScalingGroupName'],
                                'details': asg,
                                'tags': tags,
                                'has_ca_enabled': tags.get('k8s.io/cluster-autoscaler/enabled') == 'true',
                                'has_ca_cluster_tag': f'k8s.io/cluster-autoscaler/{cluster_name}' in tags
                            })
                        
                        logger.info(f'Retrieved details for {len(self_managed_node_groups)} self-managed ASGs')
                
            except Exception as e:
                logger.warning(f'Failed to get self-managed node groups: {str(e)}')
                import traceback
                logger.warning(f'Traceback: {traceback.format_exc()}')
            
            # Store both types of node groups
            shared_data['managed_node_groups'] = managed_node_groups
            shared_data['self_managed_node_groups'] = self_managed_node_groups
            shared_data['node_groups'] = managed_node_groups  # For backward compatibility with C3 check
            shared_data['all_node_groups'] = managed_node_groups + self_managed_node_groups
            shared_data['managed_count'] = len(managed_node_groups)
            shared_data['self_managed_count'] = len(self_managed_node_groups)
            shared_data['total_node_groups'] = len(managed_node_groups) + len(self_managed_node_groups)
            
            logger.info(f'Node group summary: {len(managed_node_groups)} managed, {len(self_managed_node_groups)} self-managed, {shared_data["total_node_groups"]} total')
            
            # Get Cluster Autoscaler deployment info and parse configuration (optimization #2)
            try:
                deployments = k8s_client.list_resources(
                    kind='Deployment',
                    api_version='apps/v1',
                    namespace=namespace or 'kube-system'
                )
                
                ca_deployments = []
                ca_config = {
                    'auto_discovery_enabled': False,
                    'expander_strategy': None,
                    'scan_interval': None,
                    'scale_down_enabled': True,
                    'scale_down_delay_after_add': None,
                    'scale_down_unneeded_time': None,
                    'resource_limits': {},
                    'resource_requests': {},
                    'command_args': [],
                    'env_vars': {}
                }
                
                for deployment in deployments.items:
                    if 'cluster-autoscaler' in deployment.metadata.name.lower():
                        ca_deployments.append({
                            'name': deployment.metadata.name,
                            'namespace': deployment.metadata.namespace,
                            'deployment': deployment
                        })
                        
                        # Pre-extract CA configuration (optimization #2)
                        containers = deployment.spec.template.spec.get('containers', [])
                        for container in containers:
                            if 'cluster-autoscaler' in container.get('name', '').lower():
                                # Parse command args
                                command = container.get('command', [])
                                args = container.get('args', [])
                                all_args = command + args
                                ca_config['command_args'] = all_args
                                
                                # Extract key settings
                                for arg in all_args:
                                    arg_str = str(arg)
                                    if '--node-group-auto-discovery' in arg_str:
                                        ca_config['auto_discovery_enabled'] = True
                                    elif '--expander=' in arg_str:
                                        ca_config['expander_strategy'] = arg_str.split('=', 1)[1] if '=' in arg_str else None
                                    elif '--scan-interval=' in arg_str:
                                        ca_config['scan_interval'] = arg_str.split('=', 1)[1] if '=' in arg_str else None
                                    elif '--scale-down-enabled=' in arg_str:
                                        ca_config['scale_down_enabled'] = arg_str.split('=', 1)[1].lower() == 'true' if '=' in arg_str else True
                                    elif '--scale-down-delay-after-add=' in arg_str:
                                        ca_config['scale_down_delay_after_add'] = arg_str.split('=', 1)[1] if '=' in arg_str else None
                                    elif '--scale-down-unneeded-time=' in arg_str:
                                        ca_config['scale_down_unneeded_time'] = arg_str.split('=', 1)[1] if '=' in arg_str else None
                                
                                # Extract resource limits and requests
                                resources = container.get('resources', {})
                                ca_config['resource_limits'] = resources.get('limits', {})
                                ca_config['resource_requests'] = resources.get('requests', {})
                                
                                # Extract environment variables
                                env_vars = container.get('env', [])
                                for env_var in env_vars:
                                    ca_config['env_vars'][env_var.get('name')] = env_var.get('value')
                
                shared_data['ca_deployments'] = ca_deployments
                shared_data['ca_config'] = ca_config  # Pre-parsed configuration
                logger.info(f'Found {len(ca_deployments)} Cluster Autoscaler deployments')
                logger.info(f'CA config: auto_discovery={ca_config["auto_discovery_enabled"]}, expander={ca_config["expander_strategy"]}, scan_interval={ca_config["scan_interval"]}')
                
            except Exception as e:
                logger.warning(f'Failed to get Cluster Autoscaler deployments: {str(e)}')
                shared_data['ca_deployments'] = []
                shared_data['ca_config'] = {}
            
            return shared_data
            
        except Exception as e:
            logger.warning(f'Failed to get cluster and node group info: {str(e)}')
            import traceback
            logger.warning(f'Traceback: {traceback.format_exc()}')
            return None

    async def _execute_check(self, check_id: str, clients: Dict[str, Any], cluster_name: str, namespace: Optional[str]) -> Dict[str, Any]:
        """Execute a single check based on its ID."""
        
        # Map check IDs to their corresponding methods
        check_methods = {
            'C1': self._check_version_compatibility,
            'C2': self._check_auto_discovery_enabled,
            'C3': self._check_node_group_tags,
            'C4': self._check_iam_permissions,
            'C5': self._check_identical_scheduling_properties,
            'C6': self._check_node_group_consolidation,
            'C7': self._check_managed_node_groups,
            'C8': self._check_spot_diversification,
            'C9': self._check_capacity_separation,
            'C10': self._check_expander_strategy,
            'C11': self._check_resource_allocation,
            'C12': self._check_scan_interval,
            'C13': self._check_overprovisioning,
            'C14': self._check_workload_protection,
        }
        
        method = check_methods.get(check_id)
        if method:
            return await method(clients, cluster_name, namespace)
        else:
            return self._create_check_error_result(check_id, f'Check method not implemented for {check_id}')

    async def _check_version_compatibility(self, clients: Dict[str, Any], cluster_name: str, namespace: Optional[str]) -> Dict[str, Any]:
        """Check if Cluster Autoscaler version matches cluster version."""
        try:
            # Use shared data if available
            shared_data = clients.get('shared_data', {})
            cluster_version = shared_data.get('cluster_version')
            ca_deployments = shared_data.get('ca_deployments', [])
            
            if not cluster_version:
                return self._create_check_error_result('C1', 'Failed to get cluster version')
            
            if not ca_deployments:
                # Fallback: try to fetch deployments directly
                k8s_client = clients.get('k8s')
                if not k8s_client:
                    return self._create_check_error_result('C1', 'Kubernetes client not available')
                
                deployments = k8s_client.list_resources(
                    kind='Deployment',
                    api_version='apps/v1',
                    namespace=namespace or 'kube-system'
                )
                
                ca_deployments = []
                for deployment in deployments.items:
                    if 'cluster-autoscaler' in deployment.metadata.name.lower():
                        ca_deployments.append({
                            'name': deployment.metadata.name,
                            'namespace': deployment.metadata.namespace,
                            'deployment': deployment
                        })
            
            version_issues = []
            compliant_deployments = []
            
            for ca_dep in ca_deployments:
                deployment = ca_dep['deployment']
                deployment_name = f"{ca_dep['namespace']}/{ca_dep['name']}"
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
                    'C1',
                    False,
                    [],
                    'No Cluster Autoscaler deployment found'
                )
            
            if version_issues:
                return self._create_check_result(
                    'C1',
                    False,
                    version_issues,
                    f'Version mismatch detected. Cluster version: {cluster_version}'
                )
            else:
                return self._create_check_result(
                    'C1',
                    True,
                    compliant_deployments,
                    f'Cluster Autoscaler version matches cluster version {cluster_version}'
                )
        except Exception as e:
            return self._create_check_error_result('C1', str(e))

    async def _check_auto_discovery_enabled(self, clients: Dict[str, Any], cluster_name: str, namespace: Optional[str]) -> Dict[str, Any]:
        """Check if auto-discovery is enabled."""
        try:
            # Use shared data if available
            shared_data = clients.get('shared_data', {})
            ca_deployments = shared_data.get('ca_deployments', [])
            
            if not ca_deployments:
                # Fallback: try to fetch deployments directly
                k8s_client = clients.get('k8s')
                if not k8s_client:
                    return self._create_check_error_result('C2', 'Kubernetes client not available')
                
                deployments = k8s_client.list_resources(
                    kind='Deployment',
                    api_version='apps/v1',
                    namespace=namespace or 'kube-system'
                )
                
                ca_deployments = []
                for deployment in deployments.items:
                    if 'cluster-autoscaler' in deployment.metadata.name.lower():
                        ca_deployments.append({
                            'name': deployment.metadata.name,
                            'namespace': deployment.metadata.namespace,
                            'deployment': deployment
                        })
            
            auto_discovery_issues = []
            compliant_deployments = []
            
            for ca_dep in ca_deployments:
                deployment = ca_dep['deployment']
                deployment_name = f"{ca_dep['namespace']}/{ca_dep['name']}"
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
                    'C2',
                    False,
                    [],
                    'No Cluster Autoscaler deployment found'
                )
            
            if auto_discovery_issues:
                return self._create_check_result(
                    'C2',
                    False,
                    auto_discovery_issues,
                    'Auto-discovery not enabled'
                )
            else:
                return self._create_check_result(
                    'C2',
                    True,
                    compliant_deployments,
                    'Auto-discovery is enabled'
                )
        except Exception as e:
            return self._create_check_error_result('C2', str(e))

    async def _check_node_group_tags(self, clients: Dict[str, Any], cluster_name: str, namespace: Optional[str]) -> Dict[str, Any]:
        """Check if node groups have proper auto-discovery tags (both managed and self-managed)."""
        try:
            # Use shared data if available
            shared_data = clients.get('shared_data', {})
            managed_node_groups = shared_data.get('managed_node_groups', [])
            self_managed_node_groups = shared_data.get('self_managed_node_groups', [])
            
            total_node_groups = len(managed_node_groups) + len(self_managed_node_groups)
            
            if total_node_groups == 0:
                return self._create_check_result(
                    'C3',
                    False,
                    [],
                    'No node groups found in the cluster'
                )
            
            missing_tags = []
            compliant_nodegroups = []
            
            # Check managed node groups (optimization #5: using extracted fields)
            for ng in managed_node_groups:
                ng_name = ng.get('name', 'unknown')
                tags = ng.get('tags', {})
                
                # Check for required auto-discovery tags
                has_cluster_tag = f'k8s.io/cluster-autoscaler/{cluster_name}' in tags
                has_enabled_tag = 'k8s.io/cluster-autoscaler/enabled' in tags
                
                if not has_cluster_tag or not has_enabled_tag:
                    missing_tags.append(f'Managed: {ng_name}')
                else:
                    compliant_nodegroups.append(f'Managed: {ng_name}')
            
            # Check self-managed node groups (ASGs)
            for ng in self_managed_node_groups:
                ng_name = ng.get('name', 'unknown')
                tags = ng.get('tags', {})
                
                # Check for required auto-discovery tags
                has_cluster_tag = f'k8s.io/cluster-autoscaler/{cluster_name}' in tags
                has_enabled_tag = tags.get('k8s.io/cluster-autoscaler/enabled') == 'true'
                
                if not has_cluster_tag or not has_enabled_tag:
                    missing_tags.append(f'Self-managed: {ng_name}')
                else:
                    compliant_nodegroups.append(f'Self-managed: {ng_name}')
            
            if missing_tags:
                return self._create_check_result(
                    'C3',
                    False,
                    missing_tags,
                    f'Found {len(missing_tags)} node groups without proper auto-discovery tags (out of {total_node_groups} total)'
                )
            else:
                return self._create_check_result(
                    'C3',
                    True,
                    compliant_nodegroups,
                    f'All {len(compliant_nodegroups)} node groups have proper auto-discovery tags ({len(managed_node_groups)} managed, {len(self_managed_node_groups)} self-managed)'
                )
        except Exception as e:
            return self._create_check_error_result('C3', str(e))

    # Placeholder implementations for remaining checks
    async def _check_iam_permissions(self, clients: Dict[str, Any], cluster_name: str, namespace: Optional[str]) -> Dict[str, Any]:
        """Check IAM permissions - placeholder implementation."""
        return self._create_check_result('C4', True, [], 'IAM permissions check not yet implemented')

    async def _check_identical_scheduling_properties(self, clients: Dict[str, Any], cluster_name: str, namespace: Optional[str]) -> Dict[str, Any]:
        """Check identical scheduling properties - placeholder implementation."""
        return self._create_check_result('C5', True, [], 'Scheduling properties check not yet implemented')

    async def _check_node_group_consolidation(self, clients: Dict[str, Any], cluster_name: str, namespace: Optional[str]) -> Dict[str, Any]:
        """Check node group consolidation - placeholder implementation."""
        return self._create_check_result('C6', True, [], 'Node group consolidation check not yet implemented')

    async def _check_managed_node_groups(self, clients: Dict[str, Any], cluster_name: str, namespace: Optional[str]) -> Dict[str, Any]:
        """Check managed node groups usage - placeholder implementation."""
        return self._create_check_result('C7', True, [], 'Managed node groups check not yet implemented')

    async def _check_spot_diversification(self, clients: Dict[str, Any], cluster_name: str, namespace: Optional[str]) -> Dict[str, Any]:
        """Check spot diversification - placeholder implementation."""
        return self._create_check_result('C8', True, [], 'Spot diversification check not yet implemented')

    async def _check_capacity_separation(self, clients: Dict[str, Any], cluster_name: str, namespace: Optional[str]) -> Dict[str, Any]:
        """Check capacity separation - placeholder implementation."""
        return self._create_check_result('C9', True, [], 'Capacity separation check not yet implemented')

    async def _check_expander_strategy(self, clients: Dict[str, Any], cluster_name: str, namespace: Optional[str]) -> Dict[str, Any]:
        """Check expander strategy - placeholder implementation."""
        return self._create_check_result('C10', True, [], 'Expander strategy check not yet implemented')

    async def _check_resource_allocation(self, clients: Dict[str, Any], cluster_name: str, namespace: Optional[str]) -> Dict[str, Any]:
        """Check resource allocation - placeholder implementation."""
        return self._create_check_result('C11', True, [], 'Resource allocation check not yet implemented')

    async def _check_scan_interval(self, clients: Dict[str, Any], cluster_name: str, namespace: Optional[str]) -> Dict[str, Any]:
        """Check scan interval - placeholder implementation."""
        return self._create_check_result('C12', True, [], 'Scan interval check not yet implemented')

    async def _check_overprovisioning(self, clients: Dict[str, Any], cluster_name: str, namespace: Optional[str]) -> Dict[str, Any]:
        """Check overprovisioning - placeholder implementation."""
        return self._create_check_result('C13', True, [], 'Overprovisioning check not yet implemented')

    async def _check_workload_protection(self, clients: Dict[str, Any], cluster_name: str, namespace: Optional[str]) -> Dict[str, Any]:
        """Check workload protection - placeholder implementation."""
        return self._create_check_result('C14', True, [], 'Workload protection check not yet implemented')

    async def _check_for_karpenter(self, k8s_client, namespace: Optional[str]) -> bool:
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

    async def _check_for_auto_mode(self, eks_client, cluster_name: str, shared_data: Optional[Dict[str, Any]] = None) -> bool:
        """Check if EKS Auto Mode is enabled for the cluster (optimization #1: reuse cluster_info)."""
        try:
            # Reuse cluster_info if available (optimization #1)
            if shared_data and shared_data.get('cluster_info'):
                cluster_info = shared_data['cluster_info']
                logger.info('Reusing cached cluster info for Auto Mode check')
            else:
                response = eks_client.describe_cluster(name=cluster_name)
                cluster_info = response.get('cluster', {})
            
            # Check if Auto Mode is enabled
            compute_config = cluster_info.get('computeConfig', {})
            enabled = compute_config.get('enabled', False)
            
            if enabled:
                logger.info('EKS Auto Mode is enabled for this cluster')
            
            return enabled
        except Exception as e:
            logger.warning(f'Error checking for Auto Mode: {str(e)}')
            return False
