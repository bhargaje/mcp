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

"""Handler for EKS security checks in the EKS MCP Server."""

import json
from pathlib import Path
from awslabs.eks_review_mcp_server.aws_helper import AwsHelper
from awslabs.eks_review_mcp_server.logging_helper import LogLevel, log_with_request_id
from awslabs.eks_review_mcp_server.models import SecurityCheckResponse
from collections import Counter
from loguru import logger
from mcp.server.fastmcp import Context
from mcp.types import TextContent
from pydantic import Field
from typing import Any, Dict, Optional, List


class EKSSecurityHandler:
    """Handler for EKS security checks in the EKS MCP Server."""

    def __init__(self, mcp, client_cache):
        """Initialize the EKS security handler.

        Args:
            mcp: The MCP server instance
            client_cache: K8sClientCache instance to share between handlers
        """
        self.mcp = mcp
        self.client_cache = client_cache
        self.check_registry = self._load_check_registry()

        # Register the comprehensive check tool
        self.mcp.tool(name='check_eks_security')(self.check_eks_security)

    def _load_check_registry(self) -> Dict[str, Any]:
        """Load check definitions from JSON file."""
        try:
            config_path = Path(__file__).parent / 'data' / 'eks_security_checks.json'
            with open(config_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load check registry: {e}")
            return {}

    def _get_all_checks(self) -> Dict[str, Dict[str, Any]]:
        """Get all checks flattened into a single dictionary."""
        all_checks = {}
        for category in ['iam_checks']:
            all_checks.update(self.check_registry.get(category, {}))
        return all_checks

    def _get_check_info(self, check_id: str) -> Dict[str, Any]:
        """Get check information by ID."""
        all_checks = self._get_all_checks()
        return all_checks.get(check_id, {})

    def _get_remediation(self, check_id: str) -> str:
        """Get remediation guidance for a check."""
        check_info = self._get_check_info(check_id)
        return check_info.get('recommendation', '')

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

    def _create_error_response(self, cluster_name: str, error_msg: str) -> SecurityCheckResponse:
        """Create an error response."""
        return SecurityCheckResponse(
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

    async def check_eks_security(
        self,
        ctx: Context,
        cluster_name: str = Field(
            ..., description='Name of the EKS cluster to check for security best practices.'
        ),
        namespace: Optional[str] = Field(
            None, description='Optional namespace to limit the check scope.'
        ),
    ) -> SecurityCheckResponse:
        """Check EKS cluster for security best practices.

        This tool runs a comprehensive set of security checks against your EKS cluster
        to identify potential security issues and provides remediation guidance.

        The tool evaluates critical security best practices across IAM and access control:
        - IAM Related Checks: Cluster access management, endpoint security, and authentication
        """
        try:
            logger.info(f'Starting security check for cluster: {cluster_name}')

            # Get K8s client for the cluster
            try:
                client = self.client_cache.get_client(cluster_name)
                logger.info(f'Successfully obtained K8s client for cluster: {cluster_name}')
            except Exception as e:
                logger.error(f'Failed to get K8s client for cluster {cluster_name}: {str(e)}')
                return self._create_error_response(cluster_name, str(e))

            # Run all checks
            check_results = []
            all_compliant = True
            
            # Get all checks and sort by ID for consistent execution order
            all_checks = self._get_all_checks()
            
            for check_id in sorted(all_checks.keys()):
                try:
                    logger.info(f'Running check {check_id}')
                    result = await self._execute_check(check_id, client, cluster_name, namespace)
                    check_results.append(result)
                    
                    if not result['compliant']:
                        all_compliant = False
                        
                    logger.info(f'Check {check_id} completed: {result["compliant"]}')
                    
                except Exception as e:
                    logger.error(f'Error in check {check_id}: {str(e)}')
                    error_result = self._create_check_error_result(check_id, str(e))
                    check_results.append(error_result)
                    all_compliant = False

            # Generate summary
            passed_count = sum(1 for r in check_results if r['compliant'])
            failed_count = len(check_results) - passed_count
            summary = f'Cluster {cluster_name} security check: {passed_count} checks passed, {failed_count} checks failed'

            return SecurityCheckResponse(
                isError=False,
                content=[TextContent(type='text', text=summary)],
                check_results=check_results,
                overall_compliant=all_compliant,
                summary=summary,
            )

        except Exception as e:
            logger.error(f'Unexpected error in security check: {str(e)}')
            return self._create_error_response(cluster_name, str(e))

    async def _execute_check(self, check_id: str, client, cluster_name: str, namespace: Optional[str]) -> Dict[str, Any]:
        """Execute a single check based on its ID."""
        
        # Map check IDs to their corresponding methods
        check_methods = {
            'IAM1': self._check_cluster_access_manager,
            'IAM2': self._check_private_endpoint,
            'IAM3': self._check_service_account_tokens,
            'IAM4': self._check_least_privileged_rbac,
            'IAM5': self._check_pod_identity,
            'IAM6': self._check_imdsv2_enforcement,
            'IAM7': self._check_non_root_user,
            'IAM8': self._check_irsa_configuration,
        }
        
        method = check_methods.get(check_id)
        if method:
            return await method(client, cluster_name, namespace)
        else:
            return self._create_check_error_result(check_id, f'Check method not implemented for {check_id}')

    async def _check_cluster_access_manager(self, client, cluster_name: str, namespace: Optional[str]) -> Dict[str, Any]:
        """Check if EKS Cluster Access Manager is configured."""
        try:
            import boto3
            eks_client = boto3.client('eks')
            
            # Get cluster configuration
            response = eks_client.describe_cluster(name=cluster_name)
            cluster = response['cluster']
            
            # Check authentication mode
            access_config = cluster.get('accessConfig', {})
            auth_mode = access_config.get('authenticationMode', 'CONFIG_MAP')
            
            if auth_mode in ['API', 'API_AND_CONFIG_MAP']:
                return self._create_check_result(
                    'IAM1',
                    True,
                    [],
                    f'Cluster uses {auth_mode} authentication mode'
                )
            else:
                return self._create_check_result(
                    'IAM1',
                    False,
                    [cluster_name],
                    f'Cluster uses {auth_mode} authentication mode, should use API or API_AND_CONFIG_MAP'
                )
        except Exception as e:
            return self._create_check_error_result('IAM1', str(e))

    async def _check_private_endpoint(self, client, cluster_name: str, namespace: Optional[str]) -> Dict[str, Any]:
        """Check if EKS cluster endpoint is private."""
        try:
            import boto3
            eks_client = boto3.client('eks')
            
            # Get cluster configuration
            response = eks_client.describe_cluster(name=cluster_name)
            cluster = response['cluster']
            
            # Check endpoint configuration
            vpc_config = cluster.get('resourcesVpcConfig', {})
            public_access = vpc_config.get('endpointPublicAccess', True)
            private_access = vpc_config.get('endpointPrivateAccess', False)
            
            if not public_access and private_access:
                return self._create_check_result(
                    'IAM2',
                    True,
                    [],
                    'Cluster endpoint is private only'
                )
            elif public_access and private_access:
                return self._create_check_result(
                    'IAM2',
                    False,
                    [cluster_name],
                    'Cluster endpoint allows both public and private access'
                )
            else:
                return self._create_check_result(
                    'IAM2',
                    False,
                    [cluster_name],
                    'Cluster endpoint is public only'
                )
        except Exception as e:
            return self._create_check_error_result('IAM2', str(e))

    async def _check_service_account_tokens(self, client, cluster_name: str, namespace: Optional[str]) -> Dict[str, Any]:
        """Check for service account token usage."""
        try:
            # Use the K8sApis client to list service accounts
            if namespace:
                service_accounts = client.list_resources(
                    kind='ServiceAccount',
                    api_version='v1',
                    namespace=namespace
                )
            else:
                service_accounts = client.list_resources(
                    kind='ServiceAccount',
                    api_version='v1'
                )
            
            non_compliant_sa = []
            for sa in service_accounts.items:
                # Check if automountServiceAccountToken is explicitly set to True or not set (defaults to True)
                automount = sa.get('automountServiceAccountToken')
                if automount is None or automount:
                    sa_name = sa.metadata.name
                    sa_namespace = sa.metadata.namespace
                    non_compliant_sa.append(f"{sa_namespace}/{sa_name}")
            
            if non_compliant_sa:
                return self._create_check_result(
                    'IAM3',
                    False,
                    non_compliant_sa,
                    f'Found {len(non_compliant_sa)} service accounts with automountServiceAccountToken enabled'
                )
            else:
                return self._create_check_result(
                    'IAM3',
                    True,
                    [],
                    'All service accounts have automountServiceAccountToken disabled'
                )
                
        except Exception as e:
            return self._create_check_error_result('IAM3', str(e))

    async def _check_least_privileged_rbac(self, client, cluster_name: str, namespace: Optional[str]) -> Dict[str, Any]:
        """Check for overly permissive RoleBindings and ClusterRoleBindings."""
        try:
            # Check ClusterRoles and Roles for wildcard permissions
            cluster_roles = client.list_resources(kind='ClusterRole', api_version='rbac.authorization.k8s.io/v1')
            roles = client.list_resources(kind='Role', api_version='rbac.authorization.k8s.io/v1', namespace=namespace) if namespace else client.list_resources(kind='Role', api_version='rbac.authorization.k8s.io/v1')
            
            overly_permissive = []
            all_roles = []
            
            if cluster_roles and hasattr(cluster_roles, 'items'):
                all_roles.extend(cluster_roles.items)
            if roles and hasattr(roles, 'items'):
                all_roles.extend(roles.items)
            
            for role in all_roles:
                if not role or not hasattr(role, 'metadata'):
                    continue
                    
                role_name = role.metadata.name
                role_namespace = getattr(role.metadata, 'namespace', 'cluster-wide')
                rules = getattr(role, 'rules', None) or []
                
                for rule in rules:
                    if not rule:
                        continue
                    verbs = rule.get('verbs', []) or []
                    resources = rule.get('resources', []) or []
                    api_groups = rule.get('apiGroups', []) or []
                    
                    if '*' in verbs or '*' in resources or '*' in api_groups:
                        overly_permissive.append(f"{role_namespace}/{role_name}")
                        break
            
            if overly_permissive:
                return self._create_check_result(
                    'IAM4',
                    False,
                    overly_permissive,
                    f'Found {len(overly_permissive)} roles with wildcard permissions'
                )
            else:
                return self._create_check_result(
                    'IAM4',
                    True,
                    [],
                    'All roles follow least privilege principle'
                )
        except Exception as e:
            return self._create_check_error_result('IAM4', str(e))

    async def _check_pod_identity(self, client, cluster_name: str, namespace: Optional[str]) -> Dict[str, Any]:
        """Check if EKS Pod Identity is configured."""
        try:
            import boto3
            eks_client = boto3.client('eks')
            
            # Check if pod identity agent addon is installed
            try:
                addons = eks_client.list_addons(clusterName=cluster_name)
                pod_identity_addon = 'eks-pod-identity-agent' in addons.get('addons', [])
                
                if pod_identity_addon:
                    return self._create_check_result(
                        'IAM5',
                        True,
                        [],
                        'EKS Pod Identity agent addon is installed'
                    )
                else:
                    return self._create_check_result(
                        'IAM5',
                        False,
                        [cluster_name],
                        'EKS Pod Identity agent addon is not installed'
                    )
            except Exception as e:
                return self._create_check_error_result('IAM5', str(e))
        except Exception as e:
            return self._create_check_error_result('IAM5', str(e))

    async def _check_imdsv2_enforcement(self, client, cluster_name: str, namespace: Optional[str]) -> Dict[str, Any]:
        """Check if IMDSv2 is enforced on worker nodes."""
        try:
            import boto3
            ec2_client = boto3.client('ec2')
            
            # Get node group instances
            eks_client = boto3.client('eks')
            node_groups = eks_client.list_nodegroups(clusterName=cluster_name)
            
            non_compliant_instances = []
            
            for ng_name in node_groups.get('nodegroups', []):
                ng_details = eks_client.describe_nodegroup(clusterName=cluster_name, nodegroupName=ng_name)
                
                # Check launch template or instance configuration
                launch_template = ng_details['nodegroup'].get('launchTemplate')
                if launch_template:
                    lt_response = ec2_client.describe_launch_template_versions(
                        LaunchTemplateId=launch_template['id'],
                        Versions=[launch_template.get('version', '$Latest')]
                    )
                    
                    for version in lt_response['LaunchTemplateVersions']:
                        metadata_options = version.get('LaunchTemplateData', {}).get('MetadataOptions', {})
                        if metadata_options.get('HttpTokens') != 'required':
                            non_compliant_instances.append(f"nodegroup/{ng_name}")
            
            if non_compliant_instances:
                return self._create_check_result(
                    'IAM6',
                    False,
                    non_compliant_instances,
                    f'Found {len(non_compliant_instances)} node groups without IMDSv2 enforcement'
                )
            else:
                return self._create_check_result(
                    'IAM6',
                    True,
                    [],
                    'All node groups enforce IMDSv2'
                )
        except Exception as e:
            return self._create_check_error_result('IAM6', str(e))

    async def _check_non_root_user(self, client, cluster_name: str, namespace: Optional[str]) -> Dict[str, Any]:
        """Check if pods run as non-root user."""
        try:
            # Get all pods and check their security context
            if namespace:
                pods = client.list_resources(kind='Pod', api_version='v1', namespace=namespace)
            else:
                pods = client.list_resources(kind='Pod', api_version='v1')
            
            root_pods = []
            
            for pod in pods.items:
                pod_name = pod.metadata.name
                pod_namespace = pod.metadata.namespace
                
                # Check pod-level security context
                security_context = pod.spec.get('securityContext', {})
                run_as_user = security_context.get('runAsUser')
                run_as_non_root = security_context.get('runAsNonRoot')
                
                # If runAsNonRoot is explicitly True, it's compliant
                if run_as_non_root:
                    continue
                    
                # If runAsUser is 0 or not set (defaults to root), it's non-compliant
                if run_as_user is None or run_as_user == 0:
                    root_pods.append(f"{pod_namespace}/{pod_name}")
            
            if root_pods:
                return self._create_check_result(
                    'IAM7',
                    False,
                    root_pods,
                    f'Found {len(root_pods)} pods running as root user'
                )
            else:
                return self._create_check_result(
                    'IAM7',
                    True,
                    [],
                    'All pods run as non-root user'
                )
        except Exception as e:
            return self._create_check_error_result('IAM7', str(e))

    async def _check_irsa_configuration(self, client, cluster_name: str, namespace: Optional[str]) -> Dict[str, Any]:
        """Check if IRSA is configured when Pod Identity is not available."""
        try:
            import boto3
            eks_client = boto3.client('eks')
            
            # First check if Pod Identity is enabled
            addons = eks_client.list_addons(clusterName=cluster_name)
            pod_identity_enabled = 'eks-pod-identity-agent' in addons.get('addons', [])
            
            if pod_identity_enabled:
                return self._create_check_result(
                    'IAM8',
                    True,
                    [],
                    'Pod Identity is enabled, IRSA check not required'
                )
            
            # Check if OIDC is configured
            cluster_info = eks_client.describe_cluster(name=cluster_name)
            oidc_issuer = cluster_info['cluster'].get('identity', {}).get('oidc', {}).get('issuer')
            
            if not oidc_issuer:
                return self._create_check_result(
                    'IAM8',
                    False,
                    [cluster_name],
                    'OIDC identity provider is not configured'
                )
            
            # Check service accounts for IRSA annotations
            if namespace:
                service_accounts = client.list_resources(kind='ServiceAccount', api_version='v1', namespace=namespace)
            else:
                service_accounts = client.list_resources(kind='ServiceAccount', api_version='v1')
            
            irsa_configured_sa = []
            for sa in service_accounts.items:
                annotations = sa.metadata.get('annotations', {})
                if 'eks.amazonaws.com/role-arn' in annotations:
                    sa_name = sa.metadata.name
                    sa_namespace = sa.metadata.namespace
                    irsa_configured_sa.append(f"{sa_namespace}/{sa_name}")
            
            if irsa_configured_sa:
                return self._create_check_result(
                    'IAM8',
                    True,
                    irsa_configured_sa,
                    f'Found {len(irsa_configured_sa)} service accounts with IRSA configured'
                )
            else:
                return self._create_check_result(
                    'IAM8',
                    False,
                    [],
                    'No service accounts found with IRSA configuration'
                )
        except Exception as e:
            return self._create_check_error_result('IAM8', str(e))



