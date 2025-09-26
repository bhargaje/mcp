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
        for category in ['iam_checks', 'pod_security', 'multi_tenancy', 'detective_controls', 'data_encryption_and_secrets_mgmt', 'infra_security']:
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
            'I1': self._check_cluster_access_manager,
            'I2': self._check_private_endpoint,
            'I3': self._check_service_account_tokens,
            'I4': self._check_least_privileged_rbac,
            'I5': self._check_pod_identity,
            'I6': self._check_imdsv2_enforcement,
            'I7': self._check_non_root_user,
            'I8': self._check_irsa_configuration,
            'P1': self._check_pod_security_standards,
            'P2': self._check_hostpath_usage,
            'P3': self._check_image_tags,
            'P4': self._check_privilege_escalation,
            'P5': self._check_readonly_filesystem,
            'P6': self._check_serviceaccount_token_mount,
            'M1': self._check_network_policies,
            'M2': self._check_namespace_quotas,
            'M3': self._check_node_isolation,
            'D1': self._check_control_plane_logs,
            'DE1': self._check_storage_encryption,
            'DE2': self._check_external_secrets,
            'IS1': self._check_private_subnets,
            'IS2': self._check_container_optimized_os,
            'IS3': self._check_worker_node_access,
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
                    'I1',
                    True,
                    [],
                    f'Cluster uses {auth_mode} authentication mode'
                )
            else:
                return self._create_check_result(
                    'I1',
                    False,
                    [cluster_name],
                    f'Cluster uses {auth_mode} authentication mode, should use API or API_AND_CONFIG_MAP'
                )
        except Exception as e:
            return self._create_check_error_result('I1', str(e))

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
                    'I2',
                    True,
                    [],
                    'Cluster endpoint is private only'
                )
            elif public_access and private_access:
                return self._create_check_result(
                    'I2',
                    False,
                    [cluster_name],
                    'Cluster endpoint allows both public and private access'
                )
            else:
                return self._create_check_result(
                    'I2',
                    False,
                    [cluster_name],
                    'Cluster endpoint is public only'
                )
        except Exception as e:
            return self._create_check_error_result('I2', str(e))

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
                    'I3',
                    False,
                    non_compliant_sa,
                    f'Found {len(non_compliant_sa)} service accounts with automountServiceAccountToken enabled'
                )
            else:
                return self._create_check_result(
                    'I3',
                    True,
                    [],
                    'All service accounts have automountServiceAccountToken disabled'
                )
                
        except Exception as e:
            return self._create_check_error_result('I3', str(e))

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
                    'I4',
                    False,
                    overly_permissive,
                    f'Found {len(overly_permissive)} roles with wildcard permissions'
                )
            else:
                return self._create_check_result(
                    'I4',
                    True,
                    [],
                    'All roles follow least privilege principle'
                )
        except Exception as e:
            return self._create_check_error_result('I4', str(e))

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
                        'I5',
                        True,
                        [],
                        'EKS Pod Identity agent addon is installed'
                    )
                else:
                    return self._create_check_result(
                        'I5',
                        False,
                        [cluster_name],
                        'EKS Pod Identity agent addon is not installed'
                    )
            except Exception as e:
                return self._create_check_error_result('I5', str(e))
        except Exception as e:
            return self._create_check_error_result('I5', str(e))

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
                    'I6',
                    False,
                    non_compliant_instances,
                    f'Found {len(non_compliant_instances)} node groups without IMDSv2 enforcement'
                )
            else:
                return self._create_check_result(
                    'I6',
                    True,
                    [],
                    'All node groups enforce IMDSv2'
                )
        except Exception as e:
            return self._create_check_error_result('I6', str(e))

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
                    'I7',
                    False,
                    root_pods,
                    f'Found {len(root_pods)} pods running as root user'
                )
            else:
                return self._create_check_result(
                    'I7',
                    True,
                    [],
                    'All pods run as non-root user'
                )
        except Exception as e:
            return self._create_check_error_result('I7', str(e))

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
                    'I8',
                    True,
                    [],
                    'Pod Identity is enabled, IRSA check not required'
                )
            
            # Check if OIDC is configured
            cluster_info = eks_client.describe_cluster(name=cluster_name)
            oidc_issuer = cluster_info['cluster'].get('identity', {}).get('oidc', {}).get('issuer')
            
            if not oidc_issuer:
                return self._create_check_result(
                    'I8',
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
                    'I8',
                    True,
                    irsa_configured_sa,
                    f'Found {len(irsa_configured_sa)} service accounts with IRSA configured'
                )
            else:
                return self._create_check_result(
                    'I8',
                    False,
                    [],
                    'No service accounts found with IRSA configuration'
                )
        except Exception as e:
            return self._create_check_error_result('I8', str(e))

    async def _check_pod_security_standards(self, client, cluster_name: str, namespace: Optional[str]) -> Dict[str, Any]:
        """Check if Pod Security Standards (PSS) and Pod Security Admission (PSA) is configured."""
        try:
            # Check for PSA labels on namespaces
            if namespace:
                namespaces = client.list_resources(kind='Namespace', api_version='v1', namespace=namespace)
            else:
                namespaces = client.list_resources(kind='Namespace', api_version='v1')
            
            non_compliant_ns = []
            psa_labels = ['pod-security.kubernetes.io/enforce', 'pod-security.kubernetes.io/audit', 'pod-security.kubernetes.io/warn']
            
            for ns in namespaces.items:
                ns_name = ns.metadata.name
                labels = ns.metadata.get('labels', {})
                
                # Check if any PSA labels are present
                has_psa = any(label in labels for label in psa_labels)
                if not has_psa and ns_name not in ['kube-system', 'kube-public', 'kube-node-lease']:
                    non_compliant_ns.append(ns_name)
            
            if non_compliant_ns:
                return self._create_check_result(
                    'P1',
                    False,
                    non_compliant_ns,
                    f'Found {len(non_compliant_ns)} namespaces without Pod Security Standards configured'
                )
            else:
                return self._create_check_result(
                    'P1',
                    True,
                    [],
                    'All namespaces have Pod Security Standards configured'
                )
        except Exception as e:
            return self._create_check_error_result('P1', str(e))

    async def _check_hostpath_usage(self, client, cluster_name: str, namespace: Optional[str]) -> Dict[str, Any]:
        """Check for hostPath volume usage."""
        try:
            if namespace:
                pods = client.list_resources(kind='Pod', api_version='v1', namespace=namespace)
            else:
                pods = client.list_resources(kind='Pod', api_version='v1')
            
            hostpath_pods = []
            
            for pod in pods.items:
                pod_name = pod.metadata.name
                pod_namespace = pod.metadata.namespace
                volumes = pod.spec.get('volumes', [])
                
                for volume in volumes:
                    if 'hostPath' in volume:
                        hostpath_pods.append(f"{pod_namespace}/{pod_name}")
                        break
            
            if hostpath_pods:
                return self._create_check_result(
                    'P2',
                    False,
                    hostpath_pods,
                    f'Found {len(hostpath_pods)} pods using hostPath volumes'
                )
            else:
                return self._create_check_result(
                    'P2',
                    True,
                    [],
                    'No pods using hostPath volumes'
                )
        except Exception as e:
            return self._create_check_error_result('P2', str(e))

    async def _check_image_tags(self, client, cluster_name: str, namespace: Optional[str]) -> Dict[str, Any]:
        """Check if pods are using latest or mutable image tags."""
        try:
            if namespace:
                pods = client.list_resources(kind='Pod', api_version='v1', namespace=namespace)
            else:
                pods = client.list_resources(kind='Pod', api_version='v1')
            
            mutable_tag_pods = []
            
            for pod in pods.items:
                pod_name = pod.metadata.name
                pod_namespace = pod.metadata.namespace
                containers = pod.spec.get('containers', [])
                
                for container in containers:
                    image = container.get('image', '')
                    if ':latest' in image or ':' not in image:
                        mutable_tag_pods.append(f"{pod_namespace}/{pod_name}")
                        break
            
            if mutable_tag_pods:
                return self._create_check_result(
                    'P3',
                    False,
                    mutable_tag_pods,
                    f'Found {len(mutable_tag_pods)} pods using mutable image tags'
                )
            else:
                return self._create_check_result(
                    'P3',
                    True,
                    [],
                    'All pods use immutable image tags'
                )
        except Exception as e:
            return self._create_check_error_result('P3', str(e))

    async def _check_privilege_escalation(self, client, cluster_name: str, namespace: Optional[str]) -> Dict[str, Any]:
        """Check for privilege escalation in pods."""
        try:
            if namespace:
                pods = client.list_resources(kind='Pod', api_version='v1', namespace=namespace)
            else:
                pods = client.list_resources(kind='Pod', api_version='v1')
            
            privilege_escalation_pods = []
            
            for pod in pods.items:
                pod_name = pod.metadata.name
                pod_namespace = pod.metadata.namespace
                containers = pod.spec.get('containers', [])
                
                for container in containers:
                    security_context = container.get('securityContext', {})
                    allow_privilege_escalation = security_context.get('allowPrivilegeEscalation')
                    
                    # If not explicitly set to False, it defaults to True
                    if allow_privilege_escalation is None or allow_privilege_escalation:
                        privilege_escalation_pods.append(f"{pod_namespace}/{pod_name}")
                        break
            
            if privilege_escalation_pods:
                return self._create_check_result(
                    'P4',
                    False,
                    privilege_escalation_pods,
                    f'Found {len(privilege_escalation_pods)} pods allowing privilege escalation'
                )
            else:
                return self._create_check_result(
                    'P4',
                    True,
                    [],
                    'All pods have privilege escalation disabled'
                )
        except Exception as e:
            return self._create_check_error_result('P4', str(e))

    async def _check_readonly_filesystem(self, client, cluster_name: str, namespace: Optional[str]) -> Dict[str, Any]:
        """Check if pods have read-only root filesystem."""
        try:
            if namespace:
                pods = client.list_resources(kind='Pod', api_version='v1', namespace=namespace)
            else:
                pods = client.list_resources(kind='Pod', api_version='v1')
            
            writable_fs_pods = []
            
            for pod in pods.items:
                pod_name = pod.metadata.name
                pod_namespace = pod.metadata.namespace
                containers = pod.spec.get('containers', [])
                
                for container in containers:
                    security_context = container.get('securityContext', {})
                    read_only_root_fs = security_context.get('readOnlyRootFilesystem')
                    
                    # If not explicitly set to True, filesystem is writable
                    if not read_only_root_fs:
                        writable_fs_pods.append(f"{pod_namespace}/{pod_name}")
                        break
            
            if writable_fs_pods:
                return self._create_check_result(
                    'P5',
                    False,
                    writable_fs_pods,
                    f'Found {len(writable_fs_pods)} pods with writable root filesystem'
                )
            else:
                return self._create_check_result(
                    'P5',
                    True,
                    [],
                    'All pods have read-only root filesystem'
                )
        except Exception as e:
            return self._create_check_error_result('P5', str(e))

    async def _check_serviceaccount_token_mount(self, client, cluster_name: str, namespace: Optional[str]) -> Dict[str, Any]:
        """Check if ServiceAccount token mounting is disabled for pods."""
        try:
            if namespace:
                pods = client.list_resources(kind='Pod', api_version='v1', namespace=namespace)
            else:
                pods = client.list_resources(kind='Pod', api_version='v1')
            
            token_mount_pods = []
            
            for pod in pods.items:
                pod_name = pod.metadata.name
                pod_namespace = pod.metadata.namespace
                
                # Check pod-level automountServiceAccountToken
                automount = pod.spec.get('automountServiceAccountToken')
                if automount is None or automount:
                    token_mount_pods.append(f"{pod_namespace}/{pod_name}")
            
            if token_mount_pods:
                return self._create_check_result(
                    'P6',
                    False,
                    token_mount_pods,
                    f'Found {len(token_mount_pods)} pods with ServiceAccount token mounting enabled'
                )
            else:
                return self._create_check_result(
                    'P6',
                    True,
                    [],
                    'All pods have ServiceAccount token mounting disabled'
                )
        except Exception as e:
            return self._create_check_error_result('P6', str(e))

    async def _check_network_policies(self, client, cluster_name: str, namespace: Optional[str]) -> Dict[str, Any]:
        """Check if Network Policies are used to restrict communication between namespaces."""
        try:
            if namespace:
                network_policies = client.list_resources(kind='NetworkPolicy', api_version='networking.k8s.io/v1', namespace=namespace)
            else:
                network_policies = client.list_resources(kind='NetworkPolicy', api_version='networking.k8s.io/v1')
            
            if network_policies and hasattr(network_policies, 'items') and len(network_policies.items) > 0:
                policy_count = len(network_policies.items)
                policy_names = [f"{policy.metadata.namespace}/{policy.metadata.name}" for policy in network_policies.items]
                return self._create_check_result(
                    'M1',
                    True,
                    policy_names,
                    f'Found {policy_count} Network Policies configured for network isolation'
                )
            else:
                return self._create_check_result(
                    'M1',
                    False,
                    [],
                    'No Network Policies found - namespaces can communicate freely'
                )
        except Exception as e:
            return self._create_check_error_result('M1', str(e))

    async def _check_namespace_quotas(self, client, cluster_name: str, namespace: Optional[str]) -> Dict[str, Any]:
        """Check if Resource Quotas are defined at the namespace level."""
        try:
            if namespace:
                resource_quotas = client.list_resources(kind='ResourceQuota', api_version='v1', namespace=namespace)
                namespaces_to_check = [namespace]
            else:
                resource_quotas = client.list_resources(kind='ResourceQuota', api_version='v1')
                namespaces = client.list_resources(kind='Namespace', api_version='v1')
                namespaces_to_check = [ns.metadata.name for ns in namespaces.items if ns.metadata.name not in ['kube-system', 'kube-public', 'kube-node-lease']]
            
            namespaces_with_quotas = set()
            if resource_quotas and hasattr(resource_quotas, 'items'):
                for quota in resource_quotas.items:
                    namespaces_with_quotas.add(quota.metadata.namespace)
            
            namespaces_without_quotas = [ns for ns in namespaces_to_check if ns not in namespaces_with_quotas]
            
            if namespaces_without_quotas:
                return self._create_check_result(
                    'M2',
                    False,
                    namespaces_without_quotas,
                    f'Found {len(namespaces_without_quotas)} namespaces without Resource Quotas'
                )
            else:
                return self._create_check_result(
                    'M2',
                    True,
                    list(namespaces_with_quotas),
                    f'All {len(namespaces_with_quotas)} namespaces have Resource Quotas configured'
                )
        except Exception as e:
            return self._create_check_error_result('M2', str(e))

    async def _check_node_isolation(self, client, cluster_name: str, namespace: Optional[str]) -> Dict[str, Any]:
        """Check if tenant workloads are isolated to specific nodes using taints/tolerations and node affinity."""
        try:
            # Check for nodes with taints (indicating tenant isolation)
            nodes = client.list_resources(kind='Node', api_version='v1')
            tainted_nodes = []
            
            for node in nodes.items:
                node_name = node.metadata.name
                taints = node.spec.get('taints', [])
                if taints:
                    tainted_nodes.append(node_name)
            
            # Check for pods with tolerations or node affinity
            if namespace:
                pods = client.list_resources(kind='Pod', api_version='v1', namespace=namespace)
            else:
                pods = client.list_resources(kind='Pod', api_version='v1')
            
            isolated_pods = []
            for pod in pods.items:
                pod_name = pod.metadata.name
                pod_namespace = pod.metadata.namespace
                
                # Check for tolerations
                tolerations = pod.spec.get('tolerations', [])
                # Check for node affinity
                affinity = pod.spec.get('affinity', {})
                node_affinity = affinity.get('nodeAffinity', {})
                
                if tolerations or node_affinity:
                    isolated_pods.append(f"{pod_namespace}/{pod_name}")
            
            if tainted_nodes or isolated_pods:
                details = f'Found {len(tainted_nodes)} tainted nodes and {len(isolated_pods)} pods with isolation configuration'
                return self._create_check_result(
                    'M3',
                    True,
                    tainted_nodes + isolated_pods,
                    details
                )
            else:
                return self._create_check_result(
                    'M3',
                    False,
                    [],
                    'No node isolation mechanisms found (no taints, tolerations, or node affinity)'
                )
        except Exception as e:
            return self._create_check_error_result('M3', str(e))

    async def _check_control_plane_logs(self, client, cluster_name: str, namespace: Optional[str]) -> Dict[str, Any]:
        """Check if EKS Control Plane logs are enabled."""
        try:
            import boto3
            eks_client = boto3.client('eks')
            
            # Get cluster configuration
            response = eks_client.describe_cluster(name=cluster_name)
            cluster = response['cluster']
            
            # Check logging configuration
            logging_config = cluster.get('logging', {})
            cluster_logging = logging_config.get('clusterLogging', [])
            
            enabled_log_types = []
            disabled_log_types = []
            
            for log_config in cluster_logging:
                log_types = log_config.get('types', [])
                enabled = log_config.get('enabled', False)
                
                if enabled:
                    enabled_log_types.extend(log_types)
                else:
                    disabled_log_types.extend(log_types)
            
            # All possible log types
            all_log_types = ['api', 'audit', 'authenticator', 'controllerManager', 'scheduler']
            
            if len(enabled_log_types) == len(all_log_types):
                return self._create_check_result(
                    'D1',
                    True,
                    enabled_log_types,
                    f'All control plane log types are enabled: {enabled_log_types}'
                )
            elif enabled_log_types:
                return self._create_check_result(
                    'D1',
                    False,
                    enabled_log_types,
                    f'Partial control plane logging enabled: {enabled_log_types}, missing: {[t for t in all_log_types if t not in enabled_log_types]}'
                )
            else:
                return self._create_check_result(
                    'D1',
                    False,
                    [],
                    'No control plane logs are enabled'
                )
        except Exception as e:
            return self._create_check_error_result('D1', str(e))

    async def _check_storage_encryption(self, client, cluster_name: str, namespace: Optional[str]) -> Dict[str, Any]:
        """Check if encryption is enabled in StorageClass."""
        try:
            # Get all StorageClasses
            storage_classes = client.list_resources(kind='StorageClass', api_version='storage.k8s.io/v1')
            
            non_encrypted_sc = []
            encrypted_sc = []
            
            for sc in storage_classes.items:
                sc_name = sc.metadata.name
                parameters = sc.get('parameters', {})
                
                # Check for encryption parameters based on provisioner
                provisioner = sc.get('provisioner', '')
                encrypted = False
                
                if 'ebs.csi.aws.com' in provisioner:
                    # EBS CSI driver - check for encrypted parameter
                    encrypted = parameters.get('encrypted', '').lower() == 'true'
                elif 'efs.csi.aws.com' in provisioner:
                    # EFS CSI driver - EFS is encrypted by default in newer versions
                    encrypted = True
                elif 'fsx.csi.aws.com' in provisioner:
                    # FSx CSI driver - check for encryption parameters
                    encrypted = 'KmsKeyId' in parameters or 'EncryptionAtTransitRequested' in parameters
                
                if encrypted:
                    encrypted_sc.append(sc_name)
                else:
                    non_encrypted_sc.append(sc_name)
            
            if non_encrypted_sc:
                return self._create_check_result(
                    'DE1',
                    False,
                    non_encrypted_sc,
                    f'Found {len(non_encrypted_sc)} StorageClasses without encryption enabled'
                )
            elif encrypted_sc:
                return self._create_check_result(
                    'DE1',
                    True,
                    encrypted_sc,
                    f'All {len(encrypted_sc)} StorageClasses have encryption enabled'
                )
            else:
                return self._create_check_result(
                    'DE1',
                    False,
                    [],
                    'No StorageClasses found in the cluster'
                )
        except Exception as e:
            return self._create_check_error_result('DE1', str(e))

    async def _check_external_secrets(self, client, cluster_name: str, namespace: Optional[str]) -> Dict[str, Any]:
        """Check if external secrets provider is used."""
        try:
            # Check for External Secrets Operator
            external_secrets_found = []
            
            # Check for ExternalSecret CRDs
            try:
                if namespace:
                    external_secrets = client.list_resources(kind='ExternalSecret', api_version='external-secrets.io/v1beta1', namespace=namespace)
                else:
                    external_secrets = client.list_resources(kind='ExternalSecret', api_version='external-secrets.io/v1beta1')
                
                if external_secrets and hasattr(external_secrets, 'items') and len(external_secrets.items) > 0:
                    for es in external_secrets.items:
                        external_secrets_found.append(f"{es.metadata.namespace}/{es.metadata.name}")
            except Exception:
                # ExternalSecret CRD might not be installed
                pass
            
            # Check for AWS Secrets Manager CSI driver
            try:
                if namespace:
                    secret_provider_classes = client.list_resources(kind='SecretProviderClass', api_version='secrets-store.csi.x-k8s.io/v1', namespace=namespace)
                else:
                    secret_provider_classes = client.list_resources(kind='SecretProviderClass', api_version='secrets-store.csi.x-k8s.io/v1')
                
                if secret_provider_classes and hasattr(secret_provider_classes, 'items'):
                    for spc in secret_provider_classes.items:
                        spec = spc.get('spec', {})
                        provider = spec.get('provider', '')
                        if provider == 'aws':
                            external_secrets_found.append(f"{spc.metadata.namespace}/{spc.metadata.name}")
            except Exception:
                # SecretProviderClass CRD might not be installed
                pass
            
            # Check for AWS Load Balancer Controller (uses external secrets)
            try:
                if namespace:
                    deployments = client.list_resources(kind='Deployment', api_version='apps/v1', namespace=namespace)
                else:
                    deployments = client.list_resources(kind='Deployment', api_version='apps/v1')
                
                for deployment in deployments.items:
                    dep_name = deployment.metadata.name
                    if 'external-secrets' in dep_name.lower() or 'secrets-store-csi' in dep_name.lower():
                        external_secrets_found.append(f"{deployment.metadata.namespace}/{dep_name}")
            except Exception:
                pass
            
            if external_secrets_found:
                return self._create_check_result(
                    'DE2',
                    True,
                    external_secrets_found,
                    f'Found {len(external_secrets_found)} external secrets resources'
                )
            else:
                return self._create_check_result(
                    'DE2',
                    False,
                    [],
                    'No external secrets provider found - using native Kubernetes secrets only'
                )
        except Exception as e:
            return self._create_check_error_result('DE2', str(e))

    async def _check_private_subnets(self, client, cluster_name: str, namespace: Optional[str]) -> Dict[str, Any]:
        """Check if worker nodes are deployed onto private subnets."""
        try:
            import boto3
            ec2_client = boto3.client('ec2')
            eks_client = boto3.client('eks')
            
            # Get node groups
            node_groups = eks_client.list_nodegroups(clusterName=cluster_name)
            public_nodegroups = []
            private_nodegroups = []
            
            for ng_name in node_groups.get('nodegroups', []):
                ng_details = eks_client.describe_nodegroup(clusterName=cluster_name, nodegroupName=ng_name)
                subnets = ng_details['nodegroup'].get('subnets', [])
                
                # Check if subnets are private
                for subnet_id in subnets:
                    subnet_response = ec2_client.describe_subnets(SubnetIds=[subnet_id])
                    subnet = subnet_response['Subnets'][0]
                    
                    # Check route table for internet gateway
                    route_tables = ec2_client.describe_route_tables(
                        Filters=[{'Name': 'association.subnet-id', 'Values': [subnet_id]}]
                    )
                    
                    is_public = False
                    for rt in route_tables['RouteTables']:
                        for route in rt.get('Routes', []):
                            if route.get('GatewayId', '').startswith('igw-'):
                                is_public = True
                                break
                    
                    if is_public:
                        public_nodegroups.append(ng_name)
                        break
                else:
                    private_nodegroups.append(ng_name)
            
            if public_nodegroups:
                return self._create_check_result(
                    'IS1',
                    False,
                    public_nodegroups,
                    f'Found {len(public_nodegroups)} node groups in public subnets'
                )
            else:
                return self._create_check_result(
                    'IS1',
                    True,
                    private_nodegroups,
                    f'All {len(private_nodegroups)} node groups are in private subnets'
                )
        except Exception as e:
            return self._create_check_error_result('IS1', str(e))

    async def _check_container_optimized_os(self, client, cluster_name: str, namespace: Optional[str]) -> Dict[str, Any]:
        """Check if nodes use container-optimized OS."""
        try:
            import boto3
            eks_client = boto3.client('eks')
            ec2_client = boto3.client('ec2')
            
            # Get node groups
            node_groups = eks_client.list_nodegroups(clusterName=cluster_name)
            optimized_nodegroups = []
            non_optimized_nodegroups = []
            
            for ng_name in node_groups.get('nodegroups', []):
                ng_details = eks_client.describe_nodegroup(clusterName=cluster_name, nodegroupName=ng_name)
                
                # Check AMI type
                ami_type = ng_details['nodegroup'].get('amiType', '')
                
                # EKS optimized AMIs are considered container-optimized
                if any(optimized in ami_type for optimized in ['AL2_x86_64', 'AL2_x86_64_GPU', 'AL2_ARM_64', 'BOTTLEROCKET']):
                    optimized_nodegroups.append(ng_name)
                else:
                    non_optimized_nodegroups.append(ng_name)
            
            if non_optimized_nodegroups:
                return self._create_check_result(
                    'IS2',
                    False,
                    non_optimized_nodegroups,
                    f'Found {len(non_optimized_nodegroups)} node groups not using container-optimized OS'
                )
            else:
                return self._create_check_result(
                    'IS2',
                    True,
                    optimized_nodegroups,
                    f'All {len(optimized_nodegroups)} node groups use container-optimized OS'
                )
        except Exception as e:
            return self._create_check_error_result('IS2', str(e))

    async def _check_worker_node_access(self, client, cluster_name: str, namespace: Optional[str]) -> Dict[str, Any]:
        """Check if worker nodes have minimal access (no SSH, use SSM)."""
        try:
            import boto3
            eks_client = boto3.client('eks')
            ec2_client = boto3.client('ec2')
            
            # Get node groups
            node_groups = eks_client.list_nodegroups(clusterName=cluster_name)
            ssh_enabled_nodegroups = []
            secure_nodegroups = []
            
            for ng_name in node_groups.get('nodegroups', []):
                ng_details = eks_client.describe_nodegroup(clusterName=cluster_name, nodegroupName=ng_name)
                
                # Check if SSH key is configured
                remote_access = ng_details['nodegroup'].get('remoteAccess', {})
                ec2_ssh_key = remote_access.get('ec2SshKey')
                
                if ec2_ssh_key:
                    ssh_enabled_nodegroups.append(ng_name)
                else:
                    secure_nodegroups.append(ng_name)
            
            if ssh_enabled_nodegroups:
                return self._create_check_result(
                    'IS3',
                    False,
                    ssh_enabled_nodegroups,
                    f'Found {len(ssh_enabled_nodegroups)} node groups with SSH access enabled'
                )
            else:
                return self._create_check_result(
                    'IS3',
                    True,
                    secure_nodegroups,
                    f'All {len(secure_nodegroups)} node groups have SSH access disabled'
                )
        except Exception as e:
            return self._create_check_error_result('IS3', str(e))



