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
        }
        
        method = check_methods.get(check_id)
        if method:
            return await method(client, cluster_name, namespace)
        else:
            return self._create_check_error_result(check_id, f'Check method not implemented for {check_id}')

    async def _check_cluster_access_manager(self, client, cluster_name: str, namespace: Optional[str]) -> Dict[str, Any]:
        """Check if EKS Cluster Access Manager is configured."""
        try:
            # This would require AWS API calls to check cluster configuration
            # For now, return a placeholder implementation
            return self._create_check_result(
                'IAM1',
                False,  # Assume non-compliant for demonstration
                [cluster_name],
                'Cluster Access Manager configuration needs to be verified via AWS API'
            )
        except Exception as e:
            return self._create_check_error_result('IAM1', str(e))

    async def _check_private_endpoint(self, client, cluster_name: str, namespace: Optional[str]) -> Dict[str, Any]:
        """Check if EKS cluster endpoint is private."""
        try:
            # This would require AWS API calls to check endpoint configuration
            # For now, return a placeholder implementation
            return self._create_check_result(
                'IAM2',
                False,  # Assume non-compliant for demonstration
                [cluster_name],
                'Cluster endpoint privacy configuration needs to be verified via AWS API'
            )
        except Exception as e:
            return self._create_check_error_result('IAM2', str(e))

    async def _check_service_account_tokens(self, client, cluster_name: str, namespace: Optional[str]) -> Dict[str, Any]:
        """Check for service account token usage."""
        try:
            # Check for service accounts with automountServiceAccountToken enabled
            from kubernetes import client as k8s_client
            
            v1 = k8s_client.CoreV1Api(client)
            
            if namespace:
                service_accounts = v1.list_namespaced_service_account(namespace=namespace)
            else:
                service_accounts = v1.list_service_account_for_all_namespaces()
            
            non_compliant_sa = []
            for sa in service_accounts.items:
                # Check if automountServiceAccountToken is explicitly set to True or not set (defaults to True)
                if sa.automount_service_account_token is None or sa.automount_service_account_token:
                    non_compliant_sa.append(f"{sa.metadata.namespace}/{sa.metadata.name}")
            
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