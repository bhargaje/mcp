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

"""Handler for EKS resiliency checks in the EKS MCP Server."""

import json
from pathlib import Path
from awslabs.eks_review_mcp_server.aws_helper import AwsHelper
from awslabs.eks_review_mcp_server.logging_helper import LogLevel, log_with_request_id
from awslabs.eks_review_mcp_server.models import ResiliencyCheckResponse
from collections import Counter
from loguru import logger
from mcp.server.fastmcp import Context
from mcp.types import TextContent
from pydantic import Field
from typing import Any, Dict, Optional, List


class EKSResiliencyHandler:
    """Handler for EKS resiliency checks in the EKS MCP Server."""

    def __init__(self, mcp, client_cache):
        """Initialize the EKS resiliency handler.

        Args:
            mcp: The MCP server instance
            client_cache: K8sClientCache instance to share between handlers
        """
        self.mcp = mcp
        self.client_cache = client_cache
        self.check_registry = self._load_check_registry()

        # Register the comprehensive check tool
        self.mcp.tool(name='check_eks_resiliency')(self.check_eks_resiliency)

    def _load_check_registry(self) -> Dict[str, Any]:
        """Load check definitions from JSON file."""
        try:
            config_path = Path(__file__).parent / 'data' / 'eks_resiliency_checks.json'
            with open(config_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load check registry: {e}")
            return {}

    def _get_all_checks(self) -> Dict[str, Dict[str, Any]]:
        """Get all checks flattened into a single dictionary."""
        all_checks = {}
        for category in ['application_checks', 'control_plane_checks', 'data_plane_checks']:
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

    def _create_error_response(self, cluster_name: str, error_msg: str) -> ResiliencyCheckResponse:
        """Create an error response."""
        return ResiliencyCheckResponse(
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

    async def check_eks_resiliency(
        self,
        ctx: Context,
        cluster_name: str = Field(
            ..., description='Name of the EKS cluster to check for resiliency best practices.'
        ),
        namespace: Optional[str] = Field(
            None, description='Optional namespace to limit the check scope.'
        ),
    ) -> ResiliencyCheckResponse:
        """Check EKS cluster for resiliency best practices.

        This tool runs a comprehensive set of resiliency checks against your EKS cluster
        to identify potential issues that could impact application availability and
        provides remediation guidance.

        The tool evaluates 28 critical resiliency best practices across three categories:
        - Application Related Checks (A1-A14): Workload resilience and operational practices
        - Control Plane Related Checks (C1-C5): EKS control plane configuration
        - Data Plane Related Checks (D1-D7): Worker node and cluster infrastructure
        """
        try:
            logger.info(f'Starting resiliency check for cluster: {cluster_name}')

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
            summary = f'Cluster {cluster_name} resiliency check: {passed_count} checks passed, {failed_count} checks failed'

            return ResiliencyCheckResponse(
                isError=False,
                content=[TextContent(type='text', text=summary)],
                check_results=check_results,
                overall_compliant=all_compliant,
                summary=summary,
            )

        except Exception as e:
            logger.error(f'Unexpected error in resiliency check: {str(e)}')
            return self._create_error_response(cluster_name, str(e))

    async def _execute_check(self, check_id: str, client, cluster_name: str, namespace: Optional[str]) -> Dict[str, Any]:
        """Execute a single check based on its ID."""
        
        # Map check IDs to their corresponding methods
        check_methods = {
            'A1': self._check_singleton_pods,
            'A2': self._check_multiple_replicas,
            'A3': self._check_pod_anti_affinity,
            'A4': self._check_liveness_probe,
            'A5': self._check_readiness_probe,
            'A6': self._check_pod_disruption_budget,
            'A7': self._check_metrics_server,
            'A8': self._check_horizontal_pod_autoscaler,
            'A9': self._check_custom_metrics,
            'A10': self._check_vertical_pod_autoscaler,
            'A11': self._check_prestop_hooks,
            'A12': self._check_service_mesh,
            'A13': self._check_monitoring,
            'A14': self._check_centralized_logging,
            'C1': self._check_c1,
            'C2': self._check_c2,
            'C3': self._check_c3,
            'C4': self._check_c4,
            'C5': self._check_c5,
            'D1': self._check_d1,
            'D2': self._check_d2,
            'D3': self._check_d3,
            'D4': self._check_d4,
            'D5': self._check_d5,
            'D6': self._check_d6,
            'D7': self._check_d7,
        }
        
        check_method = check_methods.get(check_id)
        if not check_method:
            return self._create_check_error_result(check_id, f"No implementation found for check {check_id}")
        
        # Execute the check method
        if check_id.startswith('A'):
            # Application checks only need client and namespace
            return check_method(client, namespace)
        else:
            # Control plane and data plane checks need cluster_name too
            return check_method(client, cluster_name, namespace)

    # Placeholder check methods - these would contain the actual check logic
    # For now, I'll create simple placeholder implementations that use the JSON configuration
    
    def _check_singleton_pods(self, k8s_api, namespace: Optional[str] = None) -> Dict[str, Any]:
        """Check A1: Singleton pods without controller management."""
        singleton_pods = []
        try:
            logger.info(
                f'Starting singleton pods check, namespace: {namespace if namespace else "all"}'
            )

            # Prepare kwargs for filtering
            kwargs = {}
            if namespace:
                kwargs['namespace'] = namespace
                logger.info(f'Checking pods in namespace: {namespace}')
            else:
                logger.info('Checking pods across all namespaces')

            # Use the K8sApis list_resources method
            logger.info('Calling list_resources to get pods')
            pods_response = k8s_api.list_resources(kind='Pod', api_version='v1', **kwargs)

            # Log the number of pods found
            pod_count = len(pods_response.items) if hasattr(pods_response, 'items') else 0
            logger.info(f'Retrieved {pod_count} pods')

            # Process the response
            for pod in pods_response.items:
                try:
                    pod_dict = pod.to_dict() if hasattr(pod, 'to_dict') else pod

                    # Check if pod has owner references
                    metadata = pod_dict.get('metadata', {})
                    owner_refs = metadata.get('ownerReferences', [])

                    # Make sure we get the namespace from the pod metadata
                    pod_namespace = metadata.get('namespace')
                    if not pod_namespace:
                        logger.warning("Pod missing namespace information, using 'default'")
                        pod_namespace = 'default'

                    name = metadata.get('name', 'unknown')

                    logger.debug(f'Checking pod {pod_namespace}/{name}')

                    if not owner_refs:
                        logger.info(f'Found singleton pod: {pod_namespace}/{name}')
                        singleton_pods.append(f'{pod_namespace}/{name}')
                except Exception as pod_error:
                    logger.error(f'Error processing pod: {str(pod_error)}')

            is_compliant = len(singleton_pods) == 0
            scope_info = f"in namespace '{namespace}'" if namespace else 'across all namespaces'
            detailed_message = f'Found {len(singleton_pods)} singleton pods not managed by controllers {scope_info}'
            
            return self._create_check_result('A1', is_compliant, singleton_pods, detailed_message)

        except Exception as e:
            logger.error(f'Error checking singleton pods: {str(e)}')
            import traceback
            logger.error(f'Traceback: {traceback.format_exc()}')
            scope_info = f"in namespace '{namespace}'" if namespace else 'across all namespaces'
            error_message = f'API error while checking singleton pods {scope_info}: {str(e)}'
            return self._create_check_result('A1', False, [], error_message)

    def _check_multiple_replicas(self, k8s_api, namespace: Optional[str] = None) -> Dict[str, Any]:
        """Check A2: Deployments and StatefulSets with only one replica."""
        single_replica_workloads = []
        try:
            logger.info(
                f'Starting multiple replicas check, namespace: {namespace if namespace else "all"}'
            )

            # Prepare kwargs for filtering
            kwargs = {}
            if namespace:
                kwargs['namespace'] = namespace
                logger.info(f'Checking workloads in namespace: {namespace}')
            else:
                logger.info('Checking workloads across all namespaces')

            # Check Deployments
            logger.info('Calling list_resources to get deployments')
            deployments_response = k8s_api.list_resources(
                kind='Deployment', api_version='apps/v1', **kwargs
            )

            # Log the number of deployments found
            deployment_count = (
                len(deployments_response.items) if hasattr(deployments_response, 'items') else 0
            )
            logger.info(f'Retrieved {deployment_count} deployments')

            # Process deployments
            for deployment in deployments_response.items:
                try:
                    deployment_dict = (
                        deployment.to_dict() if hasattr(deployment, 'to_dict') else deployment
                    )

                    # Get deployment metadata
                    metadata = deployment_dict.get('metadata', {})
                    deploy_namespace = metadata.get('namespace', 'default')
                    name = metadata.get('name', 'unknown')

                    # Check replicas
                    spec = deployment_dict.get('spec', {})
                    replicas = spec.get('replicas', 0)

                    logger.debug(
                        f'Checking deployment {deploy_namespace}/{name} with {replicas} replicas'
                    )

                    if replicas == 1:
                        logger.info(f'Found single replica deployment: {deploy_namespace}/{name}')
                        single_replica_workloads.append(f'Deployment {deploy_namespace}/{name}')
                except Exception as deploy_error:
                    logger.error(f'Error processing deployment: {str(deploy_error)}')

            # Check StatefulSets
            logger.info('Calling list_resources to get statefulsets')
            try:
                statefulsets_response = k8s_api.list_resources(
                    kind='StatefulSet', api_version='apps/v1', **kwargs
                )

                # Log the number of statefulsets found
                statefulset_count = (
                    len(statefulsets_response.items)
                    if hasattr(statefulsets_response, 'items')
                    else 0
                )
                logger.info(f'Retrieved {statefulset_count} statefulsets')

                # Process statefulsets
                for statefulset in statefulsets_response.items:
                    try:
                        statefulset_dict = (
                            statefulset.to_dict()
                            if hasattr(statefulset, 'to_dict')
                            else statefulset
                        )

                        # Get statefulset metadata
                        metadata = statefulset_dict.get('metadata', {})
                        sts_namespace = metadata.get('namespace', 'default')
                        name = metadata.get('name', 'unknown')

                        # Check replicas
                        spec = statefulset_dict.get('spec', {})
                        replicas = spec.get('replicas', 0)

                        logger.debug(
                            f'Checking statefulset {sts_namespace}/{name} with {replicas} replicas'
                        )

                        if replicas == 1:
                            logger.info(
                                f'Found single replica statefulset: {sts_namespace}/{name}'
                            )
                            single_replica_workloads.append(f'StatefulSet {sts_namespace}/{name}')
                    except Exception as sts_error:
                        logger.error(f'Error processing statefulset: {str(sts_error)}')
            except Exception as sts_list_error:
                logger.warning(f'Error listing statefulsets: {str(sts_list_error)}')

            is_compliant = len(single_replica_workloads) == 0
            scope_info = f"in namespace '{namespace}'" if namespace else 'across all namespaces'
            detailed_message = f'Found {len(single_replica_workloads)} workloads (Deployments/StatefulSets) with only 1 replica {scope_info}'
            
            return self._create_check_result('A2', is_compliant, single_replica_workloads, detailed_message)

        except Exception as e:
            logger.error(f'Error checking multiple replicas: {str(e)}')
            import traceback
            logger.error(f'Traceback: {traceback.format_exc()}')
            scope_info = f"in namespace '{namespace}'" if namespace else 'across all namespaces'
            error_message = f'API error while checking workloads for multiple replicas {scope_info}: {str(e)}'
            return self._create_check_result('A2', False, [], error_message)

    def _check_pod_anti_affinity(self, k8s_api, namespace: Optional[str] = None) -> Dict[str, Any]:
        """Check A3: Multi-replica deployments without pod anti-affinity."""
        deployments_without_anti_affinity = []
        try:
            logger.info(
                f'Starting pod anti-affinity check, namespace: {namespace if namespace else "all"}'
            )

            # Prepare kwargs for filtering
            kwargs = {}
            if namespace:
                kwargs['namespace'] = namespace
                logger.info(f'Checking deployments in namespace: {namespace}')
            else:
                logger.info('Checking deployments across all namespaces')

            # Use the K8sApis list_resources method to get deployments
            logger.info('Calling list_resources to get deployments')
            deployments_response = k8s_api.list_resources(
                kind='Deployment', api_version='apps/v1', **kwargs
            )

            # Log the number of deployments found
            deployment_count = (
                len(deployments_response.items) if hasattr(deployments_response, 'items') else 0
            )
            logger.info(f'Retrieved {deployment_count} deployments')

            # Process the response
            for deployment in deployments_response.items:
                try:
                    deployment_dict = (
                        deployment.to_dict() if hasattr(deployment, 'to_dict') else deployment
                    )

                    # Get deployment metadata
                    metadata = deployment_dict.get('metadata', {})
                    deploy_namespace = metadata.get('namespace', 'default')
                    name = metadata.get('name', 'unknown')

                    # Check replicas
                    spec = deployment_dict.get('spec', {})
                    replicas = spec.get('replicas', 0)

                    # Skip deployments with only 1 replica
                    if replicas <= 1:
                        logger.debug(
                            f'Skipping deployment {deploy_namespace}/{name} with {replicas} replicas'
                        )
                        continue

                    # Check for pod anti-affinity
                    template_spec = spec.get('template', {}).get('spec', {})
                    affinity = template_spec.get('affinity', {})
                    pod_anti_affinity = affinity.get('podAntiAffinity', None)

                    has_anti_affinity = pod_anti_affinity is not None

                    logger.debug(
                        f'Checking deployment {deploy_namespace}/{name} for pod anti-affinity: {has_anti_affinity}'
                    )

                    if not has_anti_affinity:
                        logger.info(
                            f'Found deployment without pod anti-affinity: {deploy_namespace}/{name}'
                        )
                        deployments_without_anti_affinity.append(f'{deploy_namespace}/{name}')
                except Exception as deploy_error:
                    logger.error(f'Error processing deployment: {str(deploy_error)}')

            is_compliant = len(deployments_without_anti_affinity) == 0
            scope_info = f"in namespace '{namespace}'" if namespace else 'across all namespaces'
            detailed_message = f'Found {len(deployments_without_anti_affinity)} multi-replica deployments without pod anti-affinity {scope_info}'
            
            return self._create_check_result('A3', is_compliant, deployments_without_anti_affinity, detailed_message)

        except Exception as e:
            logger.error(f'Error checking pod anti-affinity: {str(e)}')
            import traceback
            logger.error(f'Traceback: {traceback.format_exc()}')
            scope_info = f"in namespace '{namespace}'" if namespace else 'across all namespaces'
            error_message = f'API error while checking deployments for pod anti-affinity {scope_info}: {str(e)}'
            return self._create_check_result('A3', False, [], error_message)

    def _check_liveness_probe(self, k8s_api, namespace: Optional[str] = None) -> Dict[str, Any]:
        """Check A4: Deployments without liveness probes."""
        workloads_without_liveness = []
        try:
            logger.info(
                f'Starting liveness probe check, namespace: {namespace if namespace else "all"}'
            )

            # Prepare kwargs for filtering
            kwargs = {}
            if namespace:
                kwargs['namespace'] = namespace
                logger.info(f'Checking workloads in namespace: {namespace}')
            else:
                logger.info('Checking workloads across all namespaces')

            # Check Deployments
            logger.info('Checking Deployments for liveness probes')
            try:
                deployments_response = k8s_api.list_resources(
                    kind='Deployment', api_version='apps/v1', **kwargs
                )

                # Process the response
                for deployment in deployments_response.items:
                    try:
                        deployment_dict = (
                            deployment.to_dict() if hasattr(deployment, 'to_dict') else deployment
                        )

                        # Get deployment metadata
                        metadata = deployment_dict.get('metadata', {})
                        deploy_namespace = metadata.get('namespace', 'default')
                        name = metadata.get('name', 'unknown')

                        # Check containers for liveness probes
                        template_spec = (
                            deployment_dict.get('spec', {}).get('template', {}).get('spec', {})
                        )
                        containers = template_spec.get('containers', [])

                        has_liveness_probe = True
                        for container in containers:
                            if not container.get('livenessProbe'):
                                has_liveness_probe = False
                                break

                        if not has_liveness_probe:
                            workloads_without_liveness.append(f'Deployment: {deploy_namespace}/{name}')
                    except Exception as deploy_error:
                        logger.error(f'Error processing deployment: {str(deploy_error)}')
            except Exception as e:
                logger.error(f'Error listing deployments: {str(e)}')

            # Check StatefulSets
            logger.info('Checking StatefulSets for liveness probes')
            try:
                statefulsets_response = k8s_api.list_resources(
                    kind='StatefulSet', api_version='apps/v1', **kwargs
                )

                for statefulset in statefulsets_response.items:
                    try:
                        statefulset_dict = (
                            statefulset.to_dict()
                            if hasattr(statefulset, 'to_dict')
                            else statefulset
                        )

                        # Get statefulset metadata
                        metadata = statefulset_dict.get('metadata', {})
                        ss_namespace = metadata.get('namespace', 'default')
                        name = metadata.get('name', 'unknown')

                        # Check containers for liveness probes
                        template_spec = (
                            statefulset_dict.get('spec', {}).get('template', {}).get('spec', {})
                        )
                        containers = template_spec.get('containers', [])

                        has_liveness_probe = True
                        for container in containers:
                            if not container.get('livenessProbe'):
                                has_liveness_probe = False
                                break

                        if not has_liveness_probe:
                            workloads_without_liveness.append(f'StatefulSet: {ss_namespace}/{name}')
                    except Exception as ss_error:
                        logger.error(f'Error processing statefulset: {str(ss_error)}')
            except Exception as e:
                logger.error(f'Error listing statefulsets: {str(e)}')

            # Check DaemonSets
            logger.info('Checking DaemonSets for liveness probes')
            try:
                daemonsets_response = k8s_api.list_resources(
                    kind='DaemonSet', api_version='apps/v1', **kwargs
                )

                for daemonset in daemonsets_response.items:
                    try:
                        daemonset_dict = (
                            daemonset.to_dict() if hasattr(daemonset, 'to_dict') else daemonset
                        )

                        # Get daemonset metadata
                        metadata = daemonset_dict.get('metadata', {})
                        ds_namespace = metadata.get('namespace', 'default')
                        name = metadata.get('name', 'unknown')

                        # Check containers for liveness probes
                        template_spec = (
                            daemonset_dict.get('spec', {}).get('template', {}).get('spec', {})
                        )
                        containers = template_spec.get('containers', [])

                        has_liveness_probe = True
                        for container in containers:
                            if not container.get('livenessProbe'):
                                has_liveness_probe = False
                                break

                        if not has_liveness_probe:
                            workloads_without_liveness.append(f'DaemonSet: {ds_namespace}/{name}')
                    except Exception as ds_error:
                        logger.error(f'Error processing daemonset: {str(ds_error)}')
            except Exception as e:
                logger.error(f'Error listing daemonsets: {str(e)}')

            is_compliant = len(workloads_without_liveness) == 0
            scope_info = f"in namespace '{namespace}'" if namespace else 'across all namespaces'
            detailed_message = f'Found {len(workloads_without_liveness)} workloads without liveness probes {scope_info}'
            
            return self._create_check_result('A4', is_compliant, workloads_without_liveness, detailed_message)

        except Exception as e:
            logger.error(f'Error checking liveness probes: {str(e)}')
            import traceback
            logger.error(f'Traceback: {traceback.format_exc()}')
            scope_info = f"in namespace '{namespace}'" if namespace else 'across all namespaces'
            error_message = f'API error while checking workloads for liveness probes {scope_info}: {str(e)}'
            return self._create_check_result('A4', False, [], error_message)

    def _check_readiness_probe(self, k8s_api, namespace: Optional[str] = None) -> Dict[str, Any]:
        """Check A5: Deployments without readiness probes."""
        workloads_without_readiness = []
        try:
            logger.info(
                f'Starting readiness probe check, namespace: {namespace if namespace else "all"}'
            )

            # Prepare kwargs for filtering
            kwargs = {}
            if namespace:
                kwargs['namespace'] = namespace
            else:
                logger.info('Checking workloads across all namespaces')

            # Check Deployments, StatefulSets, and DaemonSets
            for workload_type in ['Deployment', 'StatefulSet', 'DaemonSet']:
                try:
                    workloads_response = k8s_api.list_resources(
                        kind=workload_type, api_version='apps/v1', **kwargs
                    )

                    for workload in workloads_response.items:
                        try:
                            workload_dict = (
                                workload.to_dict() if hasattr(workload, 'to_dict') else workload
                            )

                            # Get workload metadata
                            metadata = workload_dict.get('metadata', {})
                            workload_namespace = metadata.get('namespace', 'default')
                            name = metadata.get('name', 'unknown')

                            # Check containers for readiness probes
                            template_spec = (
                                workload_dict.get('spec', {}).get('template', {}).get('spec', {})
                            )
                            containers = template_spec.get('containers', [])

                            has_readiness_probe = True
                            for container in containers:
                                if not container.get('readinessProbe'):
                                    has_readiness_probe = False
                                    break

                            if not has_readiness_probe:
                                workloads_without_readiness.append(f'{workload_type}: {workload_namespace}/{name}')
                        except Exception as workload_error:
                            logger.error(f'Error processing {workload_type}: {str(workload_error)}')
                except Exception as e:
                    logger.error(f'Error listing {workload_type}s: {str(e)}')

            is_compliant = len(workloads_without_readiness) == 0
            scope_info = f"in namespace '{namespace}'" if namespace else 'across all namespaces'
            detailed_message = f'Found {len(workloads_without_readiness)} workloads without readiness probes {scope_info}'
            
            return self._create_check_result('A5', is_compliant, workloads_without_readiness, detailed_message)

        except Exception as e:
            logger.error(f'Error checking readiness probes: {str(e)}')
            import traceback
            logger.error(f'Traceback: {traceback.format_exc()}')
            scope_info = f"in namespace '{namespace}'" if namespace else 'across all namespaces'
            error_message = f'API error while checking workloads for readiness probes {scope_info}: {str(e)}'
            return self._create_check_result('A5', False, [], error_message)

    def _check_pod_disruption_budget(self, k8s_api, namespace: Optional[str] = None) -> Dict[str, Any]:
        """Check A6: Critical workloads without Pod Disruption Budgets."""
        workloads_without_pdb = []
        try:
            logger.info(
                f'Starting pod disruption budget check, namespace: {namespace if namespace else "all"}'
            )

            # Prepare kwargs for filtering
            kwargs = {}
            if namespace:
                kwargs['namespace'] = namespace

            # Get all PDBs first
            pdbs_response = k8s_api.list_resources(
                kind='PodDisruptionBudget', api_version='policy/v1', **kwargs
            )
            
            pdb_selectors = []
            for pdb in pdbs_response.items:
                try:
                    pdb_dict = pdb.to_dict() if hasattr(pdb, 'to_dict') else pdb
                    spec = pdb_dict.get('spec', {})
                    selector = spec.get('selector', {})
                    if selector:
                        pdb_selectors.append(selector)
                except Exception as e:
                    logger.error(f'Error processing PDB: {str(e)}')

            # Check critical workloads (multi-replica Deployments and all StatefulSets)
            for workload_type in ['Deployment', 'StatefulSet']:
                try:
                    workloads_response = k8s_api.list_resources(
                        kind=workload_type, api_version='apps/v1', **kwargs
                    )

                    for workload in workloads_response.items:
                        try:
                            workload_dict = (
                                workload.to_dict() if hasattr(workload, 'to_dict') else workload
                            )

                            metadata = workload_dict.get('metadata', {})
                            workload_namespace = metadata.get('namespace', 'default')
                            name = metadata.get('name', 'unknown')
                            labels = metadata.get('labels', {})

                            # For Deployments, only check multi-replica ones
                            if workload_type == 'Deployment':
                                spec = workload_dict.get('spec', {})
                                replicas = spec.get('replicas', 0)
                                if replicas <= 1:
                                    continue

                            # Check if workload is covered by any PDB
                            has_pdb = False
                            for pdb_selector in pdb_selectors:
                                match_labels = pdb_selector.get('matchLabels', {})
                                if all(labels.get(k) == v for k, v in match_labels.items()):
                                    has_pdb = True
                                    break

                            if not has_pdb:
                                workloads_without_pdb.append(f'{workload_type}: {workload_namespace}/{name}')
                        except Exception as workload_error:
                            logger.error(f'Error processing {workload_type}: {str(workload_error)}')
                except Exception as e:
                    logger.error(f'Error listing {workload_type}s: {str(e)}')

            is_compliant = len(workloads_without_pdb) == 0
            scope_info = f"in namespace '{namespace}'" if namespace else 'across all namespaces'
            detailed_message = f'Found {len(workloads_without_pdb)} critical workloads without Pod Disruption Budgets {scope_info}'
            
            return self._create_check_result('A6', is_compliant, workloads_without_pdb, detailed_message)

        except Exception as e:
            logger.error(f'Error checking pod disruption budgets: {str(e)}')
            import traceback
            logger.error(f'Traceback: {traceback.format_exc()}')
            scope_info = f"in namespace '{namespace}'" if namespace else 'across all namespaces'
            error_message = f'API error while checking pod disruption budgets {scope_info}: {str(e)}'
            return self._create_check_result('A6', False, [], error_message)

    def _check_metrics_server(self, k8s_api, namespace: Optional[str] = None) -> Dict[str, Any]:
        """Check A7: Kubernetes Metrics Server."""
        try:
            logger.info('Starting metrics server check')

            # Check if metrics API is available
            try:
                k8s_api.api_client.call_api(
                    '/apis/metrics.k8s.io/v1beta1',
                    'GET',
                    auth_settings=['BearerToken'],
                    response_type='object',
                    _preload_content=False
                )
                metrics_api_available = True
            except Exception as e:
                logger.info(f'Metrics API not available: {str(e)}')
                metrics_api_available = False

            # Check for metrics-server deployment
            try:
                deployments_response = k8s_api.list_resources(
                    kind='Deployment', api_version='apps/v1', namespace='kube-system'
                )
                
                metrics_server_found = False
                for deployment in deployments_response.items:
                    deployment_dict = deployment.to_dict() if hasattr(deployment, 'to_dict') else deployment
                    metadata = deployment_dict.get('metadata', {})
                    name = metadata.get('name', '')
                    if 'metrics-server' in name.lower():
                        metrics_server_found = True
                        break
            except Exception as e:
                logger.error(f'Error checking metrics-server deployment: {str(e)}')
                metrics_server_found = False

            is_compliant = metrics_api_available and metrics_server_found
            
            if is_compliant:
                details = 'Metrics server is running and metrics API is accessible'
                impacted_resources = []
            else:
                details = 'Metrics server is not properly configured or not accessible'
                impacted_resources = ['metrics-server']
            
            return self._create_check_result('A7', is_compliant, impacted_resources, details)

        except Exception as e:
            logger.error(f'Error checking metrics server: {str(e)}')
            error_message = f'Error checking metrics server: {str(e)}'
            return self._create_check_result('A7', False, [], error_message)

    def _check_horizontal_pod_autoscaler(self, k8s_api, namespace: Optional[str] = None) -> Dict[str, Any]:
        """Check A8: Horizontal Pod Autoscaler (HPA)."""
        workloads_without_hpa = []
        try:
            logger.info(
                f'Starting HPA check, namespace: {namespace if namespace else "all"}'
            )

            # Prepare kwargs for filtering
            kwargs = {}
            if namespace:
                kwargs['namespace'] = namespace

            # Get all HPAs first
            try:
                hpas_response = k8s_api.list_resources(
                    kind='HorizontalPodAutoscaler', api_version='autoscaling/v2', **kwargs
                )
                hpa_targets = set()
                for hpa in hpas_response.items:
                    try:
                        hpa_dict = hpa.to_dict() if hasattr(hpa, 'to_dict') else hpa
                        spec = hpa_dict.get('spec', {})
                        scale_target_ref = spec.get('scaleTargetRef', {})
                        target_name = scale_target_ref.get('name')
                        target_kind = scale_target_ref.get('kind')
                        if target_name and target_kind:
                            hpa_targets.add(f'{target_kind}:{target_name}')
                    except Exception as e:
                        logger.error(f'Error processing HPA: {str(e)}')
            except Exception as e:
                logger.info(f'No HPAs found or error accessing HPAs: {str(e)}')
                hpa_targets = set()

            # Check multi-replica Deployments and StatefulSets
            for workload_type in ['Deployment', 'StatefulSet']:
                try:
                    workloads_response = k8s_api.list_resources(
                        kind=workload_type, api_version='apps/v1', **kwargs
                    )

                    for workload in workloads_response.items:
                        try:
                            workload_dict = (
                                workload.to_dict() if hasattr(workload, 'to_dict') else workload
                            )

                            metadata = workload_dict.get('metadata', {})
                            workload_namespace = metadata.get('namespace', 'default')
                            name = metadata.get('name', 'unknown')

                            # Skip system namespaces
                            if workload_namespace in ['kube-system', 'kube-public', 'kube-node-lease']:
                                continue

                            # Only check multi-replica workloads
                            spec = workload_dict.get('spec', {})
                            replicas = spec.get('replicas', 0)
                            if replicas <= 1:
                                continue

                            # Check if workload has HPA
                            target_key = f'{workload_type}:{name}'
                            if target_key not in hpa_targets:
                                workloads_without_hpa.append(f'{workload_type}: {workload_namespace}/{name}')
                        except Exception as workload_error:
                            logger.error(f'Error processing {workload_type}: {str(workload_error)}')
                except Exception as e:
                    logger.error(f'Error listing {workload_type}s: {str(e)}')

            is_compliant = len(workloads_without_hpa) == 0
            scope_info = f"in namespace '{namespace}'" if namespace else 'across all namespaces'
            detailed_message = f'Found {len(workloads_without_hpa)} multi-replica workloads without HPA {scope_info}'
            
            return self._create_check_result('A8', is_compliant, workloads_without_hpa, detailed_message)

        except Exception as e:
            logger.error(f'Error checking horizontal pod autoscaler: {str(e)}')
            import traceback
            logger.error(f'Traceback: {traceback.format_exc()}')
            scope_info = f"in namespace '{namespace}'" if namespace else 'across all namespaces'
            error_message = f'API error while checking HPA {scope_info}: {str(e)}'
            return self._create_check_result('A8', False, [], error_message)

    def _check_custom_metrics(self, k8s_api, namespace: Optional[str] = None) -> Dict[str, Any]:
        """Check A9: Custom metrics scaling."""
        try:
            logger.info('Starting custom metrics check')

            custom_metrics_available = False
            external_metrics_available = False
            
            # Check for custom metrics API
            try:
                k8s_api.api_client.call_api(
                    '/apis/custom.metrics.k8s.io/v1beta1',
                    'GET',
                    auth_settings=['BearerToken'],
                    response_type='object',
                    _preload_content=False
                )
                custom_metrics_available = True
            except Exception:
                pass

            # Check for external metrics API
            try:
                k8s_api.api_client.call_api(
                    '/apis/external.metrics.k8s.io/v1beta1',
                    'GET',
                    auth_settings=['BearerToken'],
                    response_type='object',
                    _preload_content=False
                )
                external_metrics_available = True
            except Exception:
                pass

            is_compliant = custom_metrics_available or external_metrics_available
            
            if is_compliant:
                details = 'Custom metrics scaling infrastructure is available'
                impacted_resources = []
            else:
                details = 'No custom metrics scaling infrastructure found'
                impacted_resources = ['custom-metrics-api']
            
            return self._create_check_result('A9', is_compliant, impacted_resources, details)

        except Exception as e:
            logger.error(f'Error checking custom metrics: {str(e)}')
            error_message = f'Error checking custom metrics: {str(e)}'
            return self._create_check_result('A9', False, [], error_message)

    def _check_vertical_pod_autoscaler(self, k8s_api, namespace: Optional[str] = None) -> Dict[str, Any]:
        """Check A10: Vertical Pod Autoscaler (VPA)."""
        try:
            logger.info('Starting VPA check')

            # Check for VPA CRD
            vpa_crd_available = False
            try:
                k8s_api.api_client.call_api(
                    '/apis/autoscaling.k8s.io/v1/verticalpodautoscalers',
                    'GET',
                    auth_settings=['BearerToken'],
                    response_type='object',
                    _preload_content=False
                )
                vpa_crd_available = True
            except Exception:
                pass

            # Check for VPA controller components
            vpa_components_found = []
            try:
                deployments_response = k8s_api.list_resources(
                    kind='Deployment', api_version='apps/v1', namespace='kube-system'
                )
                
                for deployment in deployments_response.items:
                    deployment_dict = deployment.to_dict() if hasattr(deployment, 'to_dict') else deployment
                    metadata = deployment_dict.get('metadata', {})
                    name = metadata.get('name', '')
                    if any(component in name.lower() for component in ['vpa-recommender', 'vpa-updater', 'vpa-admission-controller']):
                        vpa_components_found.append(name)
            except Exception as e:
                logger.error(f'Error checking VPA components: {str(e)}')

            is_compliant = vpa_crd_available and len(vpa_components_found) > 0
            
            if is_compliant:
                details = f'VPA is available with components: {", ".join(vpa_components_found)}'
                impacted_resources = []
            else:
                details = 'VPA is not installed or not properly configured'
                impacted_resources = ['vpa-controller']
            
            return self._create_check_result('A10', is_compliant, impacted_resources, details)

        except Exception as e:
            logger.error(f'Error checking VPA: {str(e)}')
            error_message = f'Error checking VPA: {str(e)}'
            return self._create_check_result('A10', False, [], error_message)

    def _check_prestop_hooks(self, k8s_api, namespace: Optional[str] = None) -> Dict[str, Any]:
        """Check A11: PreStop hooks for graceful termination."""
        workloads_without_prestop = []
        try:
            logger.info(
                f'Starting preStop hooks check, namespace: {namespace if namespace else "all"}'
            )

            # Prepare kwargs for filtering
            kwargs = {}
            if namespace:
                kwargs['namespace'] = namespace

            # Check Deployments and StatefulSets (exclude DaemonSets as they're system services)
            for workload_type in ['Deployment', 'StatefulSet']:
                try:
                    workloads_response = k8s_api.list_resources(
                        kind=workload_type, api_version='apps/v1', **kwargs
                    )

                    for workload in workloads_response.items:
                        try:
                            workload_dict = (
                                workload.to_dict() if hasattr(workload, 'to_dict') else workload
                            )

                            metadata = workload_dict.get('metadata', {})
                            workload_namespace = metadata.get('namespace', 'default')
                            name = metadata.get('name', 'unknown')

                            # Check containers for preStop hooks
                            template_spec = (
                                workload_dict.get('spec', {}).get('template', {}).get('spec', {})
                            )
                            containers = template_spec.get('containers', [])

                            has_prestop_hook = False
                            for container in containers:
                                lifecycle = container.get('lifecycle', {})
                                if lifecycle.get('preStop'):
                                    has_prestop_hook = True
                                    break

                            if not has_prestop_hook:
                                workloads_without_prestop.append(f'{workload_type}: {workload_namespace}/{name}')
                        except Exception as workload_error:
                            logger.error(f'Error processing {workload_type}: {str(workload_error)}')
                except Exception as e:
                    logger.error(f'Error listing {workload_type}s: {str(e)}')

            is_compliant = len(workloads_without_prestop) == 0
            scope_info = f"in namespace '{namespace}'" if namespace else 'across all namespaces'
            detailed_message = f'Found {len(workloads_without_prestop)} workloads without preStop hooks {scope_info}'
            
            return self._create_check_result('A11', is_compliant, workloads_without_prestop, detailed_message)

        except Exception as e:
            logger.error(f'Error checking preStop hooks: {str(e)}')
            import traceback
            logger.error(f'Traceback: {traceback.format_exc()}')
            scope_info = f"in namespace '{namespace}'" if namespace else 'across all namespaces'
            error_message = f'API error while checking preStop hooks {scope_info}: {str(e)}'
            return self._create_check_result('A11', False, [], error_message)

    def _check_service_mesh(self, k8s_api, namespace: Optional[str] = None) -> Dict[str, Any]:
        """Check A12: Service mesh usage."""
        try:
            logger.info('Starting service mesh check')

            service_mesh_found = []
            
            # Check for Istio
            try:
                k8s_api.api_client.call_api(
                    '/apis/networking.istio.io/v1beta1',
                    'GET',
                    auth_settings=['BearerToken'],
                    response_type='object',
                    _preload_content=False
                )
                service_mesh_found.append('Istio')
            except Exception:
                pass

            # Check for Linkerd
            try:
                k8s_api.api_client.call_api(
                    '/apis/linkerd.io/v1alpha2',
                    'GET',
                    auth_settings=['BearerToken'],
                    response_type='object',
                    _preload_content=False
                )
                service_mesh_found.append('Linkerd')
            except Exception:
                pass

            # Check for Consul Connect
            try:
                deployments_response = k8s_api.list_resources(
                    kind='Deployment', api_version='apps/v1'
                )
                
                for deployment in deployments_response.items:
                    deployment_dict = deployment.to_dict() if hasattr(deployment, 'to_dict') else deployment
                    metadata = deployment_dict.get('metadata', {})
                    name = metadata.get('name', '')
                    if 'consul' in name.lower():
                        service_mesh_found.append('Consul')
                        break
            except Exception:
                pass

            is_compliant = len(service_mesh_found) > 0
            
            if is_compliant:
                details = f'Service mesh detected: {", ".join(service_mesh_found)}'
                impacted_resources = service_mesh_found
            else:
                details = 'No service mesh implementation found'
                impacted_resources = []
            
            return self._create_check_result('A12', is_compliant, impacted_resources, details)

        except Exception as e:
            logger.error(f'Error checking service mesh: {str(e)}')
            error_message = f'Error checking service mesh: {str(e)}'
            return self._create_check_result('A12', False, [], error_message)

    def _check_monitoring(self, k8s_api, namespace: Optional[str] = None) -> Dict[str, Any]:
        """Check A13: Application monitoring."""
        try:
            logger.info('Starting monitoring check')

            monitoring_found = []
            
            # Check for Prometheus
            try:
                k8s_api.api_client.call_api(
                    '/apis/monitoring.coreos.com/v1',
                    'GET',
                    auth_settings=['BearerToken'],
                    response_type='object',
                    _preload_content=False
                )
                monitoring_found.append('Prometheus Operator')
            except Exception:
                pass

            # Check for CloudWatch Container Insights
            try:
                daemonsets_response = k8s_api.list_resources(
                    kind='DaemonSet', api_version='apps/v1', namespace='amazon-cloudwatch'
                )
                
                for ds in daemonsets_response.items:
                    ds_dict = ds.to_dict() if hasattr(ds, 'to_dict') else ds
                    metadata = ds_dict.get('metadata', {})
                    name = metadata.get('name', '')
                    if 'cloudwatch' in name.lower():
                        monitoring_found.append('CloudWatch Container Insights')
                        break
            except Exception:
                pass

            # Check for other monitoring solutions
            try:
                deployments_response = k8s_api.list_resources(
                    kind='Deployment', api_version='apps/v1'
                )
                
                for deployment in deployments_response.items:
                    deployment_dict = deployment.to_dict() if hasattr(deployment, 'to_dict') else deployment
                    metadata = deployment_dict.get('metadata', {})
                    name = metadata.get('name', '')
                    if any(monitor in name.lower() for monitor in ['datadog', 'newrelic', 'dynatrace']):
                        monitoring_found.append(name)
            except Exception:
                pass

            is_compliant = len(monitoring_found) > 0
            
            if is_compliant:
                details = f'Monitoring solution detected: {", ".join(monitoring_found)}'
                impacted_resources = monitoring_found
            else:
                details = 'No monitoring solution found'
                impacted_resources = []
            
            return self._create_check_result('A13', is_compliant, impacted_resources, details)

        except Exception as e:
            logger.error(f'Error checking monitoring: {str(e)}')
            error_message = f'Error checking monitoring: {str(e)}'
            return self._create_check_result('A13', False, [], error_message)

    def _check_centralized_logging(self, k8s_api, namespace: Optional[str] = None) -> Dict[str, Any]:
        """Check A14: Centralized logging."""
        try:
            logger.info('Starting centralized logging check')

            logging_found = []
            
            # Check for Elasticsearch/OpenSearch
            try:
                k8s_api.api_client.call_api(
                    '/apis/elasticsearch.k8s.elastic.co/v1',
                    'GET',
                    auth_settings=['BearerToken'],
                    response_type='object',
                    _preload_content=False
                )
                logging_found.append('Elasticsearch')
            except Exception:
                pass

            # Check for Fluentd/Fluent Bit
            try:
                daemonsets_response = k8s_api.list_resources(
                    kind='DaemonSet', api_version='apps/v1'
                )
                
                for ds in daemonsets_response.items:
                    ds_dict = ds.to_dict() if hasattr(ds, 'to_dict') else ds
                    metadata = ds_dict.get('metadata', {})
                    name = metadata.get('name', '')
                    if any(log_tool in name.lower() for log_tool in ['fluentd', 'fluent-bit', 'filebeat']):
                        logging_found.append(name)
            except Exception:
                pass

            # Check for Loki
            try:
                deployments_response = k8s_api.list_resources(
                    kind='Deployment', api_version='apps/v1'
                )
                
                for deployment in deployments_response.items:
                    deployment_dict = deployment.to_dict() if hasattr(deployment, 'to_dict') else deployment
                    metadata = deployment_dict.get('metadata', {})
                    name = metadata.get('name', '')
                    if 'loki' in name.lower():
                        logging_found.append('Loki')
                        break
            except Exception:
                pass

            is_compliant = len(logging_found) > 0
            
            if is_compliant:
                details = f'Centralized logging detected: {", ".join(logging_found)}'
                impacted_resources = logging_found
            else:
                details = 'No centralized logging solution found'
                impacted_resources = []
            
            return self._create_check_result('A14', is_compliant, impacted_resources, details)

        except Exception as e:
            logger.error(f'Error checking centralized logging: {str(e)}')
            error_message = f'Error checking centralized logging: {str(e)}'
            return self._create_check_result('A14', False, [], error_message)    
    def _check_c1(self, k8s_api, cluster_name: str, namespace: Optional[str] = None) -> Dict[str, Any]:
        """Check C1: Monitor Control Plane Logs."""
        try:
            logger.info(f'Starting control plane logs check for cluster: {cluster_name}')

            # Create EKS client using AwsHelper
            eks_client = AwsHelper.create_boto3_client('eks')

            # Get cluster info
            cluster_info = eks_client.describe_cluster(name=cluster_name)
            cluster_data = cluster_info['cluster']
            
            # Check logging configuration
            logging_config = cluster_data.get('logging', {})
            cluster_logging = logging_config.get('clusterLogging', {})
            enabled_types = cluster_logging.get('enabledTypes', [])
            
            # Check if 'api' logging is enabled (minimum requirement)
            api_logging_enabled = any(log_type.get('type') == 'api' for log_type in enabled_types)
            
            is_compliant = api_logging_enabled
            
            if is_compliant:
                enabled_log_types = [log_type.get('type') for log_type in enabled_types]
                details = f'Control plane logging is enabled for: {", ".join(enabled_log_types)}'
                impacted_resources = []
            else:
                details = 'Control plane logging is not enabled'
                impacted_resources = [cluster_name]
            
            return self._create_check_result('C1', is_compliant, impacted_resources, details)

        except Exception as e:
            logger.error(f'Error checking control plane logs: {str(e)}')
            error_message = f'Error checking control plane logs: {str(e)}'
            return self._create_check_result('C1', False, [], error_message)

    def _check_c2(self, k8s_api, cluster_name: str, namespace: Optional[str] = None) -> Dict[str, Any]:
        """Check C2: Cluster Authentication."""
        try:
            logger.info(f'Starting cluster authentication check for cluster: {cluster_name}')

            # Create EKS client using AwsHelper
            eks_client = AwsHelper.create_boto3_client('eks')

            auth_methods_found = []
            
            # Check for EKS Access Entries (modern method)
            try:
                access_entries = eks_client.list_access_entries(clusterName=cluster_name)
                if access_entries.get('accessEntries'):
                    auth_methods_found.append('EKS Access Entries')
            except Exception as e:
                logger.info(f'No EKS Access Entries found: {str(e)}')

            # Check for aws-auth ConfigMap (legacy method)
            try:
                configmaps_response = k8s_api.list_resources(
                    kind='ConfigMap', api_version='v1', namespace='kube-system'
                )
                
                for cm in configmaps_response.items:
                    cm_dict = cm.to_dict() if hasattr(cm, 'to_dict') else cm
                    metadata = cm_dict.get('metadata', {})
                    name = metadata.get('name', '')
                    if name == 'aws-auth':
                        auth_methods_found.append('aws-auth ConfigMap')
                        break
            except Exception as e:
                logger.info(f'Error checking aws-auth ConfigMap: {str(e)}')

            is_compliant = len(auth_methods_found) > 0
            
            if is_compliant:
                details = f'Cluster authentication configured via: {", ".join(auth_methods_found)}'
                impacted_resources = []
            else:
                details = 'No cluster authentication method found'
                impacted_resources = [cluster_name]
            
            return self._create_check_result('C2', is_compliant, impacted_resources, details)

        except Exception as e:
            logger.error(f'Error checking cluster authentication: {str(e)}')
            error_message = f'Error checking cluster authentication: {str(e)}'
            return self._create_check_result('C2', False, [], error_message)

    def _check_c3(self, k8s_api, cluster_name: str, namespace: Optional[str] = None) -> Dict[str, Any]:
        """Check C3: Running large clusters."""
        try:
            logger.info(f'Starting large clusters check for cluster: {cluster_name}')

            # Count total services in the cluster
            services_response = k8s_api.list_resources(kind='Service', api_version='v1')
            service_count = len(services_response.items) if hasattr(services_response, 'items') else 0
            
            # If less than 1000 services, cluster is not considered large
            if service_count < 1000:
                details = f'Cluster has {service_count} services (not a large cluster)'
                return self._create_check_result('C3', True, [], details)

            # For large clusters, check optimizations
            optimizations_missing = []
            
            # Check kube-proxy mode
            try:
                configmaps_response = k8s_api.list_resources(
                    kind='ConfigMap', api_version='v1', namespace='kube-system'
                )
                
                ipvs_mode_enabled = False
                for cm in configmaps_response.items:
                    cm_dict = cm.to_dict() if hasattr(cm, 'to_dict') else cm
                    metadata = cm_dict.get('metadata', {})
                    name = metadata.get('name', '')
                    if 'kube-proxy' in name.lower():
                        data = cm_dict.get('data', {})
                        config_content = data.get('config.conf', '')
                        if 'mode: "ipvs"' in config_content or 'mode: ipvs' in config_content:
                            ipvs_mode_enabled = True
                            break
                
                if not ipvs_mode_enabled:
                    optimizations_missing.append('IPVS mode for kube-proxy')
            except Exception as e:
                logger.error(f'Error checking kube-proxy mode: {str(e)}')

            # Check AWS VPC CNI IP caching
            try:
                daemonsets_response = k8s_api.list_resources(
                    kind='DaemonSet', api_version='apps/v1', namespace='kube-system'
                )
                
                ip_caching_configured = False
                for ds in daemonsets_response.items:
                    ds_dict = ds.to_dict() if hasattr(ds, 'to_dict') else ds
                    metadata = ds_dict.get('metadata', {})
                    name = metadata.get('name', '')
                    if name == 'aws-node':
                        spec = ds_dict.get('spec', {})
                        template = spec.get('template', {})
                        template_spec = template.get('spec', {})
                        containers = template_spec.get('containers', [])
                        
                        for container in containers:
                            env_vars = container.get('env', [])
                            for env_var in env_vars:
                                if env_var.get('name') == 'WARM_IP_TARGET':
                                    ip_caching_configured = True
                                    break
                        break
                
                if not ip_caching_configured:
                    optimizations_missing.append('AWS VPC CNI IP caching')
            except Exception as e:
                logger.error(f'Error checking VPC CNI configuration: {str(e)}')

            is_compliant = len(optimizations_missing) == 0
            
            if is_compliant:
                details = f'Large cluster ({service_count} services) has proper optimizations configured'
                impacted_resources = []
            else:
                details = f'Large cluster ({service_count} services) missing optimizations: {", ".join(optimizations_missing)}'
                impacted_resources = optimizations_missing
            
            return self._create_check_result('C3', is_compliant, impacted_resources, details)

        except Exception as e:
            logger.error(f'Error checking large clusters: {str(e)}')
            error_message = f'Error checking large clusters: {str(e)}'
            return self._create_check_result('C3', False, [], error_message)

    def _check_c4(self, k8s_api, cluster_name: str, namespace: Optional[str] = None) -> Dict[str, Any]:
        """Check C4: EKS Control Plane Endpoint Access Control."""
        try:
            logger.info(f'Starting endpoint access control check for cluster: {cluster_name}')

            # Create EKS client using AwsHelper
            eks_client = AwsHelper.create_boto3_client('eks')

            # Get cluster info
            cluster_info = eks_client.describe_cluster(name=cluster_name)
            cluster_data = cluster_info['cluster']
            
            # Check endpoint configuration
            resources_vpc_config = cluster_data.get('resourcesVpcConfig', {})
            endpoint_config_public_access = resources_vpc_config.get('endpointConfigPublicAccess', True)
            public_access_cidrs = resources_vpc_config.get('publicAccessCidrs', [])
            
            # Check if public access is unrestricted (0.0.0.0/0)
            unrestricted_access = endpoint_config_public_access and '0.0.0.0/0' in public_access_cidrs
            
            is_compliant = not unrestricted_access
            
            if is_compliant:
                if not endpoint_config_public_access:
                    details = 'API server endpoint is private only'
                else:
                    details = f'API server endpoint public access is restricted to: {", ".join(public_access_cidrs)}'
                impacted_resources = []
            else:
                details = 'API server endpoint has unrestricted public access (0.0.0.0/0)'
                impacted_resources = [cluster_name]
            
            return self._create_check_result('C4', is_compliant, impacted_resources, details)

        except Exception as e:
            logger.error(f'Error checking endpoint access control: {str(e)}')
            error_message = f'Error checking endpoint access control: {str(e)}'
            return self._create_check_result('C4', False, [], error_message)

    def _check_c5(self, k8s_api, cluster_name: str, namespace: Optional[str] = None) -> Dict[str, Any]:
        """Check C5: Avoid catch-all admission webhooks."""
        try:
            logger.info('Starting admission webhooks check')

            catch_all_webhooks = []
            
            # Check MutatingAdmissionWebhooks
            try:
                mutating_webhooks_response = k8s_api.list_resources(
                    kind='MutatingAdmissionWebhook', api_version='admissionregistration.k8s.io/v1'
                )
                
                for webhook in mutating_webhooks_response.items:
                    webhook_dict = webhook.to_dict() if hasattr(webhook, 'to_dict') else webhook
                    metadata = webhook_dict.get('metadata', {})
                    name = metadata.get('name', '')
                    
                    webhooks_list = webhook_dict.get('webhooks', [])
                    for wh in webhooks_list:
                        rules = wh.get('rules', [])
                        for rule in rules:
                            api_groups = rule.get('apiGroups', [])
                            api_versions = rule.get('apiVersions', [])
                            resources = rule.get('resources', [])
                            
                            if '*' in api_groups or '*' in api_versions or '*' in resources:
                                catch_all_webhooks.append(f'MutatingAdmissionWebhook: {name}')
                                break
            except Exception as e:
                logger.info(f'Error checking mutating webhooks: {str(e)}')

            # Check ValidatingAdmissionWebhooks
            try:
                validating_webhooks_response = k8s_api.list_resources(
                    kind='ValidatingAdmissionWebhook', api_version='admissionregistration.k8s.io/v1'
                )
                
                for webhook in validating_webhooks_response.items:
                    webhook_dict = webhook.to_dict() if hasattr(webhook, 'to_dict') else webhook
                    metadata = webhook_dict.get('metadata', {})
                    name = metadata.get('name', '')
                    
                    webhooks_list = webhook_dict.get('webhooks', [])
                    for wh in webhooks_list:
                        rules = wh.get('rules', [])
                        for rule in rules:
                            api_groups = rule.get('apiGroups', [])
                            api_versions = rule.get('apiVersions', [])
                            resources = rule.get('resources', [])
                            
                            if '*' in api_groups or '*' in api_versions or '*' in resources:
                                catch_all_webhooks.append(f'ValidatingAdmissionWebhook: {name}')
                                break
            except Exception as e:
                logger.info(f'Error checking validating webhooks: {str(e)}')

            is_compliant = len(catch_all_webhooks) == 0
            
            if is_compliant:
                details = 'No catch-all admission webhooks found'
                impacted_resources = []
            else:
                details = f'Found {len(catch_all_webhooks)} catch-all admission webhooks'
                impacted_resources = catch_all_webhooks
            
            return self._create_check_result('C5', is_compliant, impacted_resources, details)

        except Exception as e:
            logger.error(f'Error checking admission webhooks: {str(e)}')
            error_message = f'Error checking admission webhooks: {str(e)}'
            return self._create_check_result('C5', False, [], error_message)   
    def _check_d1(self, k8s_api, cluster_name: str, namespace: Optional[str] = None) -> Dict[str, Any]:
        """Check D1: Use Kubernetes Cluster Autoscaler or Karpenter."""
        try:
            logger.info('Starting node autoscaling check')

            autoscaling_solutions = []
            
            # Check for Cluster Autoscaler
            try:
                deployments_response = k8s_api.list_resources(
                    kind='Deployment', api_version='apps/v1', namespace='kube-system'
                )
                
                for deployment in deployments_response.items:
                    deployment_dict = deployment.to_dict() if hasattr(deployment, 'to_dict') else deployment
                    metadata = deployment_dict.get('metadata', {})
                    name = metadata.get('name', '')
                    if 'cluster-autoscaler' in name.lower():
                        autoscaling_solutions.append(f'Cluster Autoscaler: {name}')
                        break
            except Exception as e:
                logger.info(f'Error checking cluster autoscaler: {str(e)}')

            # Check for Karpenter
            try:
                k8s_api.api_client.call_api(
                    '/apis/karpenter.sh/v1beta1',
                    'GET',
                    auth_settings=['BearerToken'],
                    response_type='object',
                    _preload_content=False
                )
                
                # Check for Karpenter deployment
                deployments_response = k8s_api.list_resources(
                    kind='Deployment', api_version='apps/v1', namespace='karpenter'
                )
                
                for deployment in deployments_response.items:
                    deployment_dict = deployment.to_dict() if hasattr(deployment, 'to_dict') else deployment
                    metadata = deployment_dict.get('metadata', {})
                    name = metadata.get('name', '')
                    if 'karpenter' in name.lower():
                        autoscaling_solutions.append(f'Karpenter: {name}')
                        break
            except Exception as e:
                logger.info(f'Karpenter not found: {str(e)}')

            is_compliant = len(autoscaling_solutions) > 0
            
            if is_compliant:
                details = f'Node autoscaling available: {", ".join(autoscaling_solutions)}'
                impacted_resources = autoscaling_solutions
            else:
                details = 'No node autoscaling solution found'
                impacted_resources = []
            
            return self._create_check_result('D1', is_compliant, impacted_resources, details)

        except Exception as e:
            logger.error(f'Error checking node autoscaling: {str(e)}')
            error_message = f'Error checking node autoscaling: {str(e)}'
            return self._create_check_result('D1', False, [], error_message)

    def _check_d2(self, k8s_api, cluster_name: str, namespace: Optional[str] = None) -> Dict[str, Any]:
        """Check D2: Worker nodes spread across multiple AZs."""
        try:
            logger.info('Starting AZ distribution check')

            # Get all nodes
            nodes_response = k8s_api.list_resources(kind='Node', api_version='v1')
            
            az_distribution = {}
            total_nodes = 0
            
            for node in nodes_response.items:
                try:
                    node_dict = node.to_dict() if hasattr(node, 'to_dict') else node
                    metadata = node_dict.get('metadata', {})
                    labels = metadata.get('labels', {})
                    
                    # Get AZ from node labels
                    az = labels.get('topology.kubernetes.io/zone') or labels.get('failure-domain.beta.kubernetes.io/zone')
                    
                    if az:
                        az_distribution[az] = az_distribution.get(az, 0) + 1
                        total_nodes += 1
                except Exception as node_error:
                    logger.error(f'Error processing node: {str(node_error)}')

            # Check distribution
            num_azs = len(az_distribution)
            is_compliant = num_azs >= 2
            
            if is_compliant:
                # Check if distribution is reasonably balanced (within 20% variance)
                if num_azs > 1:
                    avg_nodes_per_az = total_nodes / num_azs
                    max_variance = 0.2 * avg_nodes_per_az
                    balanced = all(abs(count - avg_nodes_per_az) <= max_variance for count in az_distribution.values())
                    
                    if balanced:
                        details = f'Nodes well distributed across {num_azs} AZs: {dict(az_distribution)}'
                    else:
                        details = f'Nodes spread across {num_azs} AZs but unbalanced: {dict(az_distribution)}'
                else:
                    details = f'Nodes distributed across {num_azs} AZs: {dict(az_distribution)}'
                impacted_resources = []
            else:
                if num_azs == 1:
                    details = f'All {total_nodes} nodes in single AZ: {list(az_distribution.keys())[0]}'
                else:
                    details = f'Only {total_nodes} nodes found, unable to determine AZ distribution'
                impacted_resources = [cluster_name]
            
            return self._create_check_result('D2', is_compliant, impacted_resources, details)

        except Exception as e:
            logger.error(f'Error checking AZ distribution: {str(e)}')
            error_message = f'Error checking AZ distribution: {str(e)}'
            return self._create_check_result('D2', False, [], error_message)

    def _check_d3(self, k8s_api, cluster_name: str, namespace: Optional[str] = None) -> Dict[str, Any]:
        """Check D3: Configure Resource Requests/Limits."""
        deployments_without_resources = []
        try:
            logger.info(
                f'Starting resource requests/limits check, namespace: {namespace if namespace else "all"}'
            )

            # Prepare kwargs for filtering
            kwargs = {}
            if namespace:
                kwargs['namespace'] = namespace

            # Check Deployments
            deployments_response = k8s_api.list_resources(
                kind='Deployment', api_version='apps/v1', **kwargs
            )

            for deployment in deployments_response.items:
                try:
                    deployment_dict = (
                        deployment.to_dict() if hasattr(deployment, 'to_dict') else deployment
                    )

                    metadata = deployment_dict.get('metadata', {})
                    deploy_namespace = metadata.get('namespace', 'default')
                    name = metadata.get('name', 'unknown')

                    # Check containers for resource requests and limits
                    template_spec = (
                        deployment_dict.get('spec', {}).get('template', {}).get('spec', {})
                    )
                    containers = template_spec.get('containers', [])

                    has_complete_resources = True
                    for container in containers:
                        resources = container.get('resources', {})
                        requests = resources.get('requests', {})
                        limits = resources.get('limits', {})
                        
                        # Check if both CPU and memory requests and limits are set
                        if not (requests.get('cpu') and requests.get('memory') and 
                                limits.get('cpu') and limits.get('memory')):
                            has_complete_resources = False
                            break

                    if not has_complete_resources:
                        deployments_without_resources.append(f'{deploy_namespace}/{name}')
                except Exception as deploy_error:
                    logger.error(f'Error processing deployment: {str(deploy_error)}')

            is_compliant = len(deployments_without_resources) == 0
            scope_info = f"in namespace '{namespace}'" if namespace else 'across all namespaces'
            detailed_message = f'Found {len(deployments_without_resources)} deployments without complete resource specifications {scope_info}'
            
            return self._create_check_result('D3', is_compliant, deployments_without_resources, detailed_message)

        except Exception as e:
            logger.error(f'Error checking resource requests/limits: {str(e)}')
            import traceback
            logger.error(f'Traceback: {traceback.format_exc()}')
            scope_info = f"in namespace '{namespace}'" if namespace else 'across all namespaces'
            error_message = f'API error while checking resource requests/limits {scope_info}: {str(e)}'
            return self._create_check_result('D3', False, [], error_message)

    def _check_d4(self, k8s_api, cluster_name: str, namespace: Optional[str] = None) -> Dict[str, Any]:
        """Check D4: Namespace ResourceQuotas."""
        namespaces_without_quotas = []
        try:
            logger.info('Starting namespace resource quotas check')

            # Get all namespaces
            namespaces_response = k8s_api.list_resources(kind='Namespace', api_version='v1')
            
            # Get all resource quotas
            quotas_response = k8s_api.list_resources(kind='ResourceQuota', api_version='v1')
            
            # Build set of namespaces that have quotas
            namespaces_with_quotas = set()
            for quota in quotas_response.items:
                try:
                    quota_dict = quota.to_dict() if hasattr(quota, 'to_dict') else quota
                    metadata = quota_dict.get('metadata', {})
                    quota_namespace = metadata.get('namespace')
                    if quota_namespace:
                        namespaces_with_quotas.add(quota_namespace)
                except Exception as quota_error:
                    logger.error(f'Error processing quota: {str(quota_error)}')

            # Check each namespace (excluding system namespaces)
            for ns in namespaces_response.items:
                try:
                    ns_dict = ns.to_dict() if hasattr(ns, 'to_dict') else ns
                    metadata = ns_dict.get('metadata', {})
                    ns_name = metadata.get('name')
                    
                    # Skip system namespaces
                    if ns_name in ['kube-system', 'kube-public', 'kube-node-lease']:
                        continue
                    
                    # If namespace filter is provided, only check that namespace
                    if namespace and ns_name != namespace:
                        continue
                    
                    if ns_name not in namespaces_with_quotas:
                        namespaces_without_quotas.append(ns_name)
                except Exception as ns_error:
                    logger.error(f'Error processing namespace: {str(ns_error)}')

            is_compliant = len(namespaces_without_quotas) == 0
            
            if namespace:
                # If checking specific namespace
                if namespace in namespaces_without_quotas:
                    details = f'Namespace {namespace} does not have ResourceQuota'
                else:
                    details = f'Namespace {namespace} has ResourceQuota configured'
            else:
                # If checking all namespaces
                details = f'Found {len(namespaces_without_quotas)} namespaces without ResourceQuotas'
            
            return self._create_check_result('D4', is_compliant, namespaces_without_quotas, details)

        except Exception as e:
            logger.error(f'Error checking namespace resource quotas: {str(e)}')
            error_message = f'Error checking namespace resource quotas: {str(e)}'
            return self._create_check_result('D4', False, [], error_message)

    def _check_d5(self, k8s_api, cluster_name: str, namespace: Optional[str] = None) -> Dict[str, Any]:
        """Check D5: Namespace LimitRanges."""
        namespaces_without_limits = []
        try:
            logger.info('Starting namespace limit ranges check')

            # Get all namespaces
            namespaces_response = k8s_api.list_resources(kind='Namespace', api_version='v1')
            
            # Get all limit ranges
            limits_response = k8s_api.list_resources(kind='LimitRange', api_version='v1')
            
            # Build set of namespaces that have limit ranges
            namespaces_with_limits = set()
            for limit_range in limits_response.items:
                try:
                    lr_dict = limit_range.to_dict() if hasattr(limit_range, 'to_dict') else limit_range
                    metadata = lr_dict.get('metadata', {})
                    lr_namespace = metadata.get('namespace')
                    if lr_namespace:
                        namespaces_with_limits.add(lr_namespace)
                except Exception as lr_error:
                    logger.error(f'Error processing limit range: {str(lr_error)}')

            # Check each namespace (excluding system namespaces)
            for ns in namespaces_response.items:
                try:
                    ns_dict = ns.to_dict() if hasattr(ns, 'to_dict') else ns
                    metadata = ns_dict.get('metadata', {})
                    ns_name = metadata.get('name')
                    
                    # Skip system namespaces
                    if ns_name in ['kube-system', 'kube-public', 'kube-node-lease']:
                        continue
                    
                    # If namespace filter is provided, only check that namespace
                    if namespace and ns_name != namespace:
                        continue
                    
                    if ns_name not in namespaces_with_limits:
                        namespaces_without_limits.append(ns_name)
                except Exception as ns_error:
                    logger.error(f'Error processing namespace: {str(ns_error)}')

            is_compliant = len(namespaces_without_limits) == 0
            
            if namespace:
                # If checking specific namespace
                if namespace in namespaces_without_limits:
                    details = f'Namespace {namespace} does not have LimitRange'
                else:
                    details = f'Namespace {namespace} has LimitRange configured'
            else:
                # If checking all namespaces
                details = f'Found {len(namespaces_without_limits)} namespaces without LimitRanges'
            
            return self._create_check_result('D5', is_compliant, namespaces_without_limits, details)

        except Exception as e:
            logger.error(f'Error checking namespace limit ranges: {str(e)}')
            error_message = f'Error checking namespace limit ranges: {str(e)}'
            return self._create_check_result('D5', False, [], error_message)

    def _check_d6(self, k8s_api, cluster_name: str, namespace: Optional[str] = None) -> Dict[str, Any]:
        """Check D6: Monitor CoreDNS metrics."""
        try:
            logger.info('Starting CoreDNS metrics check')

            # Check for CoreDNS deployment
            coredns_found = False
            try:
                deployments_response = k8s_api.list_resources(
                    kind='Deployment', api_version='apps/v1', namespace='kube-system'
                )
                
                for deployment in deployments_response.items:
                    deployment_dict = deployment.to_dict() if hasattr(deployment, 'to_dict') else deployment
                    metadata = deployment_dict.get('metadata', {})
                    name = metadata.get('name', '')
                    if name == 'coredns':
                        coredns_found = True
                        break
            except Exception as e:
                logger.error(f'Error checking CoreDNS deployment: {str(e)}')

            # Check for monitoring setup (ServiceMonitor or similar)
            monitoring_found = False
            try:
                # Check for Prometheus ServiceMonitor
                k8s_api.api_client.call_api(
                    '/apis/monitoring.coreos.com/v1',
                    'GET',
                    auth_settings=['BearerToken'],
                    response_type='object',
                    _preload_content=False
                )
                
                servicemonitors_response = k8s_api.list_resources(
                    kind='ServiceMonitor', api_version='monitoring.coreos.com/v1', namespace='kube-system'
                )
                
                for sm in servicemonitors_response.items:
                    sm_dict = sm.to_dict() if hasattr(sm, 'to_dict') else sm
                    metadata = sm_dict.get('metadata', {})
                    name = metadata.get('name', '')
                    if 'coredns' in name.lower():
                        monitoring_found = True
                        break
            except Exception as e:
                logger.info(f'ServiceMonitor not found: {str(e)}')

            is_compliant = coredns_found and monitoring_found
            
            if is_compliant:
                details = 'CoreDNS is deployed and metrics monitoring is configured'
                impacted_resources = []
            elif coredns_found and not monitoring_found:
                details = 'CoreDNS is deployed but metrics monitoring is not configured'
                impacted_resources = ['coredns-metrics']
            else:
                details = 'CoreDNS deployment not found'
                impacted_resources = ['coredns']
            
            return self._create_check_result('D6', is_compliant, impacted_resources, details)

        except Exception as e:
            logger.error(f'Error checking CoreDNS metrics: {str(e)}')
            error_message = f'Error checking CoreDNS metrics: {str(e)}'
            return self._create_check_result('D6', False, [], error_message)

    def _check_d7(self, k8s_api, cluster_name: str, namespace: Optional[str] = None) -> Dict[str, Any]:
        """Check D7: CoreDNS Configuration."""
        try:
            logger.info(f'Starting CoreDNS configuration check for cluster: {cluster_name}')

            if not cluster_name:
                details = 'No cluster name provided'
                return self._create_check_result('D7', False, [], details)

            # Create EKS client using AwsHelper
            eks_client = AwsHelper.create_boto3_client('eks')

            # Get cluster info
            cluster_info = eks_client.describe_cluster(name=cluster_name)
            cluster_data = cluster_info['cluster']

            # Check if the cluster is an EKS auto mode cluster
            is_auto_mode = False
            compute_config = cluster_data.get('computeConfig', {})
            if compute_config and compute_config.get('enabled', False):
                is_auto_mode = True

            # Check if the cluster is using EKS managed addons for CoreDNS
            has_managed_coredns = False
            try:
                addons = eks_client.list_addons(clusterName=cluster_name)
                for addon in addons.get('addons', []):
                    if addon.lower() == 'coredns':
                        has_managed_coredns = True
                        break
            except Exception as e:
                logger.warning(f'Error checking EKS managed addons: {str(e)}')

            # Check for CoreDNS deployment
            coredns_found = False
            try:
                deployments = k8s_api.list_resources(
                    kind='Deployment',
                    api_version='apps/v1',
                    namespace='kube-system',
                    label_selector='k8s-app=kube-dns',
                )

                if hasattr(deployments, 'items') and len(deployments.items) > 0:
                    coredns_found = True
            except Exception as e:
                logger.warning(f'Error checking CoreDNS deployment: {str(e)}')

            # Determine compliance
            if is_auto_mode:
                # Auto mode clusters always have managed CoreDNS
                is_compliant = True
                details = 'EKS auto mode cluster - CoreDNS is automatically managed'
                impacted_resources = []
            elif has_managed_coredns:
                # Regular cluster with managed addon
                is_compliant = True
                details = 'CoreDNS is managed by EKS managed addon'
                impacted_resources = []
            elif coredns_found:
                # Regular cluster with self-managed CoreDNS
                is_compliant = False
                details = 'CoreDNS is self-managed - consider using EKS managed addon'
                impacted_resources = ['coredns']
            else:
                # No CoreDNS found
                is_compliant = False
                details = 'CoreDNS deployment not found'
                impacted_resources = ['coredns']
            
            return self._create_check_result('D7', is_compliant, impacted_resources, details)

        except Exception as e:
            logger.error(f'Error checking CoreDNS configuration: {str(e)}')
            import traceback
            logger.error(f'Traceback: {traceback.format_exc()}')
            error_message = f'Error checking CoreDNS configuration: {str(e)}'
            return self._create_check_result('D7', False, [], error_message)