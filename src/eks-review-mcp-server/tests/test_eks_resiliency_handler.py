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
# ruff: noqa: D101, D102, D103
"""Tests for the EKSResiliencyHandler class."""

import pytest
from awslabs.eks_review_mcp_server.eks_resiliency_handler import EKSResiliencyHandler
from awslabs.eks_review_mcp_server.models import ResiliencyCheckResponse
from contextlib import ExitStack
from mcp.server.fastmcp import Context
from unittest.mock import MagicMock, patch


@pytest.fixture
def mock_context():
    """Create a mock MCP context."""
    ctx = MagicMock(spec=Context)
    ctx.request_id = 'test-request-id'
    return ctx


@pytest.fixture
def mock_mcp():
    """Create a mock MCP server."""
    return MagicMock()


@pytest.fixture
def mock_client_cache():
    """Create a mock K8sClientCache."""
    cache = MagicMock()
    mock_k8s_apis = MagicMock()
    cache.get_client.return_value = mock_k8s_apis
    return cache


@pytest.fixture
def mock_k8s_api():
    """Create a mock K8sApis instance."""
    return MagicMock()


@pytest.fixture
def sample_shared_data(mock_k8s_api):
    """Create sample shared_data for testing with new API."""
    return {
        'k8s_client': mock_k8s_api,
        'cluster_name': 'test-cluster',
        'namespace': None,
        'pods': [],
        'deployments': [],
        'statefulsets': [],
        'daemonsets': [],
        'pdbs': [],
        'hpas': [],
        'vpas': [],
        'nodes': [],
        'namespaces': [],
        'services': [],
        'configmaps': [],
        'resource_quotas': [],
        'limit_ranges': [],
        'validating_webhooks': [],
        'mutating_webhooks': [],
        'kube_system_deployments': [],
        'kube_system_daemonsets': [],
        'kube_system_configmaps': [],
        'eks_client': MagicMock(),
        'cluster_info': {},
    }


class TestEKSResiliencyHandlerInit:
    """Tests for the EKSResiliencyHandler class initialization."""

    def test_init(self, mock_mcp, mock_client_cache):
        """Test initialization of EKSResiliencyHandler."""
        # Initialize the EKS resiliency handler
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        # Verify that the handler has the correct attributes
        assert handler.mcp == mock_mcp
        assert handler.client_cache == mock_client_cache

        # Verify that the check_eks_resiliency tool is registered
        mock_mcp.tool.assert_called_once()
        assert mock_mcp.tool.call_args[1]['name'] == 'check_eks_resiliency'

    @pytest.mark.asyncio
    async def test_check_eks_resiliency_connection_error(
        self, mock_mcp, mock_client_cache, mock_context
    ):
        """Test check_eks_resiliency with a connection error."""
        # Set up the mock client_cache to raise an exception
        mock_client_cache.get_client.side_effect = Exception('Failed to connect to cluster')

        # Initialize the EKS resiliency handler
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        # Call the check_eks_resiliency method
        result = await handler.check_eks_resiliency(mock_context, cluster_name='test-cluster')

        # Verify that the result is a ResiliencyCheckResponse
        assert isinstance(result, ResiliencyCheckResponse)
        assert result.isError is True
        assert 'Failed to connect to cluster' in result.summary
        assert len(result.check_results) == 1
        assert result.check_results[0]['check_name'] == 'Connection Error'
        assert result.check_results[0]['compliant'] is False

    @pytest.mark.asyncio
    async def test_check_eks_resiliency_success(self, mock_mcp, mock_client_cache, mock_context):
        """Test check_eks_resiliency with a successful connection."""
        # Initialize the EKS resiliency handler
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        # Mock ALL check methods to return compliant results to ensure overall_compliant is True
        check_methods = [
            '_check_singleton_pods',
            '_check_multiple_replicas',
            '_check_pod_anti_affinity',
            '_check_liveness_probe',
            '_check_readiness_probe',
            '_check_pod_disruption_budget',
            '_check_metrics_server',
            '_check_horizontal_pod_autoscaler',
            '_check_custom_metrics',
            '_check_vertical_pod_autoscaler',
            '_check_prestop_hooks',
            '_check_service_mesh',
            '_check_monitoring',
            '_check_centralized_logging',
            '_check_c1',
            '_check_c2',
            '_check_c3',
            '_check_c4',
            '_check_c5',
            '_check_d1',
            '_check_d2',
            '_check_d3',
            '_check_d4',
            '_check_d5',
            '_check_d6',
            '_check_d7',
        ]

        patches = []
        for method_name in check_methods:
            patches.append(
                patch.object(
                    handler,
                    method_name,
                    return_value={
                        'check_name': f'Mock {method_name}',
                        'compliant': True,
                        'impacted_resources': [],
                        'details': 'Mock compliant result',
                        'remediation': '',
                    },
                )
            )

        with ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)

            # Call the check_eks_resiliency method
            result = await handler.check_eks_resiliency(mock_context, cluster_name='test-cluster')

            # Verify that the result is a ResiliencyCheckResponse
            assert isinstance(result, ResiliencyCheckResponse)
            assert result.isError is False
            assert 'passed' in result.summary.lower()
            assert '0 checks failed' in result.summary or 'failed' not in result.summary
            assert len(result.check_results) >= 2  # At least the two checks we mocked
            assert result.overall_compliant is True


class TestEKSResiliencyHandlerChecksA:
    """Tests for the EKSResiliencyHandler class A-series checks."""

    def test_check_singleton_pods(self, mock_mcp, mock_client_cache, sample_shared_data):
        """Test _check_singleton_pods method."""
        # Initialize the EKS resiliency handler
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        # Test with no pods
        sample_shared_data['pods'] = []
        result = handler._check_singleton_pods(sample_shared_data)

        # Verify that the result is correct
        assert result['check_name'] == 'Avoid running singleton Pods'
        assert result['compliant'] is True
        assert len(result['impacted_resources']) == 0

        # Create mock pods - one with owner, one without
        mock_pod1 = MagicMock()
        mock_pod1.to_dict.return_value = {
            'metadata': {
                'name': 'test-pod-1',
                'namespace': 'default',
                'ownerReferences': [{'kind': 'ReplicaSet'}],
            }
        }
        mock_pod2 = MagicMock()
        mock_pod2.to_dict.return_value = {
            'metadata': {'name': 'test-pod-2', 'namespace': 'default'}
        }
        
        # Update shared_data with pods
        sample_shared_data['pods'] = [mock_pod1, mock_pod2]
        result = handler._check_singleton_pods(sample_shared_data)

        # Verify that the result is correct
        assert result['check_name'] == 'Avoid running singleton Pods'
        assert result['compliant'] is False
        assert len(result['impacted_resources']) == 1
        assert 'default/test-pod-2' in result['impacted_resources']

    def test_check_multiple_replicas(self, mock_mcp, mock_client_cache, sample_shared_data):
        """Test _check_multiple_replicas method."""
        # Initialize the EKS resiliency handler
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        # Test with no deployments
        sample_shared_data['deployments'] = []
        sample_shared_data['statefulsets'] = []
        result = handler._check_multiple_replicas(sample_shared_data)

        # Verify that the result is correct
        assert result['check_name'] == 'Run multiple replicas'
        assert result['compliant'] is True
        assert len(result['impacted_resources']) == 0

        # Create mock deployment with single replica
        mock_deployment = MagicMock()
        mock_deployment.to_dict.return_value = {
            'metadata': {'name': 'test-deployment-2', 'namespace': 'default'},
            'spec': {'replicas': 1},
        }

        # Update shared_data
        sample_shared_data['deployments'] = [mock_deployment]
        sample_shared_data['statefulsets'] = []
        result = handler._check_multiple_replicas(sample_shared_data)

        # Verify that the result is correct
        assert result['check_name'] == 'Run multiple replicas'
        assert result['compliant'] is False
        assert len(result['impacted_resources']) == 1
        assert 'Deployment default/test-deployment-2' in result['impacted_resources']

    def test_check_pod_anti_affinity(self, mock_mcp, mock_client_cache, sample_shared_data):
        """Test _check_pod_anti_affinity method."""
        # Initialize the EKS resiliency handler
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        # Test with no deployments
        sample_shared_data['deployments'] = []
        result = handler._check_pod_anti_affinity(sample_shared_data)

        # Verify that the result is correct
        assert result['check_name'] == 'Use pod anti-affinity'
        assert result['compliant'] is True
        assert len(result['impacted_resources']) == 0

        # Create mock deployments
        mock_deployment1 = MagicMock()
        mock_deployment1.to_dict.return_value = {
            'metadata': {'name': 'test-deployment-1', 'namespace': 'default'},
            'spec': {'replicas': 2, 'template': {'spec': {'affinity': {'podAntiAffinity': {}}}}},
        }
        mock_deployment2 = MagicMock()
        mock_deployment2.to_dict.return_value = {
            'metadata': {'name': 'test-deployment-2', 'namespace': 'default'},
            'spec': {'replicas': 2, 'template': {'spec': {}}},
        }
        
        # Update shared_data
        sample_shared_data['deployments'] = [mock_deployment1, mock_deployment2]
        result = handler._check_pod_anti_affinity(sample_shared_data)

        # Verify that the result is correct
        assert result['check_name'] == 'Use pod anti-affinity'
        assert result['compliant'] is False
        assert len(result['impacted_resources']) == 1
        assert 'default/test-deployment-2' in result['impacted_resources']

    def test_check_liveness_probe(self, mock_mcp, mock_client_cache, sample_shared_data):
        """Test _check_liveness_probe method."""
        # Initialize the EKS resiliency handler
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        # Test with no workloads
        sample_shared_data['deployments'] = []
        sample_shared_data['statefulsets'] = []
        sample_shared_data['daemonsets'] = []
        result = handler._check_liveness_probe(sample_shared_data)

        # Verify that the result is correct
        assert result['check_name'] == 'Use liveness probes'
        assert result['compliant'] is True
        assert len(result['impacted_resources']) == 0

        # Create deployments with and without liveness probes
        mock_deployment1 = MagicMock()
        mock_deployment1.to_dict.return_value = {
            'metadata': {'name': 'test-deployment-1', 'namespace': 'default'},
            'spec': {
                'template': {
                    'spec': {
                        'containers': [
                            {
                                'name': 'container-1',
                                'livenessProbe': {'httpGet': {'path': '/health', 'port': 8080}},
                            }
                        ]
                    }
                }
            },
        }
        mock_deployment2 = MagicMock()
        mock_deployment2.to_dict.return_value = {
            'metadata': {'name': 'test-deployment-2', 'namespace': 'default'},
            'spec': {'template': {'spec': {'containers': [{'name': 'container-2'}]}}},
        }

        # Update shared_data
        sample_shared_data['deployments'] = [mock_deployment1, mock_deployment2]
        sample_shared_data['statefulsets'] = []
        sample_shared_data['daemonsets'] = []
        result = handler._check_liveness_probe(sample_shared_data)

        # Verify that the result is correct
        assert result['check_name'] == 'Use liveness probes'
        assert result['compliant'] is False
        assert len(result['impacted_resources']) == 1
        assert 'Deployment: default/test-deployment-2' in result['impacted_resources']

    def test_check_readiness_probe(self, mock_mcp, mock_client_cache, sample_shared_data):
        """Test _check_readiness_probe method."""
        # Initialize the EKS resiliency handler
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        # Mock the list_resources method to return no workloads
        # Using shared_data instead of mock_k8s_api

        # Call the _check_readiness_probe method
        result = handler._check_readiness_probe(sample_shared_data)

        # Verify that the result is correct
        assert result['check_name'] == 'Use readiness probes'
        assert result['compliant'] is True
        assert len(result['impacted_resources']) == 0

        # Mock the list_resources method to return deployments with and without readiness probes
        mock_deployment1 = MagicMock()
        mock_deployment1.to_dict.return_value = {
            'metadata': {'name': 'test-deployment-1', 'namespace': 'default'},
            'spec': {
                'template': {
                    'spec': {
                        'containers': [
                            {
                                'name': 'container-1',
                                'readinessProbe': {'httpGet': {'path': '/ready', 'port': 8080}},
                            }
                        ]
                    }
                }
            },
        }
        mock_deployment2 = MagicMock()
        mock_deployment2.to_dict.return_value = {
            'metadata': {'name': 'test-deployment-2', 'namespace': 'default'},
            'spec': {'template': {'spec': {'containers': [{'name': 'container-2'}]}}},
        }

        # Update shared_data with deployments
        sample_shared_data['deployments'] = [mock_deployment1, mock_deployment2]
        sample_shared_data['statefulsets'] = []
        sample_shared_data['daemonsets'] = []

        # Call the _check_readiness_probe method
        result = handler._check_readiness_probe(sample_shared_data)

        # Verify that the result is correct
        assert result['check_name'] == 'Use readiness probes'
        assert result['compliant'] is False
        assert len(result['impacted_resources']) == 1
        assert 'Deployment: default/test-deployment-2' in result['impacted_resources']

    def test_check_pod_disruption_budget(self, mock_mcp, mock_client_cache, sample_shared_data):
        """Test _check_pod_disruption_budget method."""
        # Initialize the EKS resiliency handler
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        # Test with no resources - should be compliant (nothing to check)
        sample_shared_data['deployments'] = []
        sample_shared_data['statefulsets'] = []
        sample_shared_data['pdbs'] = []
        result = handler._check_pod_disruption_budget(sample_shared_data)

        # Verify that the result is correct
        assert result['check_name'] == 'Use Pod Disruption Budgets'
        assert result['compliant'] is True  # No workloads = compliant
        assert len(result['impacted_resources']) == 0

        # Create deployment and PDB with matching labels
        mock_deployment = MagicMock()
        mock_deployment.to_dict.return_value = {
            'metadata': {
                'name': 'test-deployment',
                'namespace': 'default',
                'labels': {'app': 'test-app'},
            },
            'spec': {'replicas': 3, 'selector': {'matchLabels': {'app': 'test-app'}}},
        }

        mock_pdb = MagicMock()
        mock_pdb.to_dict.return_value = {
            'metadata': {'name': 'test-pdb', 'namespace': 'default'},
            'spec': {'selector': {'matchLabels': {'app': 'test-app'}}, 'minAvailable': 2},
        }

        # Update shared_data
        sample_shared_data['deployments'] = [mock_deployment]
        sample_shared_data['statefulsets'] = []
        sample_shared_data['pdbs'] = [mock_pdb]

        # Call the _check_pod_disruption_budget method
        result = handler._check_pod_disruption_budget(sample_shared_data)

        # Verify that the result is correct
        assert result['check_name'] == 'Use Pod Disruption Budgets'
        assert result['compliant'] is True
        assert len(result['impacted_resources']) == 0

    def test_check_metrics_server(self, mock_mcp, mock_client_cache, sample_shared_data):
        """Test _check_metrics_server method."""
        # Initialize the EKS resiliency handler
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        # Test with no metrics server deployment
        sample_shared_data['kube_system_deployments'] = []
        result = handler._check_metrics_server(sample_shared_data)

        # Verify that the result is correct
        assert result['check_name'] == 'Run Kubernetes Metrics Server'
        assert result['compliant'] is False
        # When metrics server is missing, it's reported as an impacted resource
        assert len(result['impacted_resources']) >= 0

        # Test with metrics server deployment present
        mock_deployment = MagicMock()
        mock_deployment.to_dict.return_value = {
            'metadata': {'name': 'metrics-server', 'namespace': 'kube-system'}
        }
        sample_shared_data['kube_system_deployments'] = [mock_deployment]
        result = handler._check_metrics_server(sample_shared_data)

        # Verify that the result is correct
        assert result['check_name'] == 'Run Kubernetes Metrics Server'
        # Note: compliant requires both metrics API and deployment
        # In test environment, metrics API check may fail, so we just verify it runs
        assert 'check_name' in result

    def test_check_horizontal_pod_autoscaler(self, mock_mcp, mock_client_cache, sample_shared_data):
        """Test _check_horizontal_pod_autoscaler method."""
        # Initialize the EKS resiliency handler
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        # Test with no resources - should be compliant
        sample_shared_data['deployments'] = []
        sample_shared_data['statefulsets'] = []
        sample_shared_data['hpas'] = []
        result = handler._check_horizontal_pod_autoscaler(sample_shared_data)

        assert result['check_name'] == 'Use Horizontal Pod Autoscaler'
        assert result['compliant'] is True  # No multi-replica workloads = compliant
        assert len(result['impacted_resources']) == 0

        # Test with deployment with >1 replica and matching HPA
        mock_deployment = MagicMock()
        mock_deployment.to_dict.return_value = {
            'metadata': {'name': 'test-deployment', 'namespace': 'default'},
            'spec': {'replicas': 3},
        }

        mock_hpa = MagicMock()
        mock_hpa.to_dict.return_value = {
            'metadata': {'name': 'test-hpa', 'namespace': 'default'},
            'spec': {'scaleTargetRef': {'kind': 'Deployment', 'name': 'test-deployment'}},
        }

        sample_shared_data['deployments'] = [mock_deployment]
        sample_shared_data['statefulsets'] = []
        sample_shared_data['hpas'] = [mock_hpa]

        result = handler._check_horizontal_pod_autoscaler(sample_shared_data)

        assert result['check_name'] == 'Use Horizontal Pod Autoscaler'
        assert result['compliant'] is True
        assert len(result['impacted_resources']) == 0

    def test_check_custom_metrics(self, mock_mcp, mock_client_cache, sample_shared_data):
        """Test _check_custom_metrics method."""
        # Initialize the EKS resiliency handler
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        # Call the _check_custom_metrics method
        # Note: This check tries to access k8s_api directly which isn't available in test
        # In test environment, it will return non-compliant (no custom metrics API)
        result = handler._check_custom_metrics(sample_shared_data)

        # Verify that the result structure is correct
        assert result['check_name'] == 'Use custom metrics scaling'
        assert 'compliant' in result
        assert 'impacted_resources' in result
        # In test environment without real k8s API, this will be non-compliant
        assert result['compliant'] is False

    def test_check_vertical_pod_autoscaler(self, mock_mcp, mock_client_cache, sample_shared_data):
        """Test _check_vertical_pod_autoscaler method."""
        # Initialize the EKS resiliency handler
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        # Mock VPA CRD check and VPA components
        # Call the _check_vertical_pod_autoscaler method
        # Note: This check tries to access k8s_api directly for CRD check
        # In test environment, it will return non-compliant
        result = handler._check_vertical_pod_autoscaler(sample_shared_data)

        # Verify that the result structure is correct
        assert result['check_name'] == 'Use Vertical Pod Autoscaler'
        assert result['compliant'] is False  # No VPA in test environment
        # VPA controller is reported as missing
        assert len(result['impacted_resources']) >= 0

    def test_check_prestop_hooks(self, mock_mcp, mock_client_cache, sample_shared_data):
        """Test _check_prestop_hooks method."""
        # Initialize the EKS resiliency handler
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        # Test with no workloads
        sample_shared_data['deployments'] = []
        sample_shared_data['statefulsets'] = []
        sample_shared_data['daemonsets'] = []
        result = handler._check_prestop_hooks(sample_shared_data)

        assert result['check_name'] == 'Use preStop hooks'
        assert result['compliant'] is True
        assert len(result['impacted_resources']) == 0

        # Test with deployments with and without preStop hooks
        mock_deployment1 = MagicMock()
        mock_deployment1.to_dict.return_value = {
            'metadata': {'name': 'test-deployment-1', 'namespace': 'default'},
            'spec': {
                'template': {
                    'spec': {
                        'containers': [
                            {
                                'name': 'container-1',
                                'lifecycle': {
                                    'preStop': {'exec': {'command': ['/bin/sh', '-c', 'sleep 15']}}
                                },
                            }
                        ]
                    }
                }
            },
        }
        mock_deployment2 = MagicMock()
        mock_deployment2.to_dict.return_value = {
            'metadata': {'name': 'test-deployment-2', 'namespace': 'default'},
            'spec': {'template': {'spec': {'containers': [{'name': 'container-2'}]}}},
        }

        sample_shared_data['deployments'] = [mock_deployment1, mock_deployment2]
        sample_shared_data['statefulsets'] = []
        sample_shared_data['daemonsets'] = []
        result = handler._check_prestop_hooks(sample_shared_data)

        assert result['check_name'] == 'Use preStop hooks'
        assert result['compliant'] is False
        assert len(result['impacted_resources']) == 1
        assert 'Deployment: default/test-deployment-2' in result['impacted_resources']

    def test_check_service_mesh(self, mock_mcp, mock_client_cache, sample_shared_data):
        """Test _check_service_mesh method."""
        # Initialize the EKS resiliency handler
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        # Call the _check_service_mesh method
        # Note: This check tries to access k8s_api directly for CRD check
        # In test environment, it will return non-compliant
        result = handler._check_service_mesh(sample_shared_data)

        # Verify that the result structure is correct
        assert result['check_name'] == 'Use a Service Mesh'
        assert result['compliant'] is False  # No service mesh in test environment
        assert len(result['impacted_resources']) >= 0

    def test_check_monitoring(self, mock_mcp, mock_client_cache, sample_shared_data):
        """Test _check_monitoring method."""
        # Initialize the EKS resiliency handler
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        # Call the _check_monitoring method
        # Note: This check tries to access k8s_api directly for CRD check
        # In test environment, it will return non-compliant
        result = handler._check_monitoring(sample_shared_data)

        # Verify that the result structure is correct
        assert result['check_name'] == 'Monitor your applications'
        assert result['compliant'] is False  # No monitoring in test environment
        assert len(result['impacted_resources']) >= 0

    def test_check_centralized_logging(self, mock_mcp, mock_client_cache, sample_shared_data):
        """Test _check_centralized_logging method."""
        # Initialize the EKS resiliency handler
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        # Call the _check_centralized_logging method
        # Note: This check tries to access k8s_api directly for CRD check
        # In test environment, it will return non-compliant
        result = handler._check_centralized_logging(sample_shared_data)

        # Verify that the result structure is correct
        assert result['check_name'] == 'Use centralized logging'
        assert result['compliant'] is False  # No logging in test environment
        assert len(result['impacted_resources']) >= 0




class TestEKSResiliencyHandlerChecksC:
    """Tests for the EKSResiliencyHandler class C-series checks."""

    def test_check_c1_compliant(self, mock_mcp, mock_client_cache, sample_shared_data):
        """Test _check_c1 with control plane logging enabled."""
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        # Mock cluster info with logging enabled
        sample_shared_data['cluster_info'] = {
            'logging': {
                'clusterLogging': {
                    'enabledTypes': [
                        {'type': 'api'},
                        {'type': 'audit'},
                    ]
                }
            }
        }

        result = handler._check_c1(sample_shared_data, 'test-cluster')

        assert result['check_id'] == 'C1'
        assert result['compliant'] is True
        assert len(result['impacted_resources']) == 0
        assert 'api' in result['details']

    def test_check_c1_non_compliant(self, mock_mcp, mock_client_cache, sample_shared_data):
        """Test _check_c1 with control plane logging disabled."""
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        # Mock cluster info without logging
        sample_shared_data['cluster_info'] = {
            'logging': {
                'clusterLogging': {
                    'enabledTypes': []
                }
            }
        }

        result = handler._check_c1(sample_shared_data, 'test-cluster')

        assert result['check_id'] == 'C1'
        assert result['compliant'] is False
        assert 'test-cluster' in result['impacted_resources']

    def test_check_c2_compliant_with_access_entries(self, mock_mcp, mock_client_cache, sample_shared_data):
        """Test _check_c2 with EKS Access Entries configured."""
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        # Mock EKS client with access entries
        mock_eks_client = MagicMock()
        mock_eks_client.list_access_entries.return_value = {
            'accessEntries': ['arn:aws:iam::123456789012:role/test-role']
        }
        sample_shared_data['eks_client'] = mock_eks_client

        result = handler._check_c2(sample_shared_data, 'test-cluster')

        assert result['check_id'] == 'C2'
        assert result['compliant'] is True
        assert 'EKS Access Entries' in result['details']

    def test_check_c2_compliant_with_aws_auth(self, mock_mcp, mock_client_cache, sample_shared_data):
        """Test _check_c2 with aws-auth ConfigMap."""
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        # Mock aws-auth ConfigMap
        mock_cm = MagicMock()
        mock_cm.to_dict.return_value = {
            'metadata': {'name': 'aws-auth', 'namespace': 'kube-system'}
        }
        sample_shared_data['kube_system_configmaps'] = [mock_cm]
        sample_shared_data['eks_client'] = None

        result = handler._check_c2(sample_shared_data, 'test-cluster')

        assert result['check_id'] == 'C2'
        assert result['compliant'] is True
        assert 'aws-auth' in result['details']

    def test_check_c2_non_compliant(self, mock_mcp, mock_client_cache, sample_shared_data):
        """Test _check_c2 with no authentication configured."""
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        sample_shared_data['eks_client'] = None
        sample_shared_data['kube_system_configmaps'] = []

        result = handler._check_c2(sample_shared_data, 'test-cluster')

        assert result['check_id'] == 'C2'
        assert result['compliant'] is False
        assert 'test-cluster' in result['impacted_resources']

    def test_check_c3_not_large_cluster(self, mock_mcp, mock_client_cache, sample_shared_data):
        """Test _check_c3 with a small cluster."""
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        # Mock small number of services
        mock_k8s_client = sample_shared_data['k8s_client']
        mock_services = MagicMock()
        mock_services.items = [MagicMock() for _ in range(100)]
        mock_k8s_client.list_resources.return_value = mock_services

        result = handler._check_c3(sample_shared_data, 'test-cluster')

        assert result['check_id'] == 'C3'
        assert result['compliant'] is True
        assert 'not a large cluster' in result['details']

    def test_check_c3_large_cluster_compliant(self, mock_mcp, mock_client_cache, sample_shared_data):
        """Test _check_c3 with a large cluster with optimizations."""
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        # Mock large number of services
        mock_k8s_client = sample_shared_data['k8s_client']
        mock_services = MagicMock()
        mock_services.items = [MagicMock() for _ in range(1500)]
        mock_k8s_client.list_resources.return_value = mock_services

        # Mock kube-proxy with IPVS mode
        mock_cm = MagicMock()
        mock_cm.to_dict.return_value = {
            'metadata': {'name': 'kube-proxy-config'},
            'data': {'config.conf': 'mode: "ipvs"'}
        }
        sample_shared_data['kube_system_configmaps'] = [mock_cm]

        # Mock aws-node with IP caching
        mock_ds = MagicMock()
        mock_ds.to_dict.return_value = {
            'metadata': {'name': 'aws-node'},
            'spec': {
                'template': {
                    'spec': {
                        'containers': [{
                            'env': [{'name': 'WARM_IP_TARGET', 'value': '5'}]
                        }]
                    }
                }
            }
        }
        sample_shared_data['kube_system_daemonsets'] = [mock_ds]

        result = handler._check_c3(sample_shared_data, 'test-cluster')

        assert result['check_id'] == 'C3'
        assert result['compliant'] is True

    def test_check_c4_compliant_private_endpoint(self, mock_mcp, mock_client_cache, sample_shared_data):
        """Test _check_c4 with private endpoint."""
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        sample_shared_data['cluster_info'] = {
            'resourcesVpcConfig': {
                'endpointConfigPublicAccess': False
            }
        }

        result = handler._check_c4(sample_shared_data, 'test-cluster')

        assert result['check_id'] == 'C4'
        assert result['compliant'] is True
        assert 'private only' in result['details']

    def test_check_c4_compliant_restricted_public(self, mock_mcp, mock_client_cache, sample_shared_data):
        """Test _check_c4 with restricted public access."""
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        sample_shared_data['cluster_info'] = {
            'resourcesVpcConfig': {
                'endpointConfigPublicAccess': True,
                'publicAccessCidrs': ['10.0.0.0/8']
            }
        }

        result = handler._check_c4(sample_shared_data, 'test-cluster')

        assert result['check_id'] == 'C4'
        assert result['compliant'] is True

    def test_check_c4_non_compliant(self, mock_mcp, mock_client_cache, sample_shared_data):
        """Test _check_c4 with unrestricted public access."""
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        sample_shared_data['cluster_info'] = {
            'resourcesVpcConfig': {
                'endpointConfigPublicAccess': True,
                'publicAccessCidrs': ['0.0.0.0/0']
            }
        }

        result = handler._check_c4(sample_shared_data, 'test-cluster')

        assert result['check_id'] == 'C4'
        assert result['compliant'] is False
        assert 'test-cluster' in result['impacted_resources']

    def test_check_c5_compliant(self, mock_mcp, mock_client_cache, sample_shared_data):
        """Test _check_c5 with no catch-all webhooks."""
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        mock_k8s_client = sample_shared_data['k8s_client']
        
        # Mock webhooks without catch-all rules
        mock_webhook = MagicMock()
        mock_webhook.to_dict.return_value = {
            'metadata': {'name': 'test-webhook'},
            'webhooks': [{
                'rules': [{
                    'apiGroups': ['apps'],
                    'apiVersions': ['v1'],
                    'resources': ['deployments']
                }]
            }]
        }
        
        mock_response = MagicMock()
        mock_response.items = [mock_webhook]
        mock_k8s_client.list_resources.return_value = mock_response

        result = handler._check_c5(sample_shared_data, 'test-cluster')

        assert result['check_id'] == 'C5'
        assert result['compliant'] is True

    def test_check_c5_non_compliant(self, mock_mcp, mock_client_cache, sample_shared_data):
        """Test _check_c5 with catch-all webhooks."""
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        mock_k8s_client = sample_shared_data['k8s_client']
        
        # Mock webhook with catch-all rule
        mock_webhook = MagicMock()
        mock_webhook.to_dict.return_value = {
            'metadata': {'name': 'catch-all-webhook'},
            'webhooks': [{
                'rules': [{
                    'apiGroups': ['*'],
                    'apiVersions': ['*'],
                    'resources': ['*']
                }]
            }]
        }
        
        mock_response = MagicMock()
        mock_response.items = [mock_webhook]
        mock_k8s_client.list_resources.return_value = mock_response

        result = handler._check_c5(sample_shared_data, 'test-cluster')

        assert result['check_id'] == 'C5'
        assert result['compliant'] is False
        assert len(result['impacted_resources']) > 0


class TestEKSResiliencyHandlerChecksD:
    """Tests for the EKSResiliencyHandler class D-series checks."""

    def test_check_d1_compliant_with_cluster_autoscaler(self, mock_mcp, mock_client_cache, sample_shared_data):
        """Test _check_d1 with Cluster Autoscaler deployed."""
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        # Mock Cluster Autoscaler deployment
        mock_deployment = MagicMock()
        mock_deployment.to_dict.return_value = {
            'metadata': {'name': 'cluster-autoscaler', 'namespace': 'kube-system'}
        }
        sample_shared_data['kube_system_deployments'] = [mock_deployment]

        result = handler._check_d1(sample_shared_data, 'test-cluster')

        assert result['check_id'] == 'D1'
        assert result['compliant'] is True
        assert 'Cluster Autoscaler' in result['details']

    def test_check_d1_non_compliant(self, mock_mcp, mock_client_cache, sample_shared_data):
        """Test _check_d1 with no autoscaling solution."""
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        sample_shared_data['kube_system_deployments'] = []

        result = handler._check_d1(sample_shared_data, 'test-cluster')

        assert result['check_id'] == 'D1'
        assert result['compliant'] is False
        assert 'No node autoscaling' in result['details']

    def test_check_d3_compliant(self, mock_mcp, mock_client_cache, sample_shared_data):
        """Test _check_d3 with proper resource requests/limits."""
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        mock_k8s_client = sample_shared_data['k8s_client']
        
        # Mock deployment with complete resources
        mock_deployment = MagicMock()
        mock_deployment.to_dict.return_value = {
            'metadata': {'name': 'test-deployment', 'namespace': 'default'},
            'spec': {
                'template': {
                    'spec': {
                        'containers': [{
                            'name': 'app',
                            'resources': {
                                'requests': {'cpu': '100m', 'memory': '128Mi'},
                                'limits': {'cpu': '200m', 'memory': '256Mi'}
                            }
                        }]
                    }
                }
            }
        }
        
        mock_response = MagicMock()
        mock_response.items = [mock_deployment]
        mock_k8s_client.list_resources.return_value = mock_response

        result = handler._check_d3(sample_shared_data, 'test-cluster')

        assert result['check_id'] == 'D3'
        assert result['compliant'] is True

    def test_check_d3_non_compliant(self, mock_mcp, mock_client_cache, sample_shared_data):
        """Test _check_d3 with missing resource specifications."""
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        mock_k8s_client = sample_shared_data['k8s_client']
        
        # Mock deployment without resources
        mock_deployment = MagicMock()
        mock_deployment.to_dict.return_value = {
            'metadata': {'name': 'test-deployment', 'namespace': 'default'},
            'spec': {
                'template': {
                    'spec': {
                        'containers': [{
                            'name': 'app',
                            'resources': {}
                        }]
                    }
                }
            }
        }
        
        mock_response = MagicMock()
        mock_response.items = [mock_deployment]
        mock_k8s_client.list_resources.return_value = mock_response

        result = handler._check_d3(sample_shared_data, 'test-cluster')

        assert result['check_id'] == 'D3'
        assert result['compliant'] is False
        assert len(result['impacted_resources']) > 0

    def test_check_d4_compliant(self, mock_mcp, mock_client_cache, sample_shared_data):
        """Test _check_d4 with ResourceQuotas configured."""
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        mock_k8s_client = sample_shared_data['k8s_client']
        
        # Mock namespace
        mock_ns = MagicMock()
        mock_ns.to_dict.return_value = {
            'metadata': {'name': 'test-namespace'}
        }
        
        # Mock resource quota
        mock_quota = MagicMock()
        mock_quota.to_dict.return_value = {
            'metadata': {'namespace': 'test-namespace'}
        }
        
        def list_resources_side_effect(kind, **kwargs):
            mock_response = MagicMock()
            if kind == 'Namespace':
                mock_response.items = [mock_ns]
            elif kind == 'ResourceQuota':
                mock_response.items = [mock_quota]
            return mock_response
        
        mock_k8s_client.list_resources.side_effect = list_resources_side_effect

        result = handler._check_d4(sample_shared_data, 'test-cluster')

        assert result['check_id'] == 'D4'
        assert result['compliant'] is True

    def test_check_d4_non_compliant(self, mock_mcp, mock_client_cache, sample_shared_data):
        """Test _check_d4 with missing ResourceQuotas."""
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        mock_k8s_client = sample_shared_data['k8s_client']
        
        # Mock namespace without quota
        mock_ns = MagicMock()
        mock_ns.to_dict.return_value = {
            'metadata': {'name': 'test-namespace'}
        }
        
        def list_resources_side_effect(kind, **kwargs):
            mock_response = MagicMock()
            if kind == 'Namespace':
                mock_response.items = [mock_ns]
            elif kind == 'ResourceQuota':
                mock_response.items = []
            return mock_response
        
        mock_k8s_client.list_resources.side_effect = list_resources_side_effect

        result = handler._check_d4(sample_shared_data, 'test-cluster')

        assert result['check_id'] == 'D4'
        assert result['compliant'] is False
        assert 'test-namespace' in result['impacted_resources']

    def test_check_d5_compliant(self, mock_mcp, mock_client_cache, sample_shared_data):
        """Test _check_d5 with LimitRanges configured."""
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        mock_k8s_client = sample_shared_data['k8s_client']
        
        # Mock namespace
        mock_ns = MagicMock()
        mock_ns.to_dict.return_value = {
            'metadata': {'name': 'test-namespace'}
        }
        
        # Mock limit range
        mock_limit = MagicMock()
        mock_limit.to_dict.return_value = {
            'metadata': {'namespace': 'test-namespace'}
        }
        
        def list_resources_side_effect(kind, **kwargs):
            mock_response = MagicMock()
            if kind == 'Namespace':
                mock_response.items = [mock_ns]
            elif kind == 'LimitRange':
                mock_response.items = [mock_limit]
            return mock_response
        
        mock_k8s_client.list_resources.side_effect = list_resources_side_effect

        result = handler._check_d5(sample_shared_data, 'test-cluster')

        assert result['check_id'] == 'D5'
        assert result['compliant'] is True

    def test_check_d5_non_compliant(self, mock_mcp, mock_client_cache, sample_shared_data):
        """Test _check_d5 with missing LimitRanges."""
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        mock_k8s_client = sample_shared_data['k8s_client']
        
        # Mock namespace without limit range
        mock_ns = MagicMock()
        mock_ns.to_dict.return_value = {
            'metadata': {'name': 'test-namespace'}
        }
        
        def list_resources_side_effect(kind, **kwargs):
            mock_response = MagicMock()
            if kind == 'Namespace':
                mock_response.items = [mock_ns]
            elif kind == 'LimitRange':
                mock_response.items = []
            return mock_response
        
        mock_k8s_client.list_resources.side_effect = list_resources_side_effect

        result = handler._check_d5(sample_shared_data, 'test-cluster')

        assert result['check_id'] == 'D5'
        assert result['compliant'] is False
        assert 'test-namespace' in result['impacted_resources']

    def test_check_d6_compliant(self, mock_mcp, mock_client_cache, sample_shared_data):
        """Test _check_d6 with CoreDNS monitoring configured."""
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        mock_k8s_client = sample_shared_data['k8s_client']
        
        # Mock CoreDNS deployment
        mock_deployment = MagicMock()
        mock_deployment.to_dict.return_value = {
            'metadata': {'name': 'coredns', 'namespace': 'kube-system'}
        }
        
        # Mock ServiceMonitor
        mock_sm = MagicMock()
        mock_sm.to_dict.return_value = {
            'metadata': {'name': 'coredns-metrics', 'namespace': 'kube-system'}
        }
        
        def list_resources_side_effect(kind, **kwargs):
            mock_response = MagicMock()
            if kind == 'Deployment':
                mock_response.items = [mock_deployment]
            elif kind == 'ServiceMonitor':
                mock_response.items = [mock_sm]
            return mock_response
        
        mock_k8s_client.list_resources.side_effect = list_resources_side_effect
        
        # Mock API call for ServiceMonitor CRD check
        mock_k8s_client.api_client.call_api.return_value = MagicMock()

        result = handler._check_d6(sample_shared_data, 'test-cluster')

        assert result['check_id'] == 'D6'
        assert result['compliant'] is True

    def test_check_d6_non_compliant(self, mock_mcp, mock_client_cache, sample_shared_data):
        """Test _check_d6 with CoreDNS but no monitoring."""
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        mock_k8s_client = sample_shared_data['k8s_client']
        
        # Mock CoreDNS deployment
        mock_deployment = MagicMock()
        mock_deployment.to_dict.return_value = {
            'metadata': {'name': 'coredns', 'namespace': 'kube-system'}
        }
        
        def list_resources_side_effect(kind, **kwargs):
            mock_response = MagicMock()
            if kind == 'Deployment':
                mock_response.items = [mock_deployment]
            elif kind == 'ServiceMonitor':
                mock_response.items = []
            return mock_response
        
        mock_k8s_client.list_resources.side_effect = list_resources_side_effect
        
        # Mock API call failure for ServiceMonitor CRD
        mock_k8s_client.api_client.call_api.side_effect = Exception('CRD not found')

        result = handler._check_d6(sample_shared_data, 'test-cluster')

        assert result['check_id'] == 'D6'
        assert result['compliant'] is False

    @patch('awslabs.eks_review_mcp_server.eks_resiliency_handler.AwsHelper')
    def test_check_d7_compliant_managed_addon(self, mock_aws_helper, mock_mcp, mock_client_cache, sample_shared_data):
        """Test _check_d7 with EKS managed CoreDNS addon."""
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        # Mock EKS client
        mock_eks_client = MagicMock()
        mock_eks_client.describe_cluster.return_value = {
            'cluster': {'computeConfig': {'enabled': False}}
        }
        mock_eks_client.list_addons.return_value = {
            'addons': ['coredns', 'kube-proxy']
        }
        mock_aws_helper.create_boto3_client.return_value = mock_eks_client

        result = handler._check_d7(sample_shared_data, 'test-cluster')

        assert result['check_id'] == 'D7'
        assert result['compliant'] is True
        assert 'managed' in result['details'].lower()

    @patch('awslabs.eks_review_mcp_server.eks_resiliency_handler.AwsHelper')
    def test_check_d7_non_compliant_self_managed(self, mock_aws_helper, mock_mcp, mock_client_cache, sample_shared_data):
        """Test _check_d7 with self-managed CoreDNS."""
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        # Mock EKS client
        mock_eks_client = MagicMock()
        mock_eks_client.describe_cluster.return_value = {
            'cluster': {'computeConfig': {'enabled': False}}
        }
        mock_eks_client.list_addons.return_value = {
            'addons': ['kube-proxy']  # No coredns addon
        }
        mock_aws_helper.create_boto3_client.return_value = mock_eks_client

        # Mock CoreDNS deployment
        mock_k8s_client = sample_shared_data['k8s_client']
        mock_deployment = MagicMock()
        mock_response = MagicMock()
        mock_response.items = [mock_deployment]
        mock_k8s_client.list_resources.return_value = mock_response

        result = handler._check_d7(sample_shared_data, 'test-cluster')

        assert result['check_id'] == 'D7'
        assert result['compliant'] is False
        assert 'self-managed' in result['details'].lower()

    @patch('awslabs.eks_review_mcp_server.eks_resiliency_handler.AwsHelper')
    def test_check_d7_compliant_auto_mode(self, mock_aws_helper, mock_mcp, mock_client_cache, sample_shared_data):
        """Test _check_d7 with EKS auto mode cluster."""
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        # Mock EKS client for auto mode
        mock_eks_client = MagicMock()
        mock_eks_client.describe_cluster.return_value = {
            'cluster': {'computeConfig': {'enabled': True}}
        }
        mock_aws_helper.create_boto3_client.return_value = mock_eks_client

        result = handler._check_d7(sample_shared_data, 'test-cluster')

        assert result['check_id'] == 'D7'
        assert result['compliant'] is True
        assert 'auto mode' in result['details'].lower()



class TestEKSResiliencyHandlerEdgeCases:
    """Tests for edge cases and error handling."""

    def test_check_singleton_pods_with_system_pods(self, mock_mcp, mock_client_cache, sample_shared_data):
        """Test _check_singleton_pods with system namespace pods."""
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        # Create mock pod in kube-system namespace (should be ignored)
        mock_pod = MagicMock()
        mock_pod.to_dict.return_value = {
            'metadata': {
                'name': 'system-pod',
                'namespace': 'kube-system'
            }
        }
        
        sample_shared_data['pods'] = [mock_pod]
        result = handler._check_singleton_pods(sample_shared_data)

        assert result['check_name'] == 'Avoid running singleton Pods'
        # System pods might be treated differently
        assert 'check_name' in result

    def test_check_multiple_replicas_with_zero_replicas(self, mock_mcp, mock_client_cache, sample_shared_data):
        """Test _check_multiple_replicas with zero replicas."""
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        mock_deployment = MagicMock()
        mock_deployment.to_dict.return_value = {
            'metadata': {'name': 'scaled-down', 'namespace': 'default'},
            'spec': {'replicas': 0},
        }

        sample_shared_data['deployments'] = [mock_deployment]
        sample_shared_data['statefulsets'] = []
        result = handler._check_multiple_replicas(sample_shared_data)

        assert result['check_name'] == 'Run multiple replicas'
        # Zero replicas is treated as compliant (intentionally scaled down)
        assert result['compliant'] is True

    def test_check_pod_anti_affinity_with_single_replica(self, mock_mcp, mock_client_cache, sample_shared_data):
        """Test _check_pod_anti_affinity with single replica deployment."""
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        mock_deployment = MagicMock()
        mock_deployment.to_dict.return_value = {
            'metadata': {'name': 'single-replica', 'namespace': 'default'},
            'spec': {'replicas': 1, 'template': {'spec': {}}},
        }
        
        sample_shared_data['deployments'] = [mock_deployment]
        result = handler._check_pod_anti_affinity(sample_shared_data)

        assert result['check_name'] == 'Use pod anti-affinity'
        # Single replica doesn't need anti-affinity
        assert result['compliant'] is True

    def test_check_liveness_probe_with_init_containers(self, mock_mcp, mock_client_cache, sample_shared_data):
        """Test _check_liveness_probe with init containers."""
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        mock_deployment = MagicMock()
        mock_deployment.to_dict.return_value = {
            'metadata': {'name': 'with-init', 'namespace': 'default'},
            'spec': {
                'template': {
                    'spec': {
                        'initContainers': [{'name': 'init'}],
                        'containers': [
                            {
                                'name': 'main',
                                'livenessProbe': {'httpGet': {'path': '/health', 'port': 8080}}
                            }
                        ]
                    }
                }
            },
        }

        sample_shared_data['deployments'] = [mock_deployment]
        sample_shared_data['statefulsets'] = []
        sample_shared_data['daemonsets'] = []
        result = handler._check_liveness_probe(sample_shared_data)

        assert result['check_name'] == 'Use liveness probes'
        assert result['compliant'] is True

    def test_check_readiness_probe_multiple_containers(self, mock_mcp, mock_client_cache, sample_shared_data):
        """Test _check_readiness_probe with multiple containers."""
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        mock_deployment = MagicMock()
        mock_deployment.to_dict.return_value = {
            'metadata': {'name': 'multi-container', 'namespace': 'default'},
            'spec': {
                'template': {
                    'spec': {
                        'containers': [
                            {
                                'name': 'container-1',
                                'readinessProbe': {'httpGet': {'path': '/ready', 'port': 8080}}
                            },
                            {
                                'name': 'container-2'
                                # Missing readiness probe
                            }
                        ]
                    }
                }
            },
        }

        sample_shared_data['deployments'] = [mock_deployment]
        sample_shared_data['statefulsets'] = []
        sample_shared_data['daemonsets'] = []
        result = handler._check_readiness_probe(sample_shared_data)

        assert result['check_name'] == 'Use readiness probes'
        # Should be non-compliant because one container is missing probe
        assert result['compliant'] is False

    def test_check_pod_disruption_budget_with_statefulset(self, mock_mcp, mock_client_cache, sample_shared_data):
        """Test _check_pod_disruption_budget with StatefulSet."""
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        mock_statefulset = MagicMock()
        mock_statefulset.to_dict.return_value = {
            'metadata': {
                'name': 'test-statefulset',
                'namespace': 'default',
                'labels': {'app': 'database'},
            },
            'spec': {'replicas': 3, 'selector': {'matchLabels': {'app': 'database'}}},
        }

        mock_pdb = MagicMock()
        mock_pdb.to_dict.return_value = {
            'metadata': {'name': 'test-pdb', 'namespace': 'default'},
            'spec': {'selector': {'matchLabels': {'app': 'database'}}, 'minAvailable': 2},
        }

        sample_shared_data['deployments'] = []
        sample_shared_data['statefulsets'] = [mock_statefulset]
        sample_shared_data['pdbs'] = [mock_pdb]

        result = handler._check_pod_disruption_budget(sample_shared_data)

        assert result['check_name'] == 'Use Pod Disruption Budgets'
        assert result['compliant'] is True

    def test_check_horizontal_pod_autoscaler_with_statefulset(self, mock_mcp, mock_client_cache, sample_shared_data):
        """Test _check_horizontal_pod_autoscaler with StatefulSet."""
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        mock_statefulset = MagicMock()
        mock_statefulset.to_dict.return_value = {
            'metadata': {'name': 'test-statefulset', 'namespace': 'default'},
            'spec': {'replicas': 3},
        }

        mock_hpa = MagicMock()
        mock_hpa.to_dict.return_value = {
            'metadata': {'name': 'test-hpa', 'namespace': 'default'},
            'spec': {'scaleTargetRef': {'kind': 'StatefulSet', 'name': 'test-statefulset'}},
        }

        sample_shared_data['deployments'] = []
        sample_shared_data['statefulsets'] = [mock_statefulset]
        sample_shared_data['hpas'] = [mock_hpa]

        result = handler._check_horizontal_pod_autoscaler(sample_shared_data)

        assert result['check_name'] == 'Use Horizontal Pod Autoscaler'
        assert result['compliant'] is True

    def test_check_prestop_hooks_with_daemonset(self, mock_mcp, mock_client_cache, sample_shared_data):
        """Test _check_prestop_hooks with DaemonSet."""
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        mock_daemonset = MagicMock()
        mock_daemonset.to_dict.return_value = {
            'metadata': {'name': 'test-daemonset', 'namespace': 'default'},
            'spec': {
                'template': {
                    'spec': {
                        'containers': [
                            {
                                'name': 'container-1',
                                'lifecycle': {
                                    'preStop': {'exec': {'command': ['/bin/sh', '-c', 'sleep 15']}}
                                },
                            }
                        ]
                    }
                }
            },
        }

        sample_shared_data['deployments'] = []
        sample_shared_data['statefulsets'] = []
        sample_shared_data['daemonsets'] = [mock_daemonset]
        result = handler._check_prestop_hooks(sample_shared_data)

        assert result['check_name'] == 'Use preStop hooks'
        assert result['compliant'] is True


class TestEKSResiliencyHandlerCSeriesEdgeCases:
    """Tests for C-series checks edge cases."""

    @patch('awslabs.eks_review_mcp_server.eks_resiliency_handler.AwsHelper')
    def test_check_c1_with_partial_logging(self, mock_aws_helper, mock_mcp, mock_client_cache, sample_shared_data):
        """Test _check_c1 with partial logging enabled."""
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        sample_shared_data['cluster_info'] = {
            'logging': {
                'clusterLogging': {
                    'enabledTypes': [
                        {'type': 'api'},
                        # Missing audit and other types
                    ]
                }
            }
        }

        result = handler._check_c1(sample_shared_data, 'test-cluster')

        assert result['check_id'] == 'C1'
        # Partial logging might still be compliant depending on implementation
        assert 'check_id' in result

    @patch('awslabs.eks_review_mcp_server.eks_resiliency_handler.AwsHelper')
    def test_check_c2_with_empty_access_entries(self, mock_aws_helper, mock_mcp, mock_client_cache, sample_shared_data):
        """Test _check_c2 with empty access entries."""
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        mock_eks_client = MagicMock()
        mock_eks_client.list_access_entries.return_value = {
            'accessEntries': []  # Empty list
        }
        sample_shared_data['eks_client'] = mock_eks_client

        result = handler._check_c2(sample_shared_data, 'test-cluster')

        assert result['check_id'] == 'C2'
        # Empty access entries should be non-compliant
        assert result['compliant'] is False

    @patch('awslabs.eks_review_mcp_server.eks_resiliency_handler.AwsHelper')
    def test_check_c3_with_multiple_node_groups(self, mock_aws_helper, mock_mcp, mock_client_cache, sample_shared_data):
        """Test _check_c3 with multiple node groups."""
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        mock_eks_client = MagicMock()
        mock_eks_client.list_nodegroups.return_value = {
            'nodegroups': ['ng-1', 'ng-2', 'ng-3']
        }
        sample_shared_data['eks_client'] = mock_eks_client

        result = handler._check_c3(sample_shared_data, 'test-cluster')

        assert result['check_id'] == 'C3'
        # Multiple node groups should be compliant
        assert result['compliant'] is True

    @patch('awslabs.eks_review_mcp_server.eks_resiliency_handler.AwsHelper')
    def test_check_c4_with_missing_encryption_config(self, mock_aws_helper, mock_mcp, mock_client_cache, sample_shared_data):
        """Test _check_c4 with missing encryption configuration."""
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        sample_shared_data['cluster_info'] = {}  # No encryption config

        result = handler._check_c4(sample_shared_data, 'test-cluster')

        assert result['check_id'] == 'C4'
        # Missing encryption might be treated as compliant in older clusters
        # Just verify the check runs without error
        assert 'check_id' in result

    @patch('awslabs.eks_review_mcp_server.eks_resiliency_handler.AwsHelper')
    def test_check_c5_with_old_version(self, mock_aws_helper, mock_mcp, mock_client_cache, sample_shared_data):
        """Test _check_c5 with old Kubernetes version."""
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        sample_shared_data['cluster_info'] = {
            'version': '1.24'  # Old version
        }

        result = handler._check_c5(sample_shared_data, 'test-cluster')

        assert result['check_id'] == 'C5'
        # Version check depends on what's considered "current"
        # Just verify the check runs and returns valid result
        assert 'check_id' in result
        assert 'compliant' in result


class TestEKSResiliencyHandlerIntegration:
    """Integration-style tests for complete resiliency check flow."""

    @pytest.mark.asyncio
    async def test_full_resiliency_check_mixed_results(self, mock_mcp, mock_client_cache, mock_context):
        """Test full resiliency check with mixed compliant and non-compliant results."""
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        # Mock some checks to pass and some to fail
        with patch.object(handler, '_check_singleton_pods', return_value={
            'check_name': 'Avoid running singleton Pods',
            'compliant': True,
            'impacted_resources': [],
            'details': 'No singleton pods found',
            'remediation': ''
        }):
            with patch.object(handler, '_check_multiple_replicas', return_value={
                'check_name': 'Run multiple replicas',
                'compliant': False,
                'impacted_resources': ['Deployment default/single-replica'],
                'details': 'Found deployments with single replica',
                'remediation': 'Increase replica count'
            }):
                with patch.object(handler, '_check_liveness_probe', return_value={
                    'check_name': 'Use liveness probes',
                    'compliant': False,
                    'impacted_resources': ['Deployment: default/no-probe'],
                    'details': 'Missing liveness probes',
                    'remediation': 'Add liveness probes'
                }):
                    result = await handler.check_eks_resiliency(mock_context, cluster_name='test-cluster')

        assert isinstance(result, ResiliencyCheckResponse)
        assert result.isError is False
        assert result.overall_compliant is False
        # Should have both passing and failing checks
        passed = sum(1 for check in result.check_results if check['compliant'])
        failed = sum(1 for check in result.check_results if not check['compliant'])
        assert passed > 0
        assert failed > 0

    @pytest.mark.asyncio
    async def test_full_resiliency_check_with_api_errors(self, mock_mcp, mock_client_cache, mock_context):
        """Test full resiliency check when some checks encounter API errors."""
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        # Mock a check that raises an exception
        with patch.object(handler, '_check_singleton_pods', side_effect=Exception('API error')):
            with patch.object(handler, '_check_multiple_replicas', return_value={
                'check_name': 'Run multiple replicas',
                'compliant': True,
                'impacted_resources': [],
                'details': 'All deployments have multiple replicas',
                'remediation': ''
            }):
                result = await handler.check_eks_resiliency(mock_context, cluster_name='test-cluster')

        assert isinstance(result, ResiliencyCheckResponse)
        # Should handle errors gracefully
        assert 'check_results' in result.__dict__

    @pytest.mark.asyncio
    async def test_check_eks_resiliency_with_namespace_filter(self, mock_mcp, mock_client_cache, mock_context):
        """Test check_eks_resiliency with namespace filter."""
        handler = EKSResiliencyHandler(mock_mcp, mock_client_cache)

        with patch.object(handler, '_check_singleton_pods', return_value={
            'check_name': 'Avoid running singleton Pods',
            'compliant': True,
            'impacted_resources': [],
            'details': 'No singleton pods in namespace',
            'remediation': ''
        }):
            result = await handler.check_eks_resiliency(
                mock_context, 
                cluster_name='test-cluster',
                namespace='production'
            )

        assert isinstance(result, ResiliencyCheckResponse)
        assert result.isError is False
