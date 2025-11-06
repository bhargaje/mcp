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
"""Tests for the EKSNetworkingHandler class."""

import pytest
from awslabs.eks_review_mcp_server.eks_networking_handler import EKSNetworkingHandler
from awslabs.eks_review_mcp_server.models import NetworkingCheckResponse
from mcp.server.fastmcp import Context
from unittest.mock import MagicMock, AsyncMock, patch


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
    mock_k8s_client = MagicMock()
    cache.get_client.return_value = mock_k8s_client
    return cache


@pytest.fixture
def mock_eks_client():
    """Create a mock EKS client."""
    return MagicMock()


@pytest.fixture
def mock_k8s_client():
    """Create a mock K8s client."""
    return MagicMock()


@pytest.fixture
def mock_ec2_client():
    """Create a mock EC2 client."""
    return MagicMock()


class TestEKSNetworkingHandlerInit:
    """Tests for the EKSNetworkingHandler class initialization."""

    def test_init(self, mock_mcp, mock_client_cache):
        """Test initialization of EKSNetworkingHandler."""
        handler = EKSNetworkingHandler(mock_mcp, mock_client_cache)

        assert handler.mcp == mock_mcp
        assert handler.client_cache == mock_client_cache
        mock_mcp.tool.assert_called_once()
        assert mock_mcp.tool.call_args[1]['name'] == 'check_eks_networking'

    @pytest.mark.asyncio
    async def test_check_eks_networking_connection_error(
        self, mock_mcp, mock_client_cache, mock_context
    ):
        """Test check_eks_networking with a connection error."""
        mock_client_cache.get_client.side_effect = Exception('Failed to connect to cluster')

        handler = EKSNetworkingHandler(mock_mcp, mock_client_cache)

        # Mock _initialize_clients to return None
        handler._initialize_clients = AsyncMock(return_value=None)

        result = await handler.check_eks_networking(
            mock_context, cluster_name='test-cluster', region='us-west-2'
        )

        assert isinstance(result, NetworkingCheckResponse)
        assert result.isError is True
        assert 'Failed to initialize required clients' in result.summary
        assert len(result.check_results) == 1
        assert result.check_results[0]['check_name'] == 'Connection Error'
        assert result.check_results[0]['compliant'] is False

    @pytest.mark.asyncio
    async def test_check_eks_networking_invalid_region(
        self, mock_mcp, mock_client_cache, mock_context
    ):
        """Test check_eks_networking with invalid region."""
        handler = EKSNetworkingHandler(mock_mcp, mock_client_cache)

        handler._initialize_clients = AsyncMock(return_value=None)

        result = await handler.check_eks_networking(
            mock_context, cluster_name='test-cluster', region='invalid-region'
        )

        assert isinstance(result, NetworkingCheckResponse)
        assert result.isError is True
        assert result.overall_compliant is False


class TestEKSNetworkingHandlerChecks:
    """Tests for the EKSNetworkingHandler check methods."""

    @pytest.mark.asyncio
    async def test_check_cluster_endpoint_access_compliant_private_only(
        self, mock_mcp, mock_client_cache, mock_eks_client
    ):
        """Test N1 check with private-only endpoint access."""
        handler = EKSNetworkingHandler(mock_mcp, mock_client_cache)

        cluster_info = {
            'endpoint_config_private_access': True,
            'endpoint_config_public_access': False,
            'public_access_cidrs': [],
            'is_auto_mode': False
        }

        result = await handler._check_cluster_endpoint_access(
            'test-cluster', 'us-west-2', mock_eks_client, cluster_info
        )

        assert result['check_id'] == 'N1'
        assert result['compliant'] is True
        assert len(result['impacted_resources']) == 0

    @pytest.mark.asyncio
    async def test_check_cluster_endpoint_access_compliant_restricted_public(
        self, mock_mcp, mock_client_cache, mock_eks_client
    ):
        """Test N1 check with restricted public access."""
        handler = EKSNetworkingHandler(mock_mcp, mock_client_cache)

        cluster_info = {
            'endpoint_config_private_access': True,
            'endpoint_config_public_access': True,
            'public_access_cidrs': ['10.0.0.0/8', '192.168.1.0/24'],
            'is_auto_mode': False
        }

        result = await handler._check_cluster_endpoint_access(
            'test-cluster', 'us-west-2', mock_eks_client, cluster_info
        )

        assert result['check_id'] == 'N1'
        assert result['compliant'] is True
        assert len(result['impacted_resources']) == 0

    @pytest.mark.asyncio
    async def test_check_cluster_endpoint_access_non_compliant_unrestricted(
        self, mock_mcp, mock_client_cache, mock_eks_client
    ):
        """Test N1 check with unrestricted public access."""
        handler = EKSNetworkingHandler(mock_mcp, mock_client_cache)

        cluster_info = {
            'endpoint_config_private_access': False,
            'endpoint_config_public_access': True,
            'public_access_cidrs': ['0.0.0.0/0'],
            'is_auto_mode': False
        }

        result = await handler._check_cluster_endpoint_access(
            'test-cluster', 'us-west-2', mock_eks_client, cluster_info
        )

        assert result['check_id'] == 'N1'
        assert result['compliant'] is False
        assert 'Cluster: test-cluster' in result['impacted_resources']
        assert 'Unrestricted public access detected' in result['details']['issues_found']

    @pytest.mark.asyncio
    async def test_check_cluster_endpoint_access_fallback_to_api(
        self, mock_mcp, mock_client_cache, mock_eks_client
    ):
        """Test N1 check falls back to API call when cluster_info not provided."""
        handler = EKSNetworkingHandler(mock_mcp, mock_client_cache)

        mock_eks_client.describe_cluster.return_value = {
            'cluster': {
                'resourcesVpcConfig': {
                    'endpointConfigPrivateAccess': True,
                    'endpointConfigPublicAccess': False,
                    'publicAccessCidrs': []
                }
            }
        }

        result = await handler._check_cluster_endpoint_access(
            'test-cluster', 'us-west-2', mock_eks_client, cluster_info=None
        )

        assert result['check_id'] == 'N1'
        assert result['compliant'] is True
        mock_eks_client.describe_cluster.assert_called_once_with(name='test-cluster')

    @pytest.mark.asyncio
    async def test_check_cluster_endpoint_access_public_only_restricted(
        self, mock_mcp, mock_client_cache, mock_eks_client
    ):
        """Test N1 check with public-only endpoint but restricted CIDRs."""
        handler = EKSNetworkingHandler(mock_mcp, mock_client_cache)

        cluster_info = {
            'endpoint_config_private_access': False,
            'endpoint_config_public_access': True,
            'public_access_cidrs': ['10.0.0.0/8'],  # Restricted CIDR
            'is_auto_mode': False
        }

        result = await handler._check_cluster_endpoint_access(
            'test-cluster', 'us-west-2', mock_eks_client, cluster_info
        )

        assert result['check_id'] == 'N1'
        # With restricted CIDRs, this is considered compliant even without private access
        assert result['compliant'] is True

    @pytest.mark.asyncio
    async def test_check_cluster_endpoint_access_public_only_unrestricted(
        self, mock_mcp, mock_client_cache, mock_eks_client
    ):
        """Test N1 check with public-only endpoint and unrestricted access."""
        handler = EKSNetworkingHandler(mock_mcp, mock_client_cache)

        cluster_info = {
            'endpoint_config_private_access': False,
            'endpoint_config_public_access': True,
            'public_access_cidrs': ['0.0.0.0/0'],  # Unrestricted
            'is_auto_mode': False
        }

        result = await handler._check_cluster_endpoint_access(
            'test-cluster', 'us-west-2', mock_eks_client, cluster_info
        )

        assert result['check_id'] == 'N1'
        assert result['compliant'] is False
        assert 'Cluster: test-cluster' in result['impacted_resources']

    @pytest.mark.asyncio
    async def test_check_cluster_endpoint_access_missing_config(
        self, mock_mcp, mock_client_cache, mock_eks_client
    ):
        """Test N1 check with missing endpoint configuration."""
        handler = EKSNetworkingHandler(mock_mcp, mock_client_cache)

        cluster_info = {}  # Missing endpoint config

        result = await handler._check_cluster_endpoint_access(
            'test-cluster', 'us-west-2', mock_eks_client, cluster_info
        )

        assert result['check_id'] == 'N1'
        # Should handle gracefully
        assert 'check_id' in result

    @pytest.mark.asyncio
    async def test_check_cluster_endpoint_access_multiple_restricted_cidrs(
        self, mock_mcp, mock_client_cache, mock_eks_client
    ):
        """Test N1 check with multiple restricted CIDRs."""
        handler = EKSNetworkingHandler(mock_mcp, mock_client_cache)

        cluster_info = {
            'endpoint_config_private_access': True,
            'endpoint_config_public_access': True,
            'public_access_cidrs': [
                '10.0.0.0/8',
                '172.16.0.0/12',
                '192.168.0.0/16'
            ],
            'is_auto_mode': False
        }

        result = await handler._check_cluster_endpoint_access(
            'test-cluster', 'us-west-2', mock_eks_client, cluster_info
        )

        assert result['check_id'] == 'N1'
        assert result['compliant'] is True
        assert len(result['impacted_resources']) == 0

    @pytest.mark.asyncio
    async def test_check_multi_az_node_distribution_compliant(
        self, mock_mcp, mock_client_cache, mock_k8s_client
    ):
        """Test N2 check with nodes distributed across multiple AZs."""
        handler = EKSNetworkingHandler(mock_mcp, mock_client_cache)

        # Mock nodes in 3 AZs with even distribution
        mock_node1 = MagicMock()
        mock_node1.to_dict.return_value = {
            'metadata': {
                'name': 'node-1',
                'labels': {'topology.kubernetes.io/zone': 'us-west-2a'}
            }
        }
        mock_node2 = MagicMock()
        mock_node2.to_dict.return_value = {
            'metadata': {
                'name': 'node-2',
                'labels': {'topology.kubernetes.io/zone': 'us-west-2b'}
            }
        }
        mock_node3 = MagicMock()
        mock_node3.to_dict.return_value = {
            'metadata': {
                'name': 'node-3',
                'labels': {'topology.kubernetes.io/zone': 'us-west-2c'}
            }
        }

        mock_response = MagicMock()
        mock_response.items = [mock_node1, mock_node2, mock_node3]
        mock_k8s_client.list_resources.return_value = mock_response

        result = await handler._check_multi_az_node_distribution(
            'test-cluster', 'us-west-2', mock_k8s_client
        )

        assert result['check_id'] == 'N2'
        assert result['compliant'] is True
        assert result['details']['node_distribution']['availability_zones'] == 3
        assert result['details']['node_distribution']['total_nodes'] == 3

    @pytest.mark.asyncio
    async def test_check_multi_az_node_distribution_non_compliant_single_az(
        self, mock_mcp, mock_client_cache, mock_k8s_client
    ):
        """Test N2 check with nodes in single AZ."""
        handler = EKSNetworkingHandler(mock_mcp, mock_client_cache)

        # Mock nodes all in one AZ
        mock_node1 = MagicMock()
        mock_node1.to_dict.return_value = {
            'metadata': {
                'name': 'node-1',
                'labels': {'topology.kubernetes.io/zone': 'us-west-2a'}
            }
        }
        mock_node2 = MagicMock()
        mock_node2.to_dict.return_value = {
            'metadata': {
                'name': 'node-2',
                'labels': {'topology.kubernetes.io/zone': 'us-west-2a'}
            }
        }

        mock_response = MagicMock()
        mock_response.items = [mock_node1, mock_node2]
        mock_k8s_client.list_resources.return_value = mock_response

        result = await handler._check_multi_az_node_distribution(
            'test-cluster', 'us-west-2', mock_k8s_client
        )

        assert result['check_id'] == 'N2'
        assert result['compliant'] is False
        assert result['details']['node_distribution']['availability_zones'] == 1
        assert 'All nodes in single AZ' in result['impacted_resources'][0]

    @pytest.mark.asyncio
    async def test_check_multi_az_node_distribution_non_compliant_uneven(
        self, mock_mcp, mock_client_cache, mock_k8s_client
    ):
        """Test N2 check with uneven node distribution across AZs."""
        handler = EKSNetworkingHandler(mock_mcp, mock_client_cache)

        # Mock nodes with uneven distribution (5 in one AZ, 1 in another)
        nodes = []
        for i in range(5):
            node = MagicMock()
            node.to_dict.return_value = {
                'metadata': {
                    'name': f'node-{i}',
                    'labels': {'topology.kubernetes.io/zone': 'us-west-2a'}
                }
            }
            nodes.append(node)
        
        node = MagicMock()
        node.to_dict.return_value = {
            'metadata': {
                'name': 'node-5',
                'labels': {'topology.kubernetes.io/zone': 'us-west-2b'}
            }
        }
        nodes.append(node)

        mock_response = MagicMock()
        mock_response.items = nodes
        mock_k8s_client.list_resources.return_value = mock_response

        result = await handler._check_multi_az_node_distribution(
            'test-cluster', 'us-west-2', mock_k8s_client
        )

        assert result['check_id'] == 'N2'
        assert result['compliant'] is False
        assert result['details']['node_distribution']['availability_zones'] == 2
        assert len(result['impacted_resources']) > 0

    @pytest.mark.asyncio
    async def test_check_multi_az_node_distribution_no_nodes(
        self, mock_mcp, mock_client_cache, mock_k8s_client
    ):
        """Test N2 check with no nodes found."""
        handler = EKSNetworkingHandler(mock_mcp, mock_client_cache)

        mock_response = MagicMock()
        mock_response.items = []
        mock_k8s_client.list_resources.return_value = mock_response

        result = await handler._check_multi_az_node_distribution(
            'test-cluster', 'us-west-2', mock_k8s_client
        )

        assert result['check_id'] == 'N2'
        assert result['compliant'] is False
        assert 'No nodes found' in result['details']['error']

    @pytest.mark.asyncio
    async def test_check_multi_az_node_distribution_missing_az_labels(
        self, mock_mcp, mock_client_cache, mock_k8s_client
    ):
        """Test N2 check with nodes missing AZ labels."""
        handler = EKSNetworkingHandler(mock_mcp, mock_client_cache)

        # Mock node without AZ label
        mock_node = MagicMock()
        mock_node.to_dict.return_value = {
            'metadata': {
                'name': 'node-1',
                'labels': {}  # No AZ label
            }
        }

        mock_response = MagicMock()
        mock_response.items = [mock_node]
        mock_k8s_client.list_resources.return_value = mock_response

        result = await handler._check_multi_az_node_distribution(
            'test-cluster', 'us-west-2', mock_k8s_client
        )

        assert result['check_id'] == 'N2'
        assert result['compliant'] is False
        assert 'missing AZ label' in result['impacted_resources'][0]

    @pytest.mark.asyncio
    async def test_check_cluster_endpoint_access_auto_mode(
        self, mock_mcp, mock_client_cache, mock_eks_client
    ):
        """Test N1 check with EKS Auto Mode cluster."""
        handler = EKSNetworkingHandler(mock_mcp, mock_client_cache)

        cluster_info = {
            'endpoint_config_private_access': True,
            'endpoint_config_public_access': True,
            'public_access_cidrs': ['10.0.0.0/8'],
            'is_auto_mode': True,
            'auto_mode_features': {
                'compute_enabled': True,
                'storage_enabled': True
            }
        }

        result = await handler._check_cluster_endpoint_access(
            'test-cluster', 'us-west-2', mock_eks_client, cluster_info
        )

        assert result['check_id'] == 'N1'
        assert result['compliant'] is True
        assert result['details']['cluster_type'] == 'EKS Auto Mode'
        assert 'auto_mode_features' in result['details']

    @pytest.mark.asyncio
    async def test_check_cluster_endpoint_access_error_handling(
        self, mock_mcp, mock_client_cache, mock_eks_client
    ):
        """Test N1 check error handling."""
        handler = EKSNetworkingHandler(mock_mcp, mock_client_cache)

        mock_eks_client.describe_cluster.side_effect = Exception('API Error')

        result = await handler._check_cluster_endpoint_access(
            'test-cluster', 'us-west-2', mock_eks_client, cluster_info=None
        )

        assert result['check_id'] == 'N1'
        assert result['compliant'] is False
        assert 'Failed to check cluster endpoint access' in result['details']['error']

    @pytest.mark.asyncio
    async def test_check_multi_az_node_distribution_legacy_label(
        self, mock_mcp, mock_client_cache, mock_k8s_client
    ):
        """Test N2 check with legacy AZ label format."""
        handler = EKSNetworkingHandler(mock_mcp, mock_client_cache)

        # Mock node with legacy label
        mock_node = MagicMock()
        mock_node.to_dict.return_value = {
            'metadata': {
                'name': 'node-1',
                'labels': {'failure-domain.beta.kubernetes.io/zone': 'us-west-2a'}
            }
        }

        mock_response = MagicMock()
        mock_response.items = [mock_node]
        mock_k8s_client.list_resources.return_value = mock_response

        result = await handler._check_multi_az_node_distribution(
            'test-cluster', 'us-west-2', mock_k8s_client
        )

        assert result['check_id'] == 'N2'
        # Should be non-compliant due to single AZ, but should recognize the legacy label
        assert result['details']['node_distribution']['total_nodes'] == 1
        assert result['details']['node_distribution']['availability_zones'] == 1

    @pytest.mark.asyncio
    async def test_check_multi_az_node_distribution_mixed_labels(
        self, mock_mcp, mock_client_cache, mock_k8s_client
    ):
        """Test N2 check with mixed modern and legacy labels."""
        handler = EKSNetworkingHandler(mock_mcp, mock_client_cache)

        # Mock node with modern label
        mock_node1 = MagicMock()
        mock_node1.to_dict.return_value = {
            'metadata': {
                'name': 'node-1',
                'labels': {'topology.kubernetes.io/zone': 'us-west-2a'}
            }
        }

        # Mock node with legacy label
        mock_node2 = MagicMock()
        mock_node2.to_dict.return_value = {
            'metadata': {
                'name': 'node-2',
                'labels': {'failure-domain.beta.kubernetes.io/zone': 'us-west-2b'}
            }
        }

        mock_response = MagicMock()
        mock_response.items = [mock_node1, mock_node2]
        mock_k8s_client.list_resources.return_value = mock_response

        result = await handler._check_multi_az_node_distribution(
            'test-cluster', 'us-west-2', mock_k8s_client
        )

        assert result['check_id'] == 'N2'
        assert result['details']['node_distribution']['total_nodes'] == 2
        assert result['details']['node_distribution']['availability_zones'] == 2

    @pytest.mark.asyncio
    async def test_check_multi_az_node_distribution_api_error(
        self, mock_mcp, mock_client_cache, mock_k8s_client
    ):
        """Test N2 check with API error."""
        handler = EKSNetworkingHandler(mock_mcp, mock_client_cache)

        mock_k8s_client.list_resources.side_effect = Exception('API error')

        result = await handler._check_multi_az_node_distribution(
            'test-cluster', 'us-west-2', mock_k8s_client
        )

        assert result['check_id'] == 'N2'
        assert result['compliant'] is False
        assert 'error' in result['details']

    @pytest.mark.asyncio
    async def test_check_multi_az_node_distribution_four_azs(
        self, mock_mcp, mock_client_cache, mock_k8s_client
    ):
        """Test N2 check with nodes distributed across 4 AZs."""
        handler = EKSNetworkingHandler(mock_mcp, mock_client_cache)

        # Mock nodes in 4 AZs
        nodes = []
        for i, az in enumerate(['us-west-2a', 'us-west-2b', 'us-west-2c', 'us-west-2d']):
            node = MagicMock()
            node.to_dict.return_value = {
                'metadata': {
                    'name': f'node-{i}',
                    'labels': {'topology.kubernetes.io/zone': az}
                }
            }
            nodes.append(node)

        mock_response = MagicMock()
        mock_response.items = nodes
        mock_k8s_client.list_resources.return_value = mock_response

        result = await handler._check_multi_az_node_distribution(
            'test-cluster', 'us-west-2', mock_k8s_client
        )

        assert result['check_id'] == 'N2'
        assert result['compliant'] is True
        assert result['details']['node_distribution']['availability_zones'] == 4
        assert result['details']['node_distribution']['total_nodes'] == 4

    @pytest.mark.asyncio
    async def test_check_multi_az_node_distribution_two_azs_balanced(
        self, mock_mcp, mock_client_cache, mock_k8s_client
    ):
        """Test N2 check with nodes balanced across 2 AZs."""
        handler = EKSNetworkingHandler(mock_mcp, mock_client_cache)

        # Mock nodes evenly distributed across 2 AZs
        nodes = []
        for i in range(4):
            node = MagicMock()
            az = 'us-west-2a' if i % 2 == 0 else 'us-west-2b'
            node.to_dict.return_value = {
                'metadata': {
                    'name': f'node-{i}',
                    'labels': {'topology.kubernetes.io/zone': az}
                }
            }
            nodes.append(node)

        mock_response = MagicMock()
        mock_response.items = nodes
        mock_k8s_client.list_resources.return_value = mock_response

        result = await handler._check_multi_az_node_distribution(
            'test-cluster', 'us-west-2', mock_k8s_client
        )

        assert result['check_id'] == 'N2'
        assert result['compliant'] is True
        assert result['details']['node_distribution']['availability_zones'] == 2
        assert result['details']['node_distribution']['total_nodes'] == 4


class TestEKSNetworkingHandlerIntegration:
    """Integration-style tests for complete networking check flow."""

    @pytest.mark.asyncio
    async def test_full_networking_check_all_compliant(
        self, mock_mcp, mock_client_cache, mock_context
    ):
        """Test full networking check with all checks passing."""
        handler = EKSNetworkingHandler(mock_mcp, mock_client_cache)

        mock_eks_client = MagicMock()
        mock_k8s_client = MagicMock()

        # Mock compliant cluster endpoint
        cluster_info = {
            'endpoint_config_private_access': True,
            'endpoint_config_public_access': False,
            'public_access_cidrs': [],
            'is_auto_mode': False
        }

        # Mock nodes distributed across 3 AZs
        nodes = []
        for i, az in enumerate(['us-west-2a', 'us-west-2b', 'us-west-2c']):
            node = MagicMock()
            node.to_dict.return_value = {
                'metadata': {
                    'name': f'node-{i}',
                    'labels': {'topology.kubernetes.io/zone': az}
                }
            }
            nodes.append(node)

        mock_response = MagicMock()
        mock_response.items = nodes
        mock_k8s_client.list_resources.return_value = mock_response

        clients = {
            'eks': mock_eks_client,
            'k8s': mock_k8s_client
        }

        handler._initialize_clients = AsyncMock(return_value=clients)

        with patch.object(handler, '_check_cluster_endpoint_access') as mock_n1:
            with patch.object(handler, '_check_multi_az_node_distribution') as mock_n2:
                mock_n1.return_value = {
                    'check_id': 'N1',
                    'check_name': 'Cluster Endpoint Access',
                    'compliant': True,
                    'impacted_resources': [],
                    'details': {},
                    'remediation': ''
                }
                mock_n2.return_value = {
                    'check_id': 'N2',
                    'check_name': 'Multi-AZ Node Distribution',
                    'compliant': True,
                    'impacted_resources': [],
                    'details': {'node_distribution': {'availability_zones': 3, 'total_nodes': 3}},
                    'remediation': ''
                }

                result = await handler.check_eks_networking(
                    mock_context, cluster_name='test-cluster', region='us-west-2'
                )

        assert isinstance(result, NetworkingCheckResponse)
        assert result.isError is False
        # With all compliant checks, overall should be compliant
        passed_checks = sum(1 for check in result.check_results if check['compliant'])
        assert passed_checks > 0

    @pytest.mark.asyncio
    async def test_full_networking_check_with_failures(
        self, mock_mcp, mock_client_cache, mock_context
    ):
        """Test full networking check with some checks failing."""
        handler = EKSNetworkingHandler(mock_mcp, mock_client_cache)

        mock_eks_client = MagicMock()
        mock_k8s_client = MagicMock()

        # Mock non-compliant cluster endpoint (unrestricted public access)
        cluster_info = {
            'endpoint_config_private_access': False,
            'endpoint_config_public_access': True,
            'public_access_cidrs': ['0.0.0.0/0'],
            'is_auto_mode': False
        }

        # Mock nodes all in single AZ (non-compliant)
        nodes = []
        for i in range(3):
            node = MagicMock()
            node.to_dict.return_value = {
                'metadata': {
                    'name': f'node-{i}',
                    'labels': {'topology.kubernetes.io/zone': 'us-west-2a'}
                }
            }
            nodes.append(node)

        mock_response = MagicMock()
        mock_response.items = nodes
        mock_k8s_client.list_resources.return_value = mock_response

        clients = {
            'eks': mock_eks_client,
            'k8s': mock_k8s_client
        }

        handler._initialize_clients = AsyncMock(return_value=clients)

        with patch.object(handler, '_check_cluster_endpoint_access') as mock_n1:
            with patch.object(handler, '_check_multi_az_node_distribution') as mock_n2:
                mock_n1.return_value = {
                    'check_id': 'N1',
                    'check_name': 'Cluster Endpoint Access',
                    'compliant': False,
                    'impacted_resources': ['Cluster: test-cluster'],
                    'details': {'issues_found': 'Unrestricted public access detected'},
                    'remediation': 'Restrict public access'
                }
                mock_n2.return_value = {
                    'check_id': 'N2',
                    'check_name': 'Multi-AZ Node Distribution',
                    'compliant': False,
                    'impacted_resources': ['All nodes in single AZ: us-west-2a'],
                    'details': {'node_distribution': {'availability_zones': 1, 'total_nodes': 3}},
                    'remediation': 'Distribute nodes across multiple AZs'
                }

                result = await handler.check_eks_networking(
                    mock_context, cluster_name='test-cluster', region='us-west-2'
                )

        assert isinstance(result, NetworkingCheckResponse)
        assert result.isError is False
        assert result.overall_compliant is False
        # Should have multiple failed checks
        failed_checks = sum(1 for check in result.check_results if not check['compliant'])
        assert failed_checks > 0
