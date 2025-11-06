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

"""awslabs eks-review MCP Server implementation."""

from awslabs.eks_review_mcp_server.eks_resiliency_handler import EKSResiliencyHandler
from awslabs.eks_review_mcp_server.eks_security_handler import EKSSecurityHandler
from awslabs.eks_review_mcp_server.eks_karpenter_handler import EKSKarpenterHandler
from awslabs.eks_review_mcp_server.eks_cluster_autoscaler_handler import EKSClusterAutoscalerHandler
from awslabs.eks_review_mcp_server.eks_networking_handler import EKSNetworkingHandler
from awslabs.eks_review_mcp_server.k8s_client_cache import K8sClientCache
from loguru import logger
from mcp.server.fastmcp import FastMCP
from typing import Literal


INSTRUCTIONS = """Amazon EKS Review MCP Server - Assess EKS clusters against AWS best practices across networking, security, resiliency, Karpenter, and Cluster Autoscaler.

## Tools

**check_eks_networking**: Cluster endpoint access, multi-AZ distribution, VPC/subnet configuration, security groups
**check_eks_security**: IAM/RBAC, pod security, encryption, secrets management, infrastructure security
**check_eks_resiliency**: Pod controllers, replicas, health probes, PDBs, autoscaling (HPA/VPA/CA), monitoring
**check_karpenter_best_practices**: Karpenter deployment, NodePools, instance selection, spot optimization
**check_cluster_autoscaler_best_practices**: CA deployment, version compatibility, auto-discovery, node groups

## Usage

**General review** → Run all 5 tools
**Specific domain** → Run relevant tool only (networking/security/resiliency/karpenter/cluster-autoscaler)

## Tool Output

Each check returns:
- **compliant**: Pass/fail status
- **impacted_resources**: Failed resources
- **details**: Current configuration state
- **remediation**: Empty - AI generates context-aware fixes
- **severity**: High/Medium/Low

## AI Responsibilities

1. Analyze findings from details and impacted_resources
2. Generate remediation based on AWS/K8s best practices
3. Prioritize by severity (High → Medium → Low)
4. Provide actionable steps (commands, YAML, configs)

## Notes

- Tools report current state only; AI generates all remediation
- Requires AWS credentials and kubectl access
- Optimized to minimize API calls (resources fetched once, shared across checks)
- Auto Mode detection: Karpenter/CA checks skip for Auto Mode clusters

Aligns with: https://docs.aws.amazon.com/eks/latest/best-practices/
"""

mcp = FastMCP(
    "awslabs.eks-review-mcp-server",
    instructions=INSTRUCTIONS,
    dependencies=[
        'pydantic',
        'loguru',
        'boto3',
        'kubernetes',
        'cachetools',
    ],
)


# Initialize shared client cache
client_cache = K8sClientCache()

# Initialize the EKS resiliency handler
resiliency_handler = EKSResiliencyHandler(mcp, client_cache)

# Initialize the EKS security handler
security_handler = EKSSecurityHandler(mcp, client_cache)

# Initialize the EKS Karpenter handler
karpenter_handler = EKSKarpenterHandler(mcp, client_cache)

# Initialize the EKS Cluster Autoscaler handler
cluster_autoscaler_handler = EKSClusterAutoscalerHandler(mcp, client_cache)

# Initialize the EKS networking handler
networking_handler = EKSNetworkingHandler(mcp, client_cache)


def main():
    """Run the MCP server with CLI argument support."""

    logger.trace('A trace message.')
    logger.debug('A debug message.')
    logger.info('An info message.')
    logger.success('A success message.')
    logger.warning('A warning message.')
    logger.error('An error message.')
    logger.critical('A critical message.')

    mcp.run()


if __name__ == '__main__':
    main()
