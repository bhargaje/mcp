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
from awslabs.eks_review_mcp_server.eks_networking_handler import EKSNetworkingHandler
from awslabs.eks_review_mcp_server.k8s_client_cache import K8sClientCache
from loguru import logger
from mcp.server.fastmcp import FastMCP
from typing import Literal


INSTRUCTIONS = """Amazon EKS Review MCP Server for operational excellence and best practices assessment of Amazon EKS clusters.

This server provides comprehensive analysis of your EKS clusters against AWS best practices across networking, security, resiliency, and Karpenter configuration.

## Key Capabilities

- **Comprehensive Assessment**: Evaluate clusters across networking, security, resiliency, and Karpenter domains
- **Current State Analysis**: Reports actual configuration and identifies non-compliant resources
- **AI-Generated Remediation**: Tools provide findings; AI generates context-aware remediation guidance
- **Flexible Scope**: Run all checks for complete review or target specific domains

## Available Tools

### check_eks_networking
Evaluates networking configuration and connectivity best practices including cluster endpoint access control, CIDR restrictions, multi-AZ node distribution, VPC configuration, and security group settings.

### check_eks_security
Assesses security posture across IAM/RBAC configuration, pod security standards, multi-tenancy isolation, control plane logging, data encryption, secrets management, and infrastructure security.

### check_eks_resiliency
Analyzes application and infrastructure resilience including pod controllers, replica configuration, anti-affinity rules, health probes, pod disruption budgets, autoscaling (HPA/VPA/Cluster Autoscaler), node lifecycle management, and monitoring/logging setup.

### check_karpenter_best_practices
Reviews Karpenter deployment and configuration including version management, AMI pinning, instance type selection, NodePool configuration, TTL settings, spot instance optimization, resource limits, and disruption budgets.

## Usage Guidelines

### When to Run All Checks
If the user requests a general EKS best practices review or cluster assessment without specifying a domain, **run all four tools**:
1. check_eks_networking
2. check_eks_security
3. check_eks_resiliency
4. check_karpenter_best_practices

### When to Run Specific Checks
If the user explicitly requests a specific domain, run only the relevant tool(s):
- Networking/connectivity/endpoint issues → check_eks_networking
- Security/IAM/RBAC/access control → check_eks_security
- Availability/resilience/autoscaling/pod issues → check_eks_resiliency
- Karpenter/node autoscaling configuration → check_karpenter_best_practices

## Understanding Tool Output

Each tool returns check results with:
- **compliant**: Boolean indicating if the check passed
- **impacted_resources**: List of specific resources that failed the check
- **details**: Description of what was found (current state of the resource)
- **remediation**: Empty string - AI must generate context-aware remediation
- **severity**: High, Medium, or Low priority level

## AI Responsibilities

When analyzing check results, the AI must:

1. **Analyze findings** from the check results (details and impacted_resources fields)
2. **Generate remediation guidance** based on:
   - Specific issues identified in the details
   - Impacted resources that need attention
   - AWS and Kubernetes best practices
   - Context of the user's environment
3. **Prioritize by severity**: Address High severity issues first, then Medium, then Low
4. **Provide actionable steps**: Include specific commands, YAML examples, or configuration changes that can be applied immediately

## Important Notes

- Tools report **current state only** - they do NOT include pre-written remediation text
- AI must generate **dynamic, context-aware remediation** based on actual findings
- All tools require valid AWS credentials and kubectl access to the target cluster
- If a tool fails to connect, inform the user to verify cluster access and credentials

## Common Workflows

### Complete Cluster Review
```
User: "Review my EKS cluster 'production-cluster' for best practices"
AI Action: 
  1. Run all 4 tools (networking, security, resiliency, karpenter)
  2. Analyze all results and identify issues by severity
  3. Generate comprehensive report with prioritized remediation steps
  4. Provide actionable fixes for high-severity issues first
```

### Targeted Security Assessment
```
User: "Check security configuration for 'dev-cluster'"
AI Action:
  1. Run check_eks_security only
  2. Analyze security findings (IAM, RBAC, pod security, encryption)
  3. Generate security-focused remediation with specific fixes
  4. Prioritize critical security vulnerabilities
```

### Karpenter Configuration Review
```
User: "Review my Karpenter setup in 'staging-cluster'"
AI Action:
  1. Run check_karpenter_best_practices
  2. Analyze NodePool configuration, instance selection, spot usage
  3. Provide specific Karpenter configuration improvements
  4. Suggest optimizations for cost and reliability
```

## Best Practices Alignment

This server aligns with AWS EKS Best Practices Guide:
- EKS Best Practices: https://docs.aws.amazon.com/eks/latest/best-practices/introduction.html
- Networking: https://docs.aws.amazon.com/eks/latest/best-practices/networking.html
- Reliability: https://docs.aws.amazon.com/eks/latest/best-practices/reliability.html
- Security: https://docs.aws.amazon.com/eks/latest/best-practices/security.html
- Cluster Autoscaling: https://docs.aws.amazon.com/eks/latest/best-practices/cluster-autoscaling.html
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
