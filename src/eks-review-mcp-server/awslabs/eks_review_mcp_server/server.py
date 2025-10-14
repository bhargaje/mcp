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
from awslabs.eks_review_mcp_server.eks_networking_handler import EKSNetworkingHandler
from awslabs.eks_review_mcp_server.k8s_client_cache import K8sClientCache
from loguru import logger
from mcp.server.fastmcp import FastMCP
from typing import Literal


mcp = FastMCP(
    "awslabs.eks-review-mcp-server",
    instructions='This MCP server performs operational reviews of Amazon EKS clusters.',
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
