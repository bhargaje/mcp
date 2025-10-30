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

"""Data models for the EKS Review MCP Server."""

from mcp.types import CallToolResult
from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional


class ResiliencyCheckResponse(CallToolResult):
    """Response model for EKS resiliency check tool."""

    check_results: List[Dict[str, Any]] = Field(..., description='List of check results')
    overall_compliant: bool = Field(..., description='Whether all checks passed')
    summary: str = Field(..., description='Summary of the check results')


class SecurityCheckResponse(CallToolResult):
    """Response model for EKS security check tool."""

    check_results: List[Dict[str, Any]] = Field(..., description='List of check results')
    overall_compliant: bool = Field(..., description='Whether all checks passed')
    summary: str = Field(..., description='Summary of the check results')


class KarpenterCheckResponse(CallToolResult):
    """Response model for Karpenter best practices check tool."""
    
    check_results: List[Dict[str, Any]] = Field(..., description='List of check results')
    overall_compliant: bool = Field(..., description='Whether all checks passed')
    summary: str = Field(..., description='Summary of the check results')
    
class NetworkingCheckResponse(CallToolResult):
    """Response model for EKS networking check tool."""

    check_results: List[Dict[str, Any]] = Field(..., description='List of check results')
    overall_compliant: bool = Field(..., description='Whether all checks passed')
    summary: str = Field(..., description='Summary of the check results')


class ClusterAutoscalerCheckResponse(CallToolResult):
    """Response model for Cluster Autoscaler best practices check tool."""

    check_results: List[Dict[str, Any]] = Field(..., description='List of check results')
    overall_compliant: bool = Field(..., description='Whether all checks passed')
    summary: str = Field(..., description='Summary of the check results')