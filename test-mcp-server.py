#!/usr/bin/env python3
"""
Test script for the EKS Cluster Autoscaler MCP Server
"""

import asyncio
import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from awslabs.eks_review_mcp_server.eks_cluster_autoscaler_handler import EKSClusterAutoscalerHandler
from awslabs.eks_review_mcp_server.k8s_client_cache import K8sClientCache
from mcp.server.fastmcp import FastMCP

async def test_cluster_autoscaler_checks():
    """Test the Cluster Autoscaler checks"""
    
    # Initialize MCP server and handler
    mcp = FastMCP("test-server")
    client_cache = K8sClientCache()
    handler = EKSClusterAutoscalerHandler(mcp, client_cache)
    
    cluster_name = "test-cas-cluster"
    
    print(f"🔍 Testing Cluster Autoscaler checks for cluster: {cluster_name}")
    print("=" * 60)
    
    try:
        # Create a mock context
        class MockContext:
            pass
        
        ctx = MockContext()
        
        # Run the cluster autoscaler check
        result = await handler.check_cluster_autoscaler_best_practices(
            ctx=ctx,
            cluster_name=cluster_name,
            namespace="kube-system"
        )
        
        print(f"✅ Overall Compliant: {result.overall_compliant}")
        print(f"📊 Summary: {result.summary}")
        print("\n📋 Detailed Results:")
        print("-" * 40)
        
        for check in result.check_results:
            status = "✅ PASS" if check['compliant'] else "❌ FAIL"
            print(f"{status} {check['check_id']}: {check['check_name']}")
            print(f"   Details: {check['details']}")
            if not check['compliant'] and check['remediation']:
                print(f"   💡 Remediation: {check['remediation'][:100]}...")
            print()
            
    except Exception as e:
        print(f"❌ Error running checks: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_cluster_autoscaler_checks())