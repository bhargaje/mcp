# EKS Cluster Autoscaler MCP Server Test Plan

## Overview
This document outlines the testing approach for the new Cluster Autoscaler best practices handler in the EKS Review MCP Server.

## Test Environment Setup

### 1. EKS Cluster Creation (In Progress)
- **Cluster Name**: `test-cas-cluster`
- **Region**: `us-west-2`
- **Node Group**: `test-cas-nodegroup` (t3.medium, 1-4 nodes)
- **Status**: Currently being created via eksctl

### 2. Cluster Autoscaler Deployment
Once cluster is ready:
```bash
# Check cluster status
./check-cluster-status.sh

# Deploy Cluster Autoscaler
./setup-cluster-autoscaler.sh
```

## Test Scenarios

### Scenario 1: Baseline Test (No Cluster Autoscaler)
**Expected Results:**
- ❌ AD1: Auto Discovery not enabled
- ❌ AD2: Missing auto-discovery tags
- ❌ All deployment checks should fail
- ❌ Most configuration checks should fail

### Scenario 2: After Cluster Autoscaler Deployment
**Expected Results:**
- ✅ AD1: Auto Discovery enabled
- ✅ AD2: Node groups have proper tags
- ✅ Deployment checks should pass
- ✅ Most configuration checks should pass

### Scenario 3: Intentional Misconfigurations
Test various failure scenarios:
- Remove auto-discovery tags from node groups
- Modify deployment to use multiple replicas
- Change expander to suboptimal setting
- Remove resource limits

## Test Execution

### Manual Testing
```bash
# Run the MCP server test
python test-mcp-server.py

# Or test individual components
uv run python -c "
import asyncio
from awslabs.eks_review_mcp_server.eks_cluster_autoscaler_handler import EKSClusterAutoscalerHandler
# ... test code
"
```

### Expected Check Results

#### Version Compatibility
- **VC1**: Should pass if CA version matches cluster version (1.28)

#### Auto Discovery  
- **AD1**: Should pass after CA deployment
- **AD2**: Should pass with proper node group tags

#### IAM Permissions
- **IAM1**: Should pass with scoped IAM policy

#### Node Group Configuration
- **NG1**: Should pass with identical scheduling properties
- **NG2**: Should pass (we have 1 node group)
- **NG3**: Should pass (using managed node groups)

#### Cost Optimization
- **CO1**: May fail (using On-Demand only)
- **CO2**: Should pass (single capacity type)
- **CO3**: Should pass (using least-waste expander)

#### Performance & Scalability
- **PS1**: Should pass with proper resource allocation
- **PS2**: Should pass with default scan interval

#### Availability
- **AV1**: May fail (no overprovisioning configured)
- **AV2**: Should pass (no expensive workloads to protect)

## Validation Steps

1. **Pre-deployment Check**: Run test before CA deployment
2. **Post-deployment Check**: Run test after CA deployment
3. **Compare Results**: Verify improvement in compliance
4. **Log Analysis**: Check CA logs for proper operation
5. **Scaling Test**: Deploy test workload to trigger scaling

## Success Criteria

- [ ] MCP server starts without errors
- [ ] All 15 checks execute successfully
- [ ] Appropriate pass/fail results based on configuration
- [ ] Detailed remediation guidance provided for failures
- [ ] No false positives or negatives
- [ ] Performance acceptable (< 30 seconds for all checks)

## Troubleshooting

### Common Issues
- **Cluster not ready**: Wait for CloudFormation stack completion
- **kubectl access**: Ensure kubeconfig is updated
- **IAM permissions**: Verify service account role creation
- **CA not starting**: Check logs and RBAC permissions

### Debug Commands
```bash
# Check cluster status
kubectl get nodes
kubectl get pods -n kube-system | grep cluster-autoscaler

# Check CA logs
kubectl logs -f deployment/cluster-autoscaler -n kube-system

# Check node group tags
aws autoscaling describe-auto-scaling-groups --region us-west-2 --query 'AutoScalingGroups[?contains(Tags[?Key==`k8s.io/cluster-autoscaler/test-cas-cluster`].Value, `owned`)].{Name:AutoScalingGroupName,Tags:Tags}'
```

## Next Steps After Testing

1. **Documentation Update**: Update README with test results
2. **Integration**: Ensure proper integration with main MCP server
3. **Performance Optimization**: Address any performance issues
4. **Additional Checks**: Consider adding more checks based on findings
5. **Production Readiness**: Prepare for production deployment