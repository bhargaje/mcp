#!/bin/bash

CLUSTER_NAME="test-cas-cluster"
REGION="us-west-2"

echo "Checking EKS cluster status..."

# Check if cluster exists and is active
CLUSTER_STATUS=$(aws eks describe-cluster --name $CLUSTER_NAME --region $REGION --query 'cluster.status' --output text 2>/dev/null)

if [ $? -eq 0 ]; then
    echo "✅ Cluster Status: $CLUSTER_STATUS"
    
    if [ "$CLUSTER_STATUS" = "ACTIVE" ]; then
        echo "🎉 Cluster is ready!"
        
        # Update kubeconfig
        echo "Updating kubeconfig..."
        aws eks update-kubeconfig --region $REGION --name $CLUSTER_NAME
        
        # Check nodes
        echo "Checking nodes..."
        kubectl get nodes
        
        echo ""
        echo "🚀 Ready to deploy Cluster Autoscaler!"
        echo "Run: ./setup-cluster-autoscaler.sh"
    else
        echo "⏳ Cluster is still being created. Current status: $CLUSTER_STATUS"
    fi
else
    echo "❌ Cluster not found or error occurred"
fi