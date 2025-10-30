#!/bin/bash

CLUSTER_NAME="test-cas-cluster"
REGION="us-west-2"
ACCOUNT_ID="629748531802"

echo "Setting up Cluster Autoscaler for cluster: $CLUSTER_NAME"

# Create IAM policy
echo "Creating IAM policy..."
aws iam create-policy \
    --policy-name AmazonEKSClusterAutoscalerPolicy \
    --policy-document file://cluster-autoscaler-iam-policy.json \
    --region $REGION

# Create IAM role for service account
echo "Creating IAM role for service account..."
eksctl create iamserviceaccount \
    --cluster=$CLUSTER_NAME \
    --namespace=kube-system \
    --name=cluster-autoscaler \
    --attach-policy-arn=arn:aws:iam::$ACCOUNT_ID:policy/AmazonEKSClusterAutoscalerPolicy \
    --override-existing-serviceaccounts \
    --region=$REGION \
    --approve

# Update kubeconfig
echo "Updating kubeconfig..."
aws eks update-kubeconfig --region $REGION --name $CLUSTER_NAME

# Deploy Cluster Autoscaler
echo "Deploying Cluster Autoscaler..."
kubectl apply -f cluster-autoscaler-deployment.yaml

# Wait for deployment
echo "Waiting for Cluster Autoscaler to be ready..."
kubectl rollout status deployment/cluster-autoscaler -n kube-system --timeout=300s

echo "Cluster Autoscaler setup complete!"
echo "You can check the logs with: kubectl logs -f deployment/cluster-autoscaler -n kube-system"