#!/bin/bash

# Variables
CLUSTER_NAME="test-cas-cluster"
REGION="us-west-2"
NODE_GROUP_NAME="test-cas-nodegroup"

echo "Creating EKS cluster: $CLUSTER_NAME in region: $REGION"

# Create EKS cluster
eksctl create cluster \
  --name $CLUSTER_NAME \
  --region $REGION \
  --version 1.28 \
  --nodegroup-name $NODE_GROUP_NAME \
  --node-type t3.medium \
  --nodes 2 \
  --nodes-min 1 \
  --nodes-max 4 \
  --managed \
  --with-oidc \
  --ssh-access \
  --ssh-public-key ~/.ssh/id_rsa.pub \
  --tags "k8s.io/cluster-autoscaler/enabled=true,k8s.io/cluster-autoscaler/$CLUSTER_NAME=owned"

echo "Cluster creation initiated. This will take 10-15 minutes..."