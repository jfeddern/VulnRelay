# VulnRelay Helm Chart

This Helm chart deploys VulnRelay, a multi-cloud vulnerability collection service that scans container images for vulnerabilities and exposes metrics for Prometheus.

## Prerequisites

- Kubernetes 1.19+
- Helm 3.2.0+
- Kubernetes cluster (currently supports AWS EKS) with proper IAM roles configured
- Prometheus Operator (if using ServiceMonitor)

## Installation

### 1. Configure AWS IAM Role

First, create an IAM role for the application with the necessary permissions:

```bash
# Create trust policy for EKS Pod Identity
cat > trust-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::ACCOUNT_ID:oidc-provider/oidc.eks.REGION.amazonaws.com/id/CLUSTER_OIDC_ID"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "oidc.eks.REGION.amazonaws.com/id/CLUSTER_OIDC_ID:sub": "system:serviceaccount:NAMESPACE:vulnrelay"
        }
      }
    }
  ]
}
EOF

# Create the role
aws iam create-role \
  --role-name VulnRelayRole \
  --assume-role-policy-document file://trust-policy.json

# Attach the policy (you can use the policy.json from the ConfigMap)
aws iam put-role-policy \
  --role-name VulnRelayRole \
  --policy-name VulnRelayPolicy \
  --policy-document file://policy.json
```

### 2. Install the Chart

```bash
# Install from GitHub Container Registry (recommended)
helm install vulnrelay oci://ghcr.io/jan/vulnrelay/charts/vulnrelay \
  --set config.ecrAccountId=YOUR_ACCOUNT_ID \
  --set config.ecrRegion=YOUR_REGION \
  --set serviceAccount.annotations."eks\.amazonaws\.com/role-arn"=arn:aws:iam::YOUR_ACCOUNT_ID:role/VulnRelayRole

# Or install from local chart
helm install vulnrelay ./helm/vulnrelay \
  --set config.ecrAccountId=YOUR_ACCOUNT_ID \
  --set config.ecrRegion=YOUR_REGION \
  --set serviceAccount.annotations."eks\.amazonaws\.com/role-arn"=arn:aws:iam::YOUR_ACCOUNT_ID:role/VulnRelayRole
```

### 3. Cross-Account Access

For cross-account ECR access, use the `AWS_IAM_ASSUME_ROLE_ARN` environment variable:

```bash
helm install vulnrelay ./helm/vulnrelay \
  --set config.ecrAccountId=TARGET_ACCOUNT_ID \
  --set config.ecrRegion=TARGET_REGION \
  --set config.assumeRoleArn=arn:aws:iam::TARGET_ACCOUNT_ID:role/VulnRelayRole
```

## Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.mode` | Operation mode: cluster or local | `cluster` |
| `config.ecrAccountId` | AWS account ID for ECR registry (env: AWS_ECR_ACCOUNT_ID) | `123456789012` |
| `config.ecrRegion` | AWS region for ECR registry (env: AWS_ECR_REGION) | `us-east-1` |
| `config.assumeRoleArn` | AWS IAM role ARN to assume for cross-account access | `""` |
| `config.scrapeInterval` | Interval to refresh data from ECR | `5m` |
| `config.logLevel` | Logging level | `info` |
| `config.imageListFile` | Path to JSON file with image list (local mode only) | `""` |
| `replicaCount` | Number of replicas | `1` |
| `image.repository` | Container image repository | `vulnrelay` |
| `image.tag` | Container image tag | `latest` |
| `image.pullPolicy` | Container image pull policy | `Always` |
| `namespace` | Kubernetes namespace | `default` |
| `serviceAccount.create` | Create service account | `true` |
| `serviceAccount.annotations` | Service account annotations | EKS Pod Identity annotation |
| `rbac.create` | Create RBAC resources | `true` |
| `serviceMonitor.enabled` | Create ServiceMonitor for Prometheus Operator | `true` |
| `resources.requests.memory` | Memory request | `64Mi` |
| `resources.requests.cpu` | CPU request | `100m` |
| `resources.limits.memory` | Memory limit | `128Mi` |
| `resources.limits.cpu` | CPU limit | `200m` |

## Monitoring

The chart includes a ServiceMonitor for Prometheus Operator. Metrics are exposed on `/metrics` endpoint:

- `ecr_image_vulnerability_count` - Number of vulnerabilities by severity
- `ecr_image_scan_status` - Scan status of images  
- `ecr_image_last_scan_timestamp` - Last scan timestamp

## Uninstalling

```bash
helm uninstall vulnrelay
```

## Development

To test the chart locally:

```bash
# Lint the chart
helm lint helm/vulnrelay

# Template and validate
helm template test-release helm/vulnrelay \
  --set config.ecrAccountId=123456789012 \
  --set config.ecrRegion=us-east-1 \
  --dry-run
```