# Getting Started

This guide will help you get VulnRelay up and running quickly, from local testing to production deployment.

## 📋 Prerequisites

- **Go**: Version 1.24+ (for building from source)
- **Kubernetes**: Access to a cluster (for production deployment)
- **AWS Credentials**: For scanning ECR images (not needed for mock mode)
- **Helm**: Version 3.0+ (for Helm deployment)

## 🚀 Quick Start Options

### Option 1: Mock Mode (Recommended for First Try)

Test VulnRelay without any external dependencies:

```bash
# Clone the repository
git clone <repository-url>
cd VulnRelay

# Build the application
go build -o vulnrelay ./cmd/vulnrelay

# Start with mock data
./vulnrelay --mock

# In another terminal, test the endpoints
curl http://localhost:9090/health
curl http://localhost:9090/metrics | head -20
curl 'http://localhost:9090/vulnerabilities?pretty=1' | head -50
```

**What happens in mock mode:**
- Simulates 10 realistic container images with vulnerabilities
- Generates diverse vulnerability data based on image types
- No AWS credentials or external API calls required
- Perfect for understanding the API and metrics format

### Option 2: Local Mode with Real Data

Test with real ECR vulnerability data:

```bash
# Set up AWS credentials
export AWS_PROFILE=your-profile
# or set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY

# Configure VulnRelay
export AWS_ECR_ACCOUNT_ID=123456789012
export AWS_ECR_REGION=us-east-1
export MODE=local
export IMAGE_LIST_FILE=./examples/sample-images.json
export LOG_LEVEL=debug

# Create a sample image list
cat > sample-images.json << 'EOF'
[
  "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app:v1.0.0",
  "123456789012.dkr.ecr.us-east-1.amazonaws.com/api-service:latest"
]
EOF

# Run VulnRelay
./vulnrelay

# Test endpoints
curl http://localhost:9090/health
curl 'http://localhost:9090/vulnerabilities?image=my-app&pretty=1'
```

### Option 3: Kubernetes Deployment

Deploy to your Kubernetes cluster:

```bash
# Install with Helm
helm install vulnrelay ./helm/vulnrelay \
  --set config.ecrAccountId=YOUR_ACCOUNT_ID \
  --set config.ecrRegion=YOUR_REGION \
  --set serviceAccount.annotations."eks\.amazonaws\.com/role-arn"=arn:aws:iam::YOUR_ACCOUNT_ID:role/VulnRelayRole

# Check deployment status
kubectl get pods -l app.kubernetes.io/name=vulnrelay

# Port forward to test locally
kubectl port-forward svc/vulnrelay 9090:9090

# Test endpoints
curl http://localhost:9090/health
```

## 🔧 Configuration Basics

VulnRelay uses environment variables and command-line flags for configuration:

### Required Configuration (Real Mode)

```bash
export AWS_ECR_ACCOUNT_ID=123456789012    # Your AWS account ID
export AWS_ECR_REGION=us-east-1           # ECR region
```

### Common Options

```bash
export MODE=cluster                       # cluster|local
export PORT=9090                          # HTTP server port
export SCRAPE_INTERVAL=5m                 # How often to refresh data
export LOG_LEVEL=info                     # debug|info|warn|error
export MOCK_MODE=false                    # Enable mock mode
```

### Local Mode (File-based)

```bash
export MODE=local
export IMAGE_LIST_FILE=./images.json     # Path to image list JSON file
```

### Cross-Account Access

```bash
export AWS_IAM_ASSUME_ROLE_ARN=arn:aws:iam::TARGET_ACCOUNT:role/VulnRelayRole
```

## 📊 Understanding the Output

### Health Check
```bash
curl http://localhost:9090/health
# Response: {"status":"ok"}
```

### Vulnerability Summary
```bash
curl 'http://localhost:9090/vulnerabilities' | jq '.summary'
```

### Prometheus Metrics
```bash
curl http://localhost:9090/metrics | grep ecr_image_vulnerability_count
```

### Filtered Results
```bash
# Critical vulnerabilities only
curl 'http://localhost:9090/vulnerabilities?severity=CRITICAL&pretty=1'

# Specific image
curl 'http://localhost:9090/vulnerabilities?image=my-app&pretty=1'

# Limited results
curl 'http://localhost:9090/vulnerabilities?limit=5&pretty=1'
```

## 🎯 Next Steps

1. **[Configuration Reference](../configuration/)**: Complete configuration options
2. **[API Documentation](../api/)**: Detailed API reference and examples  
3. **[Deployment Guide](../deployment/)**: Production deployment with Helm
4. **[Development Guide](../development/)**: Contributing and extending VulnRelay

## ❓ Troubleshooting

### Common Issues

**Permission Denied (AWS)**
```bash
# Check AWS credentials
aws sts get-caller-identity

# Verify ECR permissions
aws ecr describe-repositories --region us-east-1
```

**Connection Refused**
```bash
# Check if VulnRelay is running
ps aux | grep vulnrelay

# Verify port binding
netstat -tlnp | grep 9090
```

**No Vulnerabilities Found**
```bash
# Check if images exist in ECR
aws ecr describe-images --repository-name my-app --region us-east-1

# Verify image list format (local mode)
cat images.json | jq '.'
```

**Kubernetes Access Issues**
```bash
# Test kubectl access
kubectl get nodes

# Check service account permissions
kubectl describe serviceaccount vulnrelay
```

### Getting Help

- Check the logs: `kubectl logs deployment/vulnrelay`
- Use debug logging: `export LOG_LEVEL=debug`
- Verify configuration: `./vulnrelay --help`
- Test with mock mode first: `./vulnrelay --mock`

For more help:
- [GitHub Issues](https://github.com/your-org/vulnrelay/issues)
- [Troubleshooting Guide](../development/troubleshooting.md)
- [FAQ](../development/faq.md)