# Configuration Reference

Complete configuration guide for VulnRelay including all options, environment variables, and examples.

## 📋 Configuration Methods

VulnRelay supports configuration through multiple methods with the following precedence:

1. **Environment Variables** (highest priority)
2. **Command Line Flags**
3. **Default Values** (lowest priority)

## 🔧 Core Configuration

### AWS Configuration

All AWS-specific configuration uses the `AWS_` prefix for better organization when adding other cloud providers.

| Flag | Environment Variable | Required | Default | Description |
|------|---------------------|----------|---------|-------------|
| `-ecr-account-id` | `AWS_ECR_ACCOUNT_ID` | ✅ | - | AWS account ID containing the ECR registry |
| `-ecr-region` | `AWS_ECR_REGION` | ✅ | - | AWS region of the ECR registry |
| - | `AWS_IAM_ASSUME_ROLE_ARN` | ❌ | - | IAM role ARN to assume for cross-account access |

### Operation Modes

| Flag | Environment Variable | Default | Description |
|------|---------------------|---------|-------------|
| `-mode` | `MODE` | `cluster` | Operation mode: `cluster`, `local` |
| `-image-list-file` | `IMAGE_LIST_FILE` | - | Path to JSON file with image list (required for local mode) |
| `-mock` | `MOCK_MODE` | `false` | Enable mock mode for local testing |

### Server Configuration

| Flag | Environment Variable | Default | Description |
|------|---------------------|---------|-------------|
| `-port` | `PORT` | `9090` | Port for metrics and API endpoints |
| `-scrape-interval` | `SCRAPE_INTERVAL` | `5m` | Interval to refresh vulnerability data |

### Logging Configuration

| Flag | Environment Variable | Default | Description |
|------|---------------------|---------|-------------|
| - | `LOG_LEVEL` | `info` | Log level: `debug`, `info`, `warn`, `error` |

## 🎯 Configuration Examples

### Cluster Mode (Same Account)

**Environment Variables:**
```bash
export AWS_ECR_ACCOUNT_ID=123456789012
export AWS_ECR_REGION=us-east-1
export LOG_LEVEL=info
```

**Command Line:**
```bash
./vulnrelay \
  -ecr-account-id 123456789012 \
  -ecr-region us-east-1
```

**Kubernetes ConfigMap:**
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: vulnrelay-config
data:
  AWS_ECR_ACCOUNT_ID: "123456789012"
  AWS_ECR_REGION: "us-east-1"
  LOG_LEVEL: "info"
```

### Cluster Mode (Cross Account)

```bash
export AWS_ECR_ACCOUNT_ID=987654321098
export AWS_ECR_REGION=us-west-2
export AWS_IAM_ASSUME_ROLE_ARN=arn:aws:iam::987654321098:role/VulnRelayRole
export LOG_LEVEL=info
```

### Local Mode

```bash
export MODE=local
export AWS_ECR_ACCOUNT_ID=123456789012
export AWS_ECR_REGION=us-east-1
export IMAGE_LIST_FILE=./images.json
export LOG_LEVEL=debug
export PORT=8080
export SCRAPE_INTERVAL=10m
```

### Mock Mode (Development)

```bash
export MOCK_MODE=true
export LOG_LEVEL=debug
export PORT=8080
export SCRAPE_INTERVAL=30s
```

## 📄 Image List Format (Local Mode)

When using local mode, provide a JSON file with an array of ECR image URIs:

```json
[
  "123456789012.dkr.ecr.us-east-1.amazonaws.com/web-frontend:v1.2.3",
  "123456789012.dkr.ecr.us-east-1.amazonaws.com/api-backend:v2.1.0",
  "123456789012.dkr.ecr.us-east-1.amazonaws.com/worker-service:latest",
  "123456789012.dkr.ecr.us-east-1.amazonaws.com/postgres-db:14.9"
]
```

**Image URI Format:**
```
{account-id}.dkr.ecr.{region}.amazonaws.com/{repository}:{tag}
```

**Examples:**
- Basic: `123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app:latest`
- Nested: `123456789012.dkr.ecr.us-east-1.amazonaws.com/team/my-app:v1.0.0`
- Deep nesting: `123456789012.dkr.ecr.us-east-1.amazonaws.com/org/team/service:v2.1.0`

## 🔐 AWS Authentication

VulnRelay supports multiple AWS authentication methods:

### 1. Environment Variables
```bash
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
export AWS_REGION=us-east-1
```

### 2. AWS Profile
```bash
export AWS_PROFILE=my-profile
```

### 3. IAM Roles (Kubernetes)
```yaml
# ServiceAccount with IAM role annotation
apiVersion: v1
kind: ServiceAccount
metadata:
  name: vulnrelay
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/VulnRelayRole
```

### 4. Cross-Account Access
```bash
# VulnRelay runs in Account A, scans ECR in Account B
export AWS_ECR_ACCOUNT_ID=111111111111           # Account B (target)
export AWS_ECR_REGION=us-east-1
export AWS_IAM_ASSUME_ROLE_ARN=arn:aws:iam::111111111111:role/VulnRelayRole
```

## ⚙️ Advanced Configuration

### Scrape Interval

Controls how often VulnRelay fetches fresh vulnerability data:

```bash
export SCRAPE_INTERVAL=5m    # Every 5 minutes (default)
export SCRAPE_INTERVAL=30s   # Every 30 seconds (development)
export SCRAPE_INTERVAL=1h    # Every hour (low-frequency)
```

**Format:** Go duration format (`30s`, `5m`, `1h`, `24h`)

### Log Levels

Control verbosity of log output:

```bash
export LOG_LEVEL=debug   # Detailed debugging information
export LOG_LEVEL=info    # General information (default)
export LOG_LEVEL=warn    # Warnings and errors only
export LOG_LEVEL=error   # Errors only
```

### Port Configuration

```bash
export PORT=9090         # Default Prometheus port
export PORT=8080         # Alternative port
export PORT=3000         # Development port
```

## 🏗️ Production Configuration

### Recommended Settings

```bash
# Production cluster mode
export AWS_ECR_ACCOUNT_ID=123456789012
export AWS_ECR_REGION=us-east-1
export MODE=cluster
export PORT=9090
export SCRAPE_INTERVAL=5m
export LOG_LEVEL=info
```

### High-Volume Environments

```bash
# Longer intervals for many images
export SCRAPE_INTERVAL=10m
export LOG_LEVEL=warn
```

### Development/Testing

```bash
# Faster refresh for development
export SCRAPE_INTERVAL=30s
export LOG_LEVEL=debug
export MOCK_MODE=true
```

## 🐳 Container Configuration

### Docker Run

```bash
docker run -d \
  --name vulnrelay \
  -p 9090:9090 \
  -e AWS_ECR_ACCOUNT_ID=123456789012 \
  -e AWS_ECR_REGION=us-east-1 \
  -e AWS_ACCESS_KEY_ID=AKIA... \
  -e AWS_SECRET_ACCESS_KEY=wJal... \
  ghcr.io/jfeddern/vulnrelay:latest
```

### Docker Compose

```yaml
version: '3.8'
services:
  vulnrelay:
    image: ghcr.io/jfeddern/vulnrelay:latest
    ports:
      - "9090:9090"
    environment:
      AWS_ECR_ACCOUNT_ID: "123456789012"
      AWS_ECR_REGION: "us-east-1"
      MODE: "local"
      IMAGE_LIST_FILE: "/data/images.json"
      LOG_LEVEL: "info"
    volumes:
      - ./images.json:/data/images.json:ro
    restart: unless-stopped
```

## ✅ Configuration Validation

VulnRelay validates configuration at startup and will exit with helpful error messages:

### Missing Required Configuration
```
FATAL: AWS ECR account ID is required. Set AWS_ECR_ACCOUNT_ID environment variable or use -ecr-account-id flag
```

### Invalid Local Mode
```
FATAL: Local mode requires image list file. Set IMAGE_LIST_FILE environment variable or use -image-list-file flag
```

### Invalid Scrape Interval
```
FATAL: Invalid scrape interval '5x': time: unknown unit "x" in duration "5x"
```

### Cross-Account Role Issues
```
ERROR: Failed to assume role arn:aws:iam::123456789012:role/VulnRelayRole: AccessDenied
```

## 🔍 Configuration Testing

Test your configuration before deployment:

```bash
# Test configuration parsing
./vulnrelay --help

# Test AWS credentials
AWS_PROFILE=myprofile aws sts get-caller-identity

# Test ECR access
aws ecr describe-repositories --region us-east-1

# Test with minimal run
./vulnrelay --mock
curl http://localhost:9090/health
```

## 📝 Configuration Templates

See [configuration templates](./templates/) for common deployment scenarios:

- [`cluster-same-account.env`](./templates/cluster-same-account.env)
- [`cluster-cross-account.env`](./templates/cluster-cross-account.env)
- [`local-development.env`](./templates/local-development.env)
- [`mock-testing.env`](./templates/mock-testing.env)