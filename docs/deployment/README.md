# Deployment Guide

Production deployment guide for VulnRelay using Kubernetes, Helm, and other deployment methods.

## 🎯 Deployment Options

| Method | Best For | Complexity | Features |
|--------|----------|------------|----------|
| [**Helm Chart**](#helm-deployment) | Production Kubernetes | Low | Full features, monitoring, security |
| [**Kubernetes Manifests**](#kubernetes-manifests) | Custom deployments | Medium | Manual configuration |
| [**Docker Compose**](#docker-compose) | Development/Testing | Low | Local development |
| [**Binary**](#binary-deployment) | Simple setups | Very Low | Basic functionality |

## 🚀 Helm Deployment (Recommended)

### Prerequisites

- Kubernetes cluster with RBAC enabled
- Helm 3.0+
- AWS IAM permissions configured

### Quick Start

```bash
# Install from local chart
helm install vulnrelay ./helm/vulnrelay \
  --set config.ecrAccountId=123456789012 \
  --set config.ecrRegion=us-east-1

# Install from registry (when published)
helm install vulnrelay oci://ghcr.io/jfeddern/vulnrelay/charts/vulnrelay \
  --set config.ecrAccountId=123456789012 \
  --set config.ecrRegion=us-east-1
```

### Production Configuration

```bash
helm install vulnrelay ./helm/vulnrelay \
  --namespace monitoring \
  --create-namespace \
  --set config.ecrAccountId=123456789012 \
  --set config.ecrRegion=us-east-1 \
  --set config.scrapeInterval=10m \
  --set config.logLevel=info \
  --set image.repository=ghcr.io/jfeddern/vulnrelay \
  --set image.tag=v1.0.0 \
  --set resources.requests.memory=128Mi \
  --set resources.requests.cpu=100m \
  --set resources.limits.memory=256Mi \
  --set resources.limits.cpu=200m \
  --set serviceMonitor.enabled=true \
  --set serviceAccount.annotations."eks\.amazonaws\.com/role-arn"=arn:aws:iam::123456789012:role/VulnRelayRole
```

### Cross-Account Deployment

```bash
helm install vulnrelay ./helm/vulnrelay \
  --set config.ecrAccountId=987654321098 \
  --set config.ecrRegion=us-west-2 \
  --set config.assumeRoleArn=arn:aws:iam::987654321098:role/VulnRelayRole \
  --set serviceAccount.annotations."eks\.amazonaws\.com/role-arn"=arn:aws:iam::123456789012:role/CrossAccountRole
```

### Chart Configuration

Key Helm values you can customize:

```yaml
# values.yaml
config:
  ecrAccountId: "123456789012"
  ecrRegion: "us-east-1"
  mode: "cluster"
  port: 9090
  scrapeInterval: "5m"
  logLevel: "info"
  assumeRoleArn: ""

image:
  repository: ghcr.io/jfeddern/vulnrelay
  tag: latest
  pullPolicy: IfNotPresent

resources:
  requests:
    memory: 128Mi
    cpu: 100m
  limits:
    memory: 256Mi
    cpu: 200m

serviceMonitor:
  enabled: true
  namespace: monitoring
  interval: 30s

nodeSelector: {}
tolerations: []
affinity: {}

securityContext:
  runAsNonRoot: true
  runAsUser: 10001
  readOnlyRootFilesystem: true
```

## 🔐 AWS IAM Setup

### 1. IAM Policy for ECR Access

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ecr:DescribeRepositories",
        "ecr:DescribeImages",
        "ecr:DescribeImageScanFindings",
        "ecr:GetAuthorizationToken",
        "ecr:BatchGetImage"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "inspector2:BatchGetAccountStatus",
        "inspector2:GetFindingsReportStatus",
        "inspector2:ListFindings"
      ],
      "Resource": "*"
    }
  ]
}
```

### 2. Trust Policy for EKS Pod Identity

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE:sub": "system:serviceaccount:monitoring:vulnrelay",
          "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE:aud": "sts.amazonaws.com"
        }
      }
    }
  ]
}
```

### 3. Create IAM Role

```bash
# Create IAM role
aws iam create-role \
  --role-name VulnRelayRole \
  --assume-role-policy-document file://trust-policy.json

# Attach policy
aws iam put-role-policy \
  --role-name VulnRelayRole \
  --policy-name VulnRelayPolicy \
  --policy-document file://policy.json

# Get role ARN
aws iam get-role --role-name VulnRelayRole --query 'Role.Arn' --output text
```

### 4. Cross-Account Setup

For scanning ECR in a different AWS account:

**Target Account (has ECR repositories):**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::SOURCE_ACCOUNT:role/VulnRelayRole"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

**Source Account (runs VulnRelay):**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::TARGET_ACCOUNT:role/VulnRelayRole"
    }
  ]
}
```

## 📋 Kubernetes Manifests

For custom deployments or environments without Helm:

### Namespace
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: monitoring
```

### ConfigMap
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: vulnrelay-config
  namespace: monitoring
data:
  AWS_ECR_ACCOUNT_ID: "123456789012"
  AWS_ECR_REGION: "us-east-1"
  LOG_LEVEL: "info"
  SCRAPE_INTERVAL: "5m"
```

### ServiceAccount
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: vulnrelay
  namespace: monitoring
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/VulnRelayRole
```

### Deployment
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vulnrelay
  namespace: monitoring
  labels:
    app.kubernetes.io/name: vulnrelay
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: vulnrelay
  template:
    metadata:
      labels:
        app.kubernetes.io/name: vulnrelay
    spec:
      serviceAccountName: vulnrelay
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        fsGroup: 10001
      containers:
      - name: vulnrelay
        image: ghcr.io/jfeddern/vulnrelay:latest
        ports:
        - containerPort: 9090
          name: http
        envFrom:
        - configMapRef:
            name: vulnrelay-config
        resources:
          requests:
            memory: 128Mi
            cpu: 100m
          limits:
            memory: 256Mi
            cpu: 200m
        livenessProbe:
          httpGet:
            path: /health
            port: http
          initialDelaySeconds: 30
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /health
            port: http
          initialDelaySeconds: 5
          periodSeconds: 10
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
```

### Service
```yaml
apiVersion: v1
kind: Service
metadata:
  name: vulnrelay
  namespace: monitoring
  labels:
    app.kubernetes.io/name: vulnrelay
spec:
  ports:
  - port: 9090
    targetPort: http
    protocol: TCP
    name: http
  selector:
    app.kubernetes.io/name: vulnrelay
```

### ServiceMonitor (Prometheus Operator)
```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: vulnrelay
  namespace: monitoring
  labels:
    app.kubernetes.io/name: vulnrelay
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: vulnrelay
  endpoints:
  - port: http
    interval: 30s
    path: /metrics
```

## 🐳 Docker Compose

For development and testing environments:

```yaml
version: '3.8'

services:
  vulnrelay:
    image: ghcr.io/jfeddern/vulnrelay:latest
    container_name: vulnrelay
    ports:
      - "9090:9090"
    environment:
      AWS_ECR_ACCOUNT_ID: "123456789012"
      AWS_ECR_REGION: "us-east-1"
      MODE: "local"
      IMAGE_LIST_FILE: "/data/images.json"
      LOG_LEVEL: "debug"
      SCRAPE_INTERVAL: "30s"
    volumes:
      - ./images.json:/data/images.json:ro
      - ~/.aws:/home/vulnrelay/.aws:ro
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    read_only: true
    tmpfs:
      - /tmp:noexec,nosuid,size=50m

  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    ports:
      - "9091:9090"
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
    depends_on:
      - vulnrelay
```

### Prometheus Configuration
```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'vulnrelay'
    static_configs:
      - targets: ['vulnrelay:9090']
    scrape_interval: 30s
    metrics_path: /metrics
```

## 📦 Binary Deployment

For simple environments or development:

### Download Release
```bash
# Download latest release
curl -LO https://github.com/your-org/vulnrelay/releases/latest/download/vulnrelay-linux-amd64

# Make executable
chmod +x vulnrelay-linux-amd64

# Move to PATH
sudo mv vulnrelay-linux-amd64 /usr/local/bin/vulnrelay
```

### Systemd Service
```ini
# /etc/systemd/system/vulnrelay.service
[Unit]
Description=VulnRelay Vulnerability Exporter
After=network.target

[Service]
Type=simple
User=vulnrelay
Group=vulnrelay
ExecStart=/usr/local/bin/vulnrelay
EnvironmentFile=/etc/vulnrelay/config.env
Restart=always
RestartSec=5
StartLimitInterval=60s
StartLimitBurst=3

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/vulnrelay
CapabilityBoundingSet=
AmbientCapabilities=
ProtectKernelTunables=true
ProtectControlGroups=true

[Install]
WantedBy=multi-user.target
```

### Configuration File
```bash
# /etc/vulnrelay/config.env
AWS_ECR_ACCOUNT_ID=123456789012
AWS_ECR_REGION=us-east-1
MODE=local
IMAGE_LIST_FILE=/etc/vulnrelay/images.json
LOG_LEVEL=info
PORT=9090
SCRAPE_INTERVAL=5m
```

### Service Management
```bash
# Create user
sudo useradd -r -s /bin/false vulnrelay

# Create directories
sudo mkdir -p /etc/vulnrelay /var/lib/vulnrelay
sudo chown vulnrelay:vulnrelay /var/lib/vulnrelay

# Enable and start service
sudo systemctl enable vulnrelay
sudo systemctl start vulnrelay

# Check status
sudo systemctl status vulnrelay

# View logs
sudo journalctl -u vulnrelay -f
```

## 🔧 Monitoring Integration

### Prometheus Configuration

```yaml
# Add to prometheus.yml
scrape_configs:
  - job_name: 'vulnrelay'
    kubernetes_sd_configs:
      - role: endpoints
        namespaces:
          names:
            - monitoring
    relabel_configs:
      - source_labels: [__meta_kubernetes_service_name]
        action: keep
        regex: vulnrelay
      - source_labels: [__meta_kubernetes_endpoint_port_name]
        action: keep
        regex: http
```

### Grafana Dashboard

Import the pre-built dashboard from `examples/grafana-dashboard.json` or create custom panels:

```json
{
  "dashboard": {
    "id": null,
    "title": "VulnRelay Dashboard",
    "panels": [
      {
        "title": "Critical Vulnerabilities",
        "type": "stat",
        "targets": [
          {
            "expr": "sum(ecr_image_vulnerability_count{severity=\"CRITICAL\"})"
          }
        ]
      }
    ]
  }
}
```

### Alert Rules

```yaml
# vulnrelay-alerts.yml
groups:
- name: vulnrelay
  rules:
  - alert: VulnRelayDown
    expr: up{job="vulnrelay"} == 0
    for: 2m
    labels:
      severity: critical
    annotations:
      summary: "VulnRelay is down"
      description: "VulnRelay has been down for more than 2 minutes"

  - alert: HighCriticalVulnerabilities
    expr: sum(ecr_image_vulnerability_count{severity="CRITICAL"}) > 10
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High number of critical vulnerabilities"
      description: "{{ $value }} critical vulnerabilities found across all images"

  - alert: OutdatedScans
    expr: time() - ecr_image_last_scan_timestamp > 86400
    for: 10m
    labels:
      severity: warning
    annotations:
      summary: "Image scan is outdated"
      description: "Image {{ $labels.image_uri }} hasn't been scanned in over 24 hours"
```

## 🔍 Troubleshooting

### Common Issues

**Pod CrashLoopBackOff**
```bash
# Check logs
kubectl logs deployment/vulnrelay -n monitoring

# Check events
kubectl describe pod vulnrelay-xxx -n monitoring

# Common causes:
# - Missing AWS credentials
# - Invalid IAM permissions
# - Wrong ECR region/account
```

**No Metrics Showing**
```bash
# Test metrics endpoint
kubectl port-forward svc/vulnrelay 9090:9090 -n monitoring
curl http://localhost:9090/metrics

# Check ServiceMonitor
kubectl get servicemonitor vulnrelay -n monitoring -o yaml

# Verify Prometheus discovery
# Look for vulnrelay targets in Prometheus UI
```

**AWS Permission Errors**
```bash
# Test IAM role
aws sts get-caller-identity

# Test ECR access
aws ecr describe-repositories --region us-east-1

# Check pod identity
kubectl describe serviceaccount vulnrelay -n monitoring
```

### Debug Mode

Enable debug logging and check detailed output:

```bash
# Helm upgrade with debug logging
helm upgrade vulnrelay ./helm/vulnrelay \
  --set config.logLevel=debug

# Check logs
kubectl logs deployment/vulnrelay -n monitoring -f
```

For more troubleshooting help, see the [Development Guide](../development/).