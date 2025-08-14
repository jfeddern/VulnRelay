# Development Guide

Guide for contributing to VulnRelay, extending functionality, and development workflows.

## 🛠️ Development Setup

### Prerequisites

- **Go**: Version 1.24+
- **Docker**: For container testing
- **Kubernetes**: Access to a test cluster (optional)
- **AWS CLI**: For testing ECR integration
- **Git**: For version control

### Local Development

```bash
# Clone the repository
git clone <repository-url>
cd VulnRelay

# Install dependencies
go mod download

# Build the application
go build -o vulnrelay ./cmd/vulnrelay

# Run tests
go test ./...

# Generate test coverage
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out -o coverage.html
```

### Development Commands

```bash
# Build for current platform
make build

# Build for all platforms
make build-all

# Run tests with coverage
make test

# Run linting
make lint

# Run security scan
make security

# Clean build artifacts
make clean
```

## 🧪 Testing Strategy

VulnRelay follows comprehensive testing practices with multiple test types:

### Unit Tests

Test individual functions and components in isolation:

```bash
# Run all unit tests
go test ./...

# Run tests for specific package
go test ./internal/engine

# Run with verbose output
go test -v ./internal/providers/aws

# Run specific test
go test -run TestEKSProviderDiscoverImages ./internal/providers/aws
```

### Integration Tests

Test component interactions with real or realistic dependencies:

```bash
# Run integration tests with build tag
go test -tags=integration ./...

# Test with real AWS services (requires credentials)
AWS_PROFILE=test go test -tags=integration ./internal/providers/aws
```

### End-to-End Tests

Test complete workflows:

```bash
# Test complete vulnerability collection
go test -tags=e2e ./cmd/vulnrelay

# Test with real Kubernetes cluster
KUBECONFIG=/path/to/config go test -tags=e2e ./...
```

### Mock Testing

VulnRelay includes comprehensive mocks for isolated testing:

```go
// Example: Testing with mocks
func TestEngineWithMocks(t *testing.T) {
    mockProvider := &MockCloudProvider{}
    mockSource := &MockVulnerabilitySource{}
    
    engine := NewEngine(mockProvider, mockSource, config, logger)
    err := engine.collectVulnerabilities(ctx)
    
    assert.NoError(t, err)
    assert.True(t, mockProvider.DiscoverImagesCalled)
}
```

## 🏗️ Architecture

### Core Components

```
VulnRelay/
├── cmd/vulnrelay/           # Main application entry point
├── internal/
│   ├── engine/              # Core vulnerability collection engine
│   ├── providers/           # Cloud provider implementations
│   │   ├── aws/            # AWS EKS and ECR providers
│   │   ├── local/          # Local file-based provider
│   │   └── mock/           # Mock implementations for testing
│   ├── cache/              # In-memory caching system
│   ├── metrics/            # Prometheus metrics collection
│   └── server/             # HTTP server and API endpoints
├── types/                  # Shared data structures
├── helm/                   # Helm chart for deployment
├── docs/                   # Documentation
└── examples/               # Example configurations and responses
```

### Design Principles

1. **Pluggable Architecture**: Easy to add new cloud providers and vulnerability sources
2. **Separation of Concerns**: Clear boundaries between components
3. **Testability**: Comprehensive mocks and dependency injection
4. **Configuration**: Environment-based configuration with validation
5. **Observability**: Structured logging and metrics throughout

### Interface Design

```go
// CloudProvider interface for discovering container images
type CloudProvider interface {
    DiscoverImages(ctx context.Context) ([]ImageInfo, error)
}

// VulnerabilitySource interface for fetching vulnerability data
type VulnerabilitySource interface {
    GetVulnerabilities(ctx context.Context, imageURI string) (*ImageVulnerability, error)
}

// VulnerabilityDataProvider interface for serving data
type VulnerabilityDataProvider interface {
    GetVulnerabilityData() map[string]*ImageVulnerability
    GetMetrics() []prometheus.Collector
}
```

## 🔌 Adding New Providers

### Cloud Provider Implementation

To add a new cloud provider (e.g., GKE, AKS):

1. **Create provider package**:
```bash
mkdir -p internal/providers/gcp
```

2. **Implement CloudProvider interface**:
```go
// internal/providers/gcp/gke.go
package gcp

import (
    "context"
    "github.com/your-org/vulnrelay/types"
)

type GKEProvider struct {
    projectID string
    region    string
    logger    *slog.Logger
}

func (p *GKEProvider) DiscoverImages(ctx context.Context) ([]types.ImageInfo, error) {
    // Implementation here
    return images, nil
}
```

3. **Add to factory**:
```go
// internal/providers/factory.go
func CreateCloudProvider(config *ProviderConfig, logger *slog.Logger) (types.CloudProvider, error) {
    switch config.Type {
    case "aws":
        return aws.NewEKSProvider(config.AWSConfig, logger)
    case "gcp":
        return gcp.NewGKEProvider(config.GCPConfig, logger)
    // ...
    }
}
```

4. **Add tests**:
```go
// internal/providers/gcp/gke_test.go
func TestGKEProviderDiscoverImages(t *testing.T) {
    // Comprehensive test implementation
}
```

### Vulnerability Source Implementation

To add a new vulnerability source (e.g., Trivy, Grype):

1. **Create source package**:
```bash
mkdir -p internal/providers/trivy
```

2. **Implement VulnerabilitySource interface**:
```go
// internal/providers/trivy/trivy.go
package trivy

func (t *TrivySource) GetVulnerabilities(ctx context.Context, imageURI string) (*types.ImageVulnerability, error) {
    // Implementation here
    return vuln, nil
}
```

3. **Add configuration support**:
```go
type TrivyConfig struct {
    ServerURL string
    APIKey    string
    Timeout   time.Duration
}
```

## 📊 Metrics Development

### Adding New Metrics

1. **Define metric in metrics package**:
```go
// internal/metrics/collectors.go
var (
    newMetric = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "vulnrelay_new_metric",
            Help: "Description of new metric",
        },
        []string{"label1", "label2"},
    )
)
```

2. **Register metric**:
```go
func init() {
    prometheus.MustRegister(newMetric)
}
```

3. **Update metric in collector**:
```go
func (c *VulnerabilityCollector) updateMetrics(data map[string]*types.ImageVulnerability) {
    // Update your new metric
    newMetric.WithLabelValues("value1", "value2").Set(float64(count))
}
```

### Metric Naming Convention

Follow Prometheus naming conventions:
- Use `vulnrelay_` prefix for application metrics
- Use `ecr_` prefix for ECR-specific metrics
- Use descriptive names: `ecr_image_vulnerability_count` not `vulns`
- Include units in name when applicable: `_seconds`, `_bytes`, `_total`

## 🔧 Configuration Management

### Adding New Configuration Options

1. **Add to types**:
```go
// types/config.go
type Config struct {
    // Existing fields...
    NewOption string `json:"new_option"`
}
```

2. **Add environment variable**:
```go
// cmd/vulnrelay/main.go
config.NewOption = getEnvOrDefault("NEW_OPTION", "default_value")
```

3. **Add command line flag**:
```go
var newOptionFlag = flag.String("new-option", "", "Description of new option")

// In main()
if *newOptionFlag != "" {
    config.NewOption = *newOptionFlag
}
```

4. **Add validation**:
```go
func validateConfig(config *Config) error {
    if config.NewOption == "" {
        return fmt.Errorf("new option is required")
    }
    return nil
}
```

## 🐛 Debugging

### Debug Logging

Enable debug logging for development:

```bash
export LOG_LEVEL=debug
./vulnrelay
```

### Common Debug Scenarios

**AWS Permission Issues**:
```bash
# Test AWS credentials
aws sts get-caller-identity

# Test ECR access
aws ecr describe-repositories --region us-east-1

# Test assume role
aws sts assume-role --role-arn arn:aws:iam::123456789012:role/VulnRelayRole --role-session-name test
```

**Kubernetes Access Issues**:
```bash
# Test kubectl access
kubectl get nodes

# Test service account
kubectl describe serviceaccount vulnrelay

# Check RBAC permissions
kubectl auth can-i get deployments --as=system:serviceaccount:monitoring:vulnrelay
```

**Mock Mode Debugging**:
```bash
# Run with debug logging
LOG_LEVEL=debug ./vulnrelay --mock

# Test endpoints with verbose output
curl -v http://localhost:9090/health
```

### Performance Profiling

VulnRelay includes pprof support for performance analysis:

```bash
# Start with profiling enabled
go run -tags=debug ./cmd/vulnrelay

# In another terminal, collect profiles
go tool pprof http://localhost:9090/debug/pprof/profile?seconds=30
go tool pprof http://localhost:9090/debug/pprof/heap
```

## 🚀 Release Process

VulnRelay uses an automated GitHub Actions workflow for releases. See the [Release Workflow Guide](release-workflow.md) for comprehensive documentation.

### Quick Release Steps

1. **Validate release readiness**:
   ```bash
   make validate-release
   # or
   ./scripts/validate-release.sh all
   ```

2. **Create and push version tag**:
   ```bash
   git tag -a v1.2.0 -m "Release v1.2.0"
   git push origin v1.2.0
   ```

3. **Monitor the automated workflow** in GitHub Actions

The workflow automatically:
- Runs comprehensive tests and security scans
- Builds multi-architecture Docker images
- Packages and publishes Helm charts
- Signs all artifacts with Cosign
- Creates GitHub release with artifacts
- Updates documentation

### Manual Release (Development/Testing)

For local development and testing:

```bash
# Build for all platforms
make build-all

# Build Docker image
make docker-build

# Test Helm chart
make helm-lint helm-test
```

### Release Artifacts

Each release produces:
- Multi-architecture Docker images on GHCR
- Helm charts in OCI registry
- Cosign signatures for all artifacts
- SBOM (Software Bill of Materials)
- Security scan results

## 🤝 Contributing

### Development Workflow

1. **Fork and Clone**:
```bash
git clone https://github.com/your-username/vulnrelay.git
cd vulnrelay
```

2. **Create Feature Branch**:
```bash
git checkout -b feature/new-provider
```

3. **Make Changes**:
   - Follow coding standards
   - Add comprehensive tests
   - Update documentation

4. **Test Changes**:
```bash
make test
make lint
make security
```

5. **Commit and Push**:
```bash
git commit -m "feat: add GCP GKE provider support"
git push origin feature/new-provider
```

6. **Create Pull Request**:
   - Describe changes clearly
   - Include test results
   - Reference related issues

### Code Style

- **Go formatting**: Use `gofmt` and `goimports`
- **Naming**: Follow Go naming conventions
- **Comments**: Document exported functions and types
- **Error handling**: Always handle errors appropriately
- **Testing**: Maintain >90% test coverage

### Commit Messages

Follow conventional commit format:
- `feat:` new features
- `fix:` bug fixes
- `docs:` documentation changes
- `test:` test additions/changes
- `refactor:` code refactoring
- `chore:` maintenance tasks

## 📋 Project Structure

### Key Files

| File/Directory | Purpose |
|----------------|---------|
| `cmd/vulnrelay/main.go` | Application entry point |
| `internal/engine/` | Core vulnerability collection logic |
| `internal/providers/` | Cloud provider and vulnerability source implementations |
| `internal/server/` | HTTP server and API handlers |
| `types/` | Shared data structures and interfaces |
| `helm/vulnrelay/` | Helm chart for Kubernetes deployment |
| `Makefile` | Build and development commands |
| `go.mod` | Go module dependencies |

### Generated Files

- `coverage.out` - Test coverage data
- `vulnrelay` - Compiled binary
- `dist/` - Release binaries (created by build process)

## 🔍 Troubleshooting Development

### Common Build Issues

**Module Download Errors**:
```bash
# Clean module cache
go clean -modcache
go mod download
```

**Build Failures**:
```bash
# Verbose build output
go build -v ./cmd/vulnrelay

# Check Go version
go version
```

### Test Failures

**Mock Test Issues**:
```bash
# Regenerate mocks if interfaces change
go generate ./...
```

**Integration Test Failures**:
```bash
# Run with verbose output
go test -v -tags=integration ./...

# Check test dependencies
docker ps
kubectl get nodes
```

For more help:
- [GitHub Issues](https://github.com/your-org/vulnrelay/issues)
- [Development FAQ](./faq.md)
- [Contributing Guidelines](../../CONTRIBUTING.md)