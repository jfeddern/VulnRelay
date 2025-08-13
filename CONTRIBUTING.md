# Contributing to VulnRelay

Thank you for your interest in contributing to VulnRelay! This document provides guidelines for contributing to the project.

## 🚀 Quick Start

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/VulnRelay.git
   cd VulnRelay
   ```
3. **Set up development environment**:
   ```bash
   go mod download
   go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
   go install golang.org/x/vuln/cmd/govulncheck@latest
   ```

4. **Test with mock data** (no AWS credentials required):
   ```bash
   go build ./cmd/vulnrelay
   ./vulnrelay -mock
   # In another terminal:
   curl http://localhost:9090/health
   curl 'http://localhost:9090/vulnerabilities?pretty=1'
   ```

## 🔄 Development Workflow

1. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** following our coding standards

3. **Test your changes**:
   ```bash
   # Run tests
   go test ./...
   
   # Run security checks
   gosec ./...
   govulncheck ./...
   
   # Check formatting
   go fmt ./...
   go vet ./...
   
   # Test with mock data (no external dependencies)
   go build ./cmd/vulnrelay
   ./vulnrelay -mock &
   curl http://localhost:9090/health
   pkill vulnrelay
   
   # Test Helm chart
   helm lint helm/vulnrelay
   ```

4. **Commit your changes**:
   ```bash
   git commit -m "feat: add support for new vulnerability source"
   ```

5. **Push and create PR**:
   ```bash
   git push origin feature/your-feature-name
   ```

## 🏗️ Project Structure

```
├── cmd/vulnrelay/              # Main application entry point
├── internal/
│   ├── engine/                 # Core vulnerability collection engine
│   ├── types/                  # Common data structures
│   ├── providers/              # Cloud providers & vulnerability sources
│   │   ├── aws/               # AWS EKS and ECR implementations
│   │   ├── local/             # Local file-based provider
│   │   └── factory.go         # Provider factory functions
│   ├── metrics/               # Prometheus metrics
│   └── server/                # HTTP API handlers
├── helm/vulnrelay/            # Helm chart
└── .github/                   # CI/CD workflows
```

## 🎯 Areas for Contribution

### High Priority
- **New Cloud Providers**: Google GKE, Azure AKS support
- **New Vulnerability Sources**: Trivy, Grype, Harbor, Anchore
- **Performance Improvements**: Caching, concurrent processing
- **Documentation**: Examples, troubleshooting guides

### Medium Priority
- **Monitoring Enhancements**: Custom metrics, dashboards
- **Security Improvements**: Additional scan types, compliance checks
- **Testing**: Integration tests, end-to-end tests

## 🔌 Adding New Providers

### Cloud Providers

To add a new cloud provider (e.g., GKE):

1. **Create provider file**: `internal/providers/gcp/gke.go`
2. **Implement CloudProvider interface**:
   ```go
   type CloudProvider interface {
       Name() string
       DiscoverImages(ctx context.Context) ([]types.ImageInfo, error)
       IsRegistryImage(imageURI string) bool
   }
   ```
3. **Update factory**: Add creation logic to `internal/providers/factory.go`
4. **Add tests**: Create comprehensive test suite
5. **Update documentation**: README and Helm chart

### Vulnerability Sources

To add a new vulnerability source (e.g., Trivy):

1. **Create source file**: `internal/providers/trivy/trivy.go`
2. **Implement VulnerabilitySource interface**:
   ```go
   type VulnerabilitySource interface {
       Name() string
       GetImageVulnerabilities(ctx context.Context, imageURI string) (*types.ImageVulnerability, error)
       ParseImageURI(imageURI string) (repository, tag string, err error)
   }
   ```
3. **Update factory**: Add creation logic to `internal/providers/factory.go`
4. **Add configuration**: Environment variables, flags
5. **Add tests and documentation**

## 🧪 Testing Guidelines

- **Unit Tests**: Test all new functions and methods
- **Integration Tests**: Test provider integrations
- **Mock Testing**: Use mock mode for development without external dependencies
- **Security Tests**: Ensure no vulnerabilities introduced
- **Performance Tests**: Verify no performance regression

### **Mock Mode for Testing**

Mock mode provides realistic test data without external API calls:

```bash
# Quick functional test
./vulnrelay -mock &
curl http://localhost:9090/vulnerabilities?severity=CRITICAL
pkill vulnrelay

# Extended testing
export MOCK_MODE=true
export LOG_LEVEL=debug
go run ./cmd/vulnrelay
```

**Mock Data Features**:
- 10 diverse container images (web, database, API, frontend)
- Realistic 2024 CVEs with proper severity levels
- Kubernetes metadata (namespaces, workloads, types)
- Different vulnerability profiles per image type

## 📚 Code Standards

- **Go Standards**: Follow effective Go guidelines
- **Security**: Never log sensitive information
- **Error Handling**: Provide meaningful error messages
- **Documentation**: Comment complex logic
- **Environment Variables**: Use `AWS_` prefix for AWS-specific configs

## 📝 Commit Messages

We follow conventional commits:

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation only changes
- `style:` Formatting, missing semicolons, etc.
- `refactor:` Code change that neither fixes a bug nor adds a feature
- `test:` Adding missing tests
- `chore:` Changes to build process or auxiliary tools

## 🚨 Security

- Report security vulnerabilities privately to the maintainers
- Run security scans before submitting PRs
- Follow principle of least privilege
- Validate all user inputs

## 📞 Getting Help

- **Documentation**: Check the README and code comments
- **Issues**: Search existing issues or create a new one
- **Discussions**: Use GitHub Discussions for questions
- **Security**: Report security issues privately

## 📋 Checklist

Before submitting a PR, ensure:

- [ ] Tests pass (`go test ./...`)
- [ ] Security scans pass (`gosec ./...`, `govulncheck ./...`)
- [ ] Code is formatted (`go fmt ./...`)
- [ ] Documentation updated
- [ ] Changelog updated (if applicable)
- [ ] Helm chart tested (`helm lint`)

Thank you for contributing to VulnRelay! 🎉