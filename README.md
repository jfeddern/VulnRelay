# VulnRelay

A production-ready Prometheus exporter that retrieves and exposes vulnerability information for container images deployed in Kubernetes clusters. VulnRelay supports multiple cloud providers and vulnerability sources with extensible architecture.

## 📖 Documentation

| Topic | Description | Quick Links |
|-------|-------------|-------------|
| [**Getting Started**](docs/getting-started/) | Installation, configuration, and first steps | [Mock Mode](docs/getting-started/#option-1-mock-mode-recommended-for-first-try) • [Local Mode](docs/getting-started/#option-2-local-mode-with-real-data) • [Kubernetes](docs/getting-started/#option-3-kubernetes-deployment) |
| [**Configuration**](docs/configuration/) | Complete configuration reference | [Environment Variables](docs/configuration/#core-configuration) • [AWS Auth](docs/configuration/#aws-authentication) • [Examples](docs/configuration/#configuration-examples) |
| [**API Reference**](docs/api/) | Endpoints, metrics, and API documentation | [Health Check](docs/api/#health-check---health) • [Metrics](docs/api/#prometheus-metrics---metrics) • [Vulnerabilities](docs/api/#vulnerability-details---vulnerabilities) |
| [**Deployment**](docs/deployment/) | Kubernetes, Helm, and production deployment | [Helm Chart](docs/deployment/#helm-deployment-recommended) • [AWS IAM](docs/deployment/#aws-iam-setup) • [Docker Compose](docs/deployment/#docker-compose) |
| [**Development**](docs/development/) | Contributing, testing, and extending VulnRelay | [Setup](docs/development/#development-setup) • [Testing](docs/development/#testing-strategy) • [Adding Providers](docs/development/#adding-new-providers) |

## ✨ Key Features

- **Multi-Cloud Support**: Amazon EKS (GKE/AKS planned)
- **Multi-Source**: AWS ECR scanning (Trivy/Grype planned)  
- **Prometheus Integration**: Comprehensive metrics and alerts
- **Production Ready**: Security hardened, health checks, caching
- **Mock Mode**: Local testing without external dependencies
- **Extensible**: Pluggable architecture for new providers

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Kubernetes    │    │    VulnRelay     │    │ Vulnerability   │
│   Cluster(s)    │◄───┤                  ├───►│    Sources      │
│                 │    │  Cloud Providers │    │                 │
│ - EKS           │    │  Vuln Engine     │    │ - AWS ECR       │
│ - GKE (planned) │    │  HTTP Server     │    │ - Trivy (plan.) │
│ - AKS (planned) │    │  /metrics        │    │ - Grype (plan.) │
└─────────────────┘    │  /health         │    └─────────────────┘
                       └──────────────────┘
```

## 📊 Example Metrics

```prometheus
# Vulnerability counts by severity
ecr_image_vulnerability_count{severity="CRITICAL",image_uri="...",namespace="production"} 2

# Detailed CVE information  
ecr_vulnerability_info{cve_name="CVE-2024-12345",severity="CRITICAL"} 1

# Fix availability
ecr_vulnerability_fix_available{fix_status="YES"} 1
```

## 🔗 Links

- **Container Images**: `ghcr.io/jfeddern/vulnrelay:latest`
- **Helm Charts**: `oci://ghcr.io/jfeddern/vulnrelay/charts/vulnrelay`
- **Issues**: [GitHub Issues](https://github.com/your-org/vulnrelay/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-org/vulnrelay/discussions)

## 📄 License

See the [LICENSE](LICENSE) file for details.