# VulnRelay Documentation

Welcome to the VulnRelay documentation. This guide will help you understand, deploy, and contribute to VulnRelay.

## 📖 Documentation Structure

### **For New Users**
1. 🚀 **[Getting Started](getting-started/)** - Start here for installation and first steps
   - Mock mode for testing without dependencies
   - Local mode with real ECR data
   - Kubernetes deployment

### **For Operators**  
2. 🔧 **[Configuration](configuration/)** - Complete configuration reference
   - Environment variables and command flags
   - AWS authentication methods
   - Cross-account setup

3. 🚀 **[Deployment](deployment/)** - Production deployment guide
   - Helm charts (recommended)
   - Kubernetes manifests
   - Docker Compose
   - AWS IAM setup

### **For Integrators**
4. 📡 **[API Reference](api/)** - Complete API documentation
   - Health check endpoint
   - Prometheus metrics format
   - Vulnerability details API
   - Query examples and filtering

### **For Contributors**
5. 🛠️ **[Development](development/)** - Contributing and extending VulnRelay
   - Development setup
   - Testing strategy
   - Adding new providers
   - Release process

## 🎯 Quick Navigation

### **I want to...**

| Goal | Go to | Specific Section |
|------|-------|------------------|
| **Try VulnRelay quickly** | [Getting Started](getting-started/) | [Mock Mode](getting-started/#option-1-mock-mode-recommended-for-first-try) |
| **Deploy to production** | [Deployment](deployment/) | [Helm Chart](deployment/#helm-deployment-recommended) |
| **Configure for my environment** | [Configuration](configuration/) | [Configuration Examples](configuration/#configuration-examples) |
| **Integrate with monitoring** | [API Reference](api/) | [Prometheus Metrics](api/#prometheus-metrics---metrics) |
| **Query vulnerability data** | [API Reference](api/) | [Vulnerability Details](api/#vulnerability-details---vulnerabilities) |
| **Set up AWS permissions** | [Deployment](deployment/) | [AWS IAM Setup](deployment/#aws-iam-setup) |
| **Add a new cloud provider** | [Development](development/) | [Adding New Providers](development/#adding-new-providers) |
| **Run tests** | [Development](development/) | [Testing Strategy](development/#testing-strategy) |
| **Troubleshoot issues** | [Getting Started](getting-started/) | [Troubleshooting](getting-started/#troubleshooting) |

## 🔗 External Resources

- **GitHub Repository**: [VulnRelay Source Code](https://github.com/your-org/vulnrelay)
- **Container Registry**: `ghcr.io/jfeddern/vulnrelay:latest`
- **Helm Charts**: `oci://ghcr.io/jfeddern/vulnrelay/charts/vulnrelay`
- **Issues & Support**: [GitHub Issues](https://github.com/your-org/vulnrelay/issues)

## 📝 Document Conventions

- **🚀 Quick Start** sections provide immediate action steps
- **📋 Prerequisites** list requirements before starting
- **✨ Key Features** highlight important capabilities  
- **🔧 Configuration** sections show all available options
- **📊 Examples** provide copy-paste ready configurations
- **🔍 Troubleshooting** helps resolve common issues

## 🤝 Contributing to Documentation

Documentation improvements are welcome! Please:
1. Follow the existing structure and formatting
2. Include practical examples
3. Test all code samples
4. Update navigation links when adding new sections

For more information, see [Development Guide](development/).