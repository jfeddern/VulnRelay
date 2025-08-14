# Release Workflow Guide

Comprehensive guide for VulnRelay's automated release process using GitHub Actions.

## 🎯 Overview

The VulnRelay release workflow is designed to provide secure, automated releases with comprehensive testing, security scanning, and artifact signing. The workflow is triggered only by version tags and follows security best practices.

## 🚀 Triggering a Release

### 1. Create and Push a Version Tag

The release workflow is triggered **only** when you push a version tag to the repository:

```bash
# Create a new version tag
git tag -a v1.0.0 -m "Release v1.0.0"

# Push the tag to GitHub
git push origin v1.0.0
```

### 2. Version Tag Format

Tags must follow semantic versioning format:

**Valid formats:**
- `v1.0.0` - Standard release
- `v1.2.3` - Standard release
- `v1.0.0-alpha1` - Prerelease
- `v2.0.0-beta2` - Prerelease
- `v1.5.0-rc1` - Release candidate

**Invalid formats:**
- `1.0.0` - Missing `v` prefix
- `v1.0` - Missing patch version
- `release-1.0.0` - Wrong prefix

## 🔄 Workflow Steps

The release workflow consists of 8 main jobs that run in sequence:

### 1. **Validate** (`validate`)
- Extracts version from tag
- Validates version format
- Determines if it's a prerelease
- **Duration**: ~30 seconds

### 2. **Test** (`test`)
- Runs comprehensive test suite
- Checks test coverage (minimum 70% required)
- Runs Go security scanner (gosec)
- Runs vulnerability check (govulncheck)
- **Duration**: ~2-3 minutes

### 3. **Build Docker** (`build-docker`)
- Builds multi-architecture Docker images (amd64, arm64)
- Pushes to GitHub Container Registry (GHCR)
- Runs Trivy security scan on the image
- Generates Software Bill of Materials (SBOM)
- **Duration**: ~5-8 minutes

### 4. **Build Helm** (`build-helm`)
- Updates Helm chart version and app version
- Lints the Helm chart
- Tests chart template generation
- Packages and pushes chart to OCI registry
- **Duration**: ~2-3 minutes

### 5. **Sign Artifacts** (`sign-artifacts`)
- Signs Docker image with Cosign
- Signs Helm chart with Cosign
- Uses keyless signing with GitHub OIDC
- **Duration**: ~1 minute

### 6. **Create Release** (`create-release`)
- Generates changelog from Git commits
- Creates GitHub release with artifacts
- Attaches Helm chart, SBOM, and coverage report
- **Duration**: ~1 minute

### 7. **Update Docs** (`update-docs`)
- Updates documentation with new version references
- Only runs for stable releases (not prereleases)
- Commits changes back to the repository
- **Duration**: ~1 minute

### 8. **Notify** (`notify`)
- Reports final status
- Provides links to released artifacts
- **Duration**: ~30 seconds

## 📦 Release Artifacts

Each successful release produces several artifacts:

### Docker Images
```bash
# Multi-architecture images on GHCR
ghcr.io/jfeddern/vulnrelay:v1.0.0
ghcr.io/jfeddern/vulnrelay:1.0.0
ghcr.io/jfeddern/vulnrelay:1.0
ghcr.io/jfeddern/vulnrelay:1
ghcr.io/jfeddern/vulnrelay:latest  # Only for stable releases
```

### Helm Charts
```bash
# OCI registry
oci://ghcr.io/jfeddern/vulnrelay/charts/vulnrelay

# Installation
helm install vulnrelay oci://ghcr.io/jfeddern/vulnrelay/charts/vulnrelay --version 1.0.0
```

### Security Artifacts
- **Cosign signatures** for all images and charts
- **SBOM (Software Bill of Materials)** in SPDX format
- **Trivy security scan results** uploaded to GitHub Security tab
- **Test coverage reports** attached to release

## 🔒 Security Features

### Image Security
- **Multi-stage builds** with minimal distroless base image
- **Non-root user** (uid/gid 65532)
- **No package manager** in final image
- **Trivy vulnerability scanning** with results in GitHub Security tab
- **SBOM generation** for transparency

### Supply Chain Security
- **Cosign signing** using keyless OIDC with GitHub
- **Provenance attestation** linking artifacts to source code
- **Immutable tags** for reproducible deployments
- **Security scanning** at multiple stages

### Build Security
- **Minimal permissions** for each job
- **Dependency caching** with integrity checks
- **Multi-architecture builds** (amd64, arm64)
- **Static analysis** with gosec and govulncheck

## 🎛️ Configuration

### Required Secrets

The workflow uses the built-in `GITHUB_TOKEN` with the following permissions:

```yaml
permissions:
  contents: write          # Create releases and update docs
  packages: write          # Push to GHCR
  security-events: write   # Upload security scan results
  id-token: write         # Cosign keyless signing
```

### Repository Settings

Ensure these settings are configured:

1. **Actions permissions**: Allow GitHub Actions to create and approve pull requests
2. **Package permissions**: Allow packages to be published
3. **Security features**: Enable dependency graph and security advisories

## 📋 Pre-Release Checklist

Before creating a release tag:

- [ ] All tests pass: `go test ./...`
- [ ] Code coverage meets requirements: `go test ./... -coverprofile=coverage.out`
- [ ] Security scan passes: `gosec ./...`
- [ ] Vulnerability check passes: `govulncheck ./...`
- [ ] Documentation is up to date
- [ ] Changelog entries are ready
- [ ] Version bump is appropriate (major/minor/patch)

## 🚨 Troubleshooting

### Common Issues

**❌ "Invalid version format" Error**
```bash
# Problem: Tag doesn't follow semantic versioning
git tag v1.0.0-fix-123  # ❌ Invalid
git tag v1.0.1          # ✅ Valid

# Solution: Delete bad tag and create valid one
git tag -d v1.0.0-fix-123
git push origin :refs/tags/v1.0.0-fix-123
git tag v1.0.1
git push origin v1.0.1
```

**❌ "Test coverage below minimum" Error**
```bash
# Check current coverage
go test ./... -coverprofile=coverage.out
go tool cover -func=coverage.out | grep total

# Add tests to meet 70% minimum requirement
```

**❌ "Docker build failed" Error**
```bash
# Test Docker build locally
docker build -t vulnrelay:test .
docker run --rm vulnrelay:test --version
```

**❌ "Helm lint failed" Error**
```bash
# Test Helm chart locally
helm lint helm/vulnrelay
helm template test helm/vulnrelay --set config.ecrAccountId=123456789012
```

### Monitoring Release Progress

1. **GitHub Actions Tab**: Monitor workflow progress
2. **GitHub Security Tab**: View security scan results
3. **GitHub Packages**: Verify artifacts are published
4. **GitHub Releases**: Check release notes and attachments

### Failed Release Recovery

If a release fails:

1. **Fix the issue** in the code
2. **Delete the failed tag**:
   ```bash
   git tag -d v1.0.0
   git push origin :refs/tags/v1.0.0
   ```
3. **Create a new tag** with incremented version:
   ```bash
   git tag v1.0.1
   git push origin v1.0.1
   ```

## 🔄 Release Cadence

### Recommended Schedule
- **Major releases**: Every 6-12 months
- **Minor releases**: Every 1-2 months  
- **Patch releases**: As needed for bug fixes
- **Prereleases**: For testing new features

### Prerelease Strategy
```bash
# Alpha releases for early testing
git tag v1.1.0-alpha1

# Beta releases for stabilization
git tag v1.1.0-beta1

# Release candidates for final testing
git tag v1.1.0-rc1

# Stable release
git tag v1.1.0
```

## 📊 Metrics and Monitoring

The workflow provides several metrics:

- **Build time**: Total workflow duration
- **Test coverage**: Percentage and trend over time
- **Security scan results**: Vulnerability count and severity
- **Artifact size**: Docker image and chart sizes
- **Download statistics**: Package and release download counts

## 🤝 Contributing to Release Process

To improve the release workflow:

1. **Workflow changes**: Edit `.github/workflows/release.yml`
2. **Testing**: Use feature branches to test workflow changes
3. **Documentation**: Update this guide for any process changes
4. **Security**: Follow principle of least privilege for permissions

## 📝 Release Notes Template

The workflow auto-generates release notes, but you can customize them by creating a release template:

```markdown
## What's Changed
- Feature: New cloud provider support
- Fix: Resolved memory leak in cache
- Security: Updated dependencies

## Breaking Changes
- Configuration format has changed (see migration guide)

## Migration Guide
- Update your configuration files as follows: ...

## Container Images
- `ghcr.io/jfeddern/vulnrelay:v1.1.0`

## Helm Chart
```bash
helm install vulnrelay oci://ghcr.io/jfeddern/vulnrelay/charts/vulnrelay --version 1.1.0
```

## Security
All artifacts are signed with Cosign and include SBOMs.
```

For more information about the release process, see the [Development Guide](README.md).