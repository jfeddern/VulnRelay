#!/bin/bash
# ABOUTME: Validation script for release readiness and workflow testing
# ABOUTME: Checks prerequisites and validates release components locally

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}ℹ️  INFO${NC}: $1"
}

log_success() {
    echo -e "${GREEN}✅ SUCCESS${NC}: $1"
}

log_warning() {
    echo -e "${YELLOW}⚠️  WARNING${NC}: $1"
}

log_error() {
    echo -e "${RED}❌ ERROR${NC}: $1"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check if we're in the right directory
check_directory() {
    log_info "Checking directory structure..."
    
    if [[ ! -f "go.mod" ]] || [[ ! -f "Dockerfile" ]] || [[ ! -d "helm/vulnrelay" ]]; then
        log_error "Not in VulnRelay root directory or missing required files"
        exit 1
    fi
    
    log_success "Directory structure looks good"
}

# Check required tools
check_tools() {
    log_info "Checking required tools..."
    
    local tools=("go" "docker" "helm" "git")
    local missing_tools=()
    
    for tool in "${tools[@]}"; do
        if command_exists "$tool"; then
            local version
            case $tool in
                "go")
                    version=$(go version | awk '{print $3}' | sed 's/go//')
                    log_success "$tool is available (version: $version)"
                    ;;
                "docker")
                    version=$(docker --version | awk '{print $3}' | sed 's/,//')
                    log_success "$tool is available (version: $version)"
                    ;;
                "helm")
                    version=$(helm version --short | awk '{print $1}' | sed 's/v//')
                    log_success "$tool is available (version: $version)"
                    ;;
                "git")
                    version=$(git --version | awk '{print $3}')
                    log_success "$tool is available (version: $version)"
                    ;;
            esac
        else
            missing_tools+=("$tool")
        fi
    done
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log_info "Please install missing tools and try again"
        exit 1
    fi
}

# Check Go version
check_go_version() {
    log_info "Checking Go version..."
    
    local go_version
    go_version=$(go version | awk '{print $3}' | sed 's/go//')
    local major minor
    major=$(echo "$go_version" | cut -d. -f1)
    minor=$(echo "$go_version" | cut -d. -f2)
    
    if [[ $major -gt 1 ]] || [[ $major -eq 1 && $minor -ge 24 ]]; then
        log_success "Go version $go_version meets requirements (>=1.24)"
    else
        log_error "Go version $go_version is too old, requires >=1.24"
        exit 1
    fi
}

# Run tests
run_tests() {
    log_info "Running test suite..."
    
    if go test ./... -v -race -coverprofile=coverage.out; then
        log_success "All tests passed"
        
        # Check coverage
        local coverage
        coverage=$(go tool cover -func=coverage.out | grep total | awk '{print substr($3, 1, length($3)-1)}')
        log_info "Test coverage: ${coverage}%"
        
        if (( $(echo "$coverage >= 70" | bc -l) )); then
            log_success "Test coverage meets release requirements (${coverage}% >= 70%)"
        else
            log_warning "Test coverage (${coverage}%) below recommended 70% for releases"
        fi
    else
        log_error "Tests failed - fix issues before release"
        exit 1
    fi
}

# Security checks
run_security_checks() {
    log_info "Running security checks..."
    
    # Check if gosec is installed
    if command_exists gosec; then
        log_info "Running gosec security scanner..."
        if gosec ./...; then
            log_success "gosec security scan passed"
        else
            log_warning "gosec found potential security issues"
        fi
    else
        log_warning "gosec not installed - install with: go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest"
    fi
    
    # Check if govulncheck is available
    if command_exists govulncheck; then
        log_info "Running vulnerability check..."
        if govulncheck ./...; then
            log_success "Vulnerability check passed"
        else
            log_warning "Vulnerability check found issues"
        fi
    else
        log_warning "govulncheck not installed - install with: go install golang.org/x/vuln/cmd/govulncheck@latest"
    fi
}

# Test Docker build
test_docker_build() {
    log_info "Testing Docker build..."
    
    local test_tag="vulnrelay:release-test"
    
    if docker build -t "$test_tag" \
        --build-arg VERSION="test" \
        --build-arg BUILD_DATE="$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
        --build-arg COMMIT="$(git rev-parse HEAD)" \
        .; then
        log_success "Docker build succeeded"
        
        # Test the image
        log_info "Testing Docker image..."
        if docker run --rm "$test_tag" --version; then
            log_success "Docker image runs successfully"
        else
            log_error "Docker image failed to run"
        fi
        
        # Clean up
        docker rmi "$test_tag" >/dev/null 2>&1 || true
    else
        log_error "Docker build failed"
        exit 1
    fi
}

# Test Helm chart
test_helm_chart() {
    log_info "Testing Helm chart..."
    
    # Lint the chart
    if helm lint helm/vulnrelay; then
        log_success "Helm chart linting passed"
    else
        log_error "Helm chart linting failed"
        exit 1
    fi
    
    # Test template rendering
    log_info "Testing Helm template rendering..."
    if helm template test-release helm/vulnrelay \
        --set config.ecrAccountId=123456789012 \
        --set config.ecrRegion=us-east-1 \
        > /tmp/helm-test.yaml; then
        log_success "Helm template rendering succeeded"
        log_info "Generated $(wc -l < /tmp/helm-test.yaml) lines of Kubernetes manifests"
    else
        log_error "Helm template rendering failed"
        exit 1
    fi
}

# Check Git status
check_git_status() {
    log_info "Checking Git status..."
    
    # Check if we're in a git repo
    if ! git rev-parse --git-dir >/dev/null 2>&1; then
        log_error "Not in a Git repository"
        exit 1
    fi
    
    # Check for uncommitted changes
    if [[ -n $(git status --porcelain) ]]; then
        log_warning "Uncommitted changes detected:"
        git status --short
        log_info "Consider committing changes before release"
    else
        log_success "Working directory is clean"
    fi
    
    # Check current branch
    local branch
    branch=$(git branch --show-current)
    log_info "Current branch: $branch"
    
    if [[ "$branch" != "main" ]] && [[ "$branch" != "master" ]]; then
        log_warning "Not on main/master branch - releases typically come from main branch"
    fi
}

# Validate version format
validate_version() {
    local version="$1"
    
    if [[ $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9]+)?$ ]]; then
        return 0
    else
        return 1
    fi
}

# Simulate release process
simulate_release() {
    local version="${1:-}"
    
    if [[ -z "$version" ]]; then
        log_info "Enter version to simulate (e.g., v1.0.0):"
        read -r version
    fi
    
    log_info "Simulating release for version: $version"
    
    if validate_version "$version"; then
        log_success "Version format is valid"
    else
        log_error "Invalid version format. Expected: v1.2.3 or v1.2.3-alpha1"
        exit 1
    fi
    
    # Check if tag already exists
    if git tag -l | grep -q "^$version$"; then
        log_error "Tag $version already exists"
        exit 1
    fi
    
    log_info "Version validation passed"
    
    # Simulate what would happen
    log_info "Release simulation would:"
    echo "  1. Create Git tag: $version"
    echo "  2. Build Docker image: ghcr.io/jfeddern/vulnrelay:$version"
    echo "  3. Build Helm chart: vulnrelay-${version#v}.tgz"
    echo "  4. Run security scans and sign artifacts"
    echo "  5. Create GitHub release with artifacts"
    
    log_info "To actually create this release, run:"
    echo "  git tag -a $version -m 'Release $version'"
    echo "  git push origin $version"
}

# Main function
main() {
    log_info "VulnRelay Release Validation Script"
    echo "======================================"
    
    case "${1:-all}" in
        "tools")
            check_tools
            ;;
        "tests")
            run_tests
            ;;
        "security")
            run_security_checks
            ;;
        "docker")
            test_docker_build
            ;;
        "helm")
            test_helm_chart
            ;;
        "git")
            check_git_status
            ;;
        "simulate")
            simulate_release "${2:-}"
            ;;
        "all")
            check_directory
            check_tools
            check_go_version
            run_tests
            run_security_checks
            test_docker_build
            test_helm_chart
            check_git_status
            log_success "All validation checks completed!"
            log_info "Ready for release! Run '$0 simulate v1.0.0' to simulate a release."
            ;;
        *)
            echo "Usage: $0 [all|tools|tests|security|docker|helm|git|simulate [version]]"
            echo ""
            echo "Commands:"
            echo "  all       - Run all validation checks (default)"
            echo "  tools     - Check required tools are installed"
            echo "  tests     - Run test suite and coverage check"
            echo "  security  - Run security scanners"
            echo "  docker    - Test Docker build"
            echo "  helm      - Test Helm chart"
            echo "  git       - Check Git status"
            echo "  simulate  - Simulate release process for given version"
            echo ""
            echo "Examples:"
            echo "  $0                    # Run all checks"
            echo "  $0 simulate v1.0.0    # Simulate release v1.0.0"
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"