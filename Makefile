# ABOUTME: Build and development automation for VulnRelay
# ABOUTME: Provides common tasks for building, testing, and releasing

.PHONY: help build build-all test test-coverage lint security clean docker-build helm-lint validate-release

# Default target
.DEFAULT_GOAL := help

# Variables
BINARY_NAME := vulnrelay
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_DATE := $(shell date -u +'%Y-%m-%dT%H:%M:%SZ')
COMMIT := $(shell git rev-parse HEAD 2>/dev/null || echo "unknown")
LDFLAGS := -X main.version=$(VERSION) -X main.buildDate=$(BUILD_DATE) -X main.commit=$(COMMIT)

# Build flags
BUILD_FLAGS := -ldflags "$(LDFLAGS)"
STATIC_FLAGS := -a -installsuffix cgo -ldflags "-w -s $(LDFLAGS)"

help: ## Show this help message
	@echo "VulnRelay Development Commands"
	@echo "=============================="
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Build the binary for current platform
	@echo "Building $(BINARY_NAME) $(VERSION)..."
	CGO_ENABLED=0 go build $(BUILD_FLAGS) -o $(BINARY_NAME) ./cmd/vulnrelay

build-all: ## Build binaries for all platforms
	@echo "Building $(BINARY_NAME) $(VERSION) for all platforms..."
	@mkdir -p dist
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build $(STATIC_FLAGS) -o dist/$(BINARY_NAME)-linux-amd64 ./cmd/vulnrelay
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build $(STATIC_FLAGS) -o dist/$(BINARY_NAME)-darwin-amd64 ./cmd/vulnrelay
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build $(STATIC_FLAGS) -o dist/$(BINARY_NAME)-windows-amd64.exe ./cmd/vulnrelay
	@echo "Built binaries in dist/"
	@ls -la dist/

test: ## Run tests
	@echo "Running tests..."
	go test ./... -v -race

test-coverage: ## Run tests with coverage report
	@echo "Running tests with coverage..."
	go test ./... -v -race -coverprofile=coverage.out
	go tool cover -html=coverage.out -o coverage.html
	go tool cover -func=coverage.out | grep total
	@echo "Coverage report generated: coverage.html"

lint: ## Run Go linters
	@echo "Running linters..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed, running go vet instead"; \
		go vet ./...; \
	fi

security: ## Run security scanners
	@echo "Running security scanners..."
	@if command -v gosec >/dev/null 2>&1; then \
		gosec ./...; \
	else \
		echo "gosec not installed, install with: go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest"; \
	fi
	@if command -v govulncheck >/dev/null 2>&1; then \
		govulncheck ./...; \
	else \
		echo "govulncheck not installed, install with: go install golang.org/x/vuln/cmd/govulncheck@latest"; \
	fi

docker-build: ## Build Docker image
	@echo "Building Docker image..."
	docker build -t $(BINARY_NAME):$(VERSION) \
		--build-arg VERSION=$(VERSION) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		--build-arg COMMIT=$(COMMIT) \
		.

helm-lint: ## Lint Helm chart
	@echo "Linting Helm chart..."
	helm lint helm/vulnrelay

helm-test: ## Test Helm chart template
	@echo "Testing Helm chart template..."
	helm template test-release helm/vulnrelay \
		--set config.ecrAccountId=123456789012 \
		--set config.ecrRegion=us-east-1 \
		> /tmp/helm-template-test.yaml
	@echo "Template generated successfully ($(shell wc -l < /tmp/helm-template-test.yaml) lines)"

validate-release: ## Validate release readiness
	@echo "Validating release readiness..."
	./scripts/validate-release.sh all

run-mock: build ## Run with mock data for testing
	@echo "Running $(BINARY_NAME) in mock mode..."
	./$(BINARY_NAME) --mock

run-local: build ## Run in local mode (requires configuration)
	@echo "Running $(BINARY_NAME) in local mode..."
	@if [ -z "$$AWS_ECR_ACCOUNT_ID" ] || [ -z "$$AWS_ECR_REGION" ]; then \
		echo "Error: AWS_ECR_ACCOUNT_ID and AWS_ECR_REGION must be set"; \
		exit 1; \
	fi
	./$(BINARY_NAME)

clean: ## Clean build artifacts
	@echo "Cleaning build artifacts..."
	rm -f $(BINARY_NAME)
	rm -f coverage.out coverage.html
	rm -rf dist/
	docker rmi -f $(BINARY_NAME):$(VERSION) 2>/dev/null || true

install-tools: ## Install development tools
	@echo "Installing development tools..."
	go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
	go install golang.org/x/vuln/cmd/govulncheck@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

deps: ## Download dependencies
	@echo "Downloading dependencies..."
	go mod download
	go mod tidy

check-version: ## Show current version info
	@echo "Version: $(VERSION)"
	@echo "Build Date: $(BUILD_DATE)"
	@echo "Commit: $(COMMIT)"
	@echo "LDFLAGS: $(LDFLAGS)"

# Development workflow targets
dev-setup: deps install-tools ## Set up development environment
	@echo "Development environment setup complete!"

pre-commit: lint test security ## Run pre-commit checks
	@echo "Pre-commit checks passed!"

ci: test test-coverage security docker-build helm-lint ## Run CI pipeline locally
	@echo "CI pipeline completed successfully!"