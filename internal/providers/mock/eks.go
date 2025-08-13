// ABOUTME: Mock EKS cloud provider for local testing and development.
// ABOUTME: Provides realistic Kubernetes image discovery without requiring cluster access.

package mock

import (
	"context"
	"strings"

	"github.com/jfeddern/VulnRelay/internal/types"
	"github.com/sirupsen/logrus"
)

// MockEKSProvider implements CloudProvider interface with mock data
type MockEKSProvider struct {
	logger *logrus.Logger
}

// NewMockEKSProvider creates a new mock EKS cloud provider
func NewMockEKSProvider(logger *logrus.Logger) *MockEKSProvider {
	return &MockEKSProvider{
		logger: logger,
	}
}

// Name returns the name of this cloud provider
func (m *MockEKSProvider) Name() string {
	return "mock-eks"
}

// DiscoverImages returns mock image data simulating a Kubernetes cluster
func (m *MockEKSProvider) DiscoverImages(ctx context.Context) ([]types.ImageInfo, error) {
	m.logger.Info("Discovering mock images from simulated EKS cluster")

	// Mock images representing various workloads in a typical cluster
	images := []types.ImageInfo{
		{
			URI:          "123456789012.dkr.ecr.us-east-1.amazonaws.com/web-frontend:v1.2.3",
			Namespace:    "production",
			Workload:     "web-frontend",
			WorkloadType: "Deployment",
		},
		{
			URI:          "123456789012.dkr.ecr.us-east-1.amazonaws.com/api-backend:v2.1.0",
			Namespace:    "production",
			Workload:     "api-backend",
			WorkloadType: "Deployment",
		},
		{
			URI:          "123456789012.dkr.ecr.us-east-1.amazonaws.com/postgres-db:14.9",
			Namespace:    "production",
			Workload:     "postgres-db",
			WorkloadType: "StatefulSet",
		},
		{
			URI:          "123456789012.dkr.ecr.us-east-1.amazonaws.com/worker-service:latest",
			Namespace:    "production",
			Workload:     "worker-service",
			WorkloadType: "Deployment",
		},
		{
			URI:          "123456789012.dkr.ecr.us-east-1.amazonaws.com/nginx-proxy:1.21.6",
			Namespace:    "ingress-system",
			Workload:     "nginx-proxy",
			WorkloadType: "Deployment",
		},
		{
			URI:          "123456789012.dkr.ecr.us-east-1.amazonaws.com/monitoring-agent:v3.4.1",
			Namespace:    "monitoring",
			Workload:     "monitoring-agent",
			WorkloadType: "Deployment",
		},
		{
			URI:          "123456789012.dkr.ecr.us-east-1.amazonaws.com/python-api:dev-abc123",
			Namespace:    "staging",
			Workload:     "python-api",
			WorkloadType: "Deployment",
		},
		{
			URI:          "123456789012.dkr.ecr.us-east-1.amazonaws.com/node-frontend:staging",
			Namespace:    "staging",
			Workload:     "node-frontend",
			WorkloadType: "Deployment",
		},
		{
			URI:          "123456789012.dkr.ecr.us-east-1.amazonaws.com/redis-cache:7.0.11",
			Namespace:    "production",
			Workload:     "redis-cache",
			WorkloadType: "StatefulSet",
		},
		{
			URI:          "123456789012.dkr.ecr.us-east-1.amazonaws.com/legacy-app:v1.0.0",
			Namespace:    "legacy",
			Workload:     "legacy-app",
			WorkloadType: "Deployment",
		},
	}

	m.logger.WithField("image_count", len(images)).Info("Mock image discovery completed")
	return images, nil
}

// IsRegistryImage checks if the image URI matches the expected registry format
func (m *MockEKSProvider) IsRegistryImage(imageURI string) bool {
	// Mock ECR registry pattern
	return strings.Contains(imageURI, ".dkr.ecr.") && strings.Contains(imageURI, ".amazonaws.com/")
}
