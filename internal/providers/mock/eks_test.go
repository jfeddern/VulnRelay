// ABOUTME: Unit tests for mock EKS cloud provider.
// ABOUTME: Validates mock image discovery and provider interface compliance.

package mock

import (
	"context"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMockEKSProvider_Name(t *testing.T) {
	logger := logrus.New()
	provider := NewMockEKSProvider(logger)

	assert.Equal(t, "mock-eks", provider.Name())
}

func TestMockEKSProvider_DiscoverImages(t *testing.T) {
	logger := logrus.New()
	provider := NewMockEKSProvider(logger)
	ctx := context.Background()

	images, err := provider.DiscoverImages(ctx)
	require.NoError(t, err)
	assert.Len(t, images, 10, "Should return exactly 10 mock images")

	// Verify all images have required fields
	for _, image := range images {
		assert.NotEmpty(t, image.URI, "Image URI should not be empty")
		assert.NotEmpty(t, image.Namespace, "Namespace should not be empty")
		assert.NotEmpty(t, image.Workload, "Workload should not be empty")
		assert.NotEmpty(t, image.WorkloadType, "WorkloadType should not be empty")

		// Verify workload type is valid
		assert.Contains(t, []string{"Deployment", "StatefulSet"}, image.WorkloadType)

		// Verify image URI format
		assert.Contains(t, image.URI, ".dkr.ecr.", "Image URI should contain ECR registry")
		assert.Contains(t, image.URI, ".amazonaws.com/", "Image URI should contain AWS domain")
		assert.Contains(t, image.URI, ":", "Image URI should contain tag separator")
	}

	// Verify we have diverse namespaces
	namespaces := make(map[string]bool)
	for _, image := range images {
		namespaces[image.Namespace] = true
	}
	assert.GreaterOrEqual(t, len(namespaces), 3, "Should have at least 3 different namespaces")

	// Verify we have both deployment types
	hasDeployment := false
	hasStatefulSet := false
	for _, image := range images {
		if image.WorkloadType == "Deployment" {
			hasDeployment = true
		}
		if image.WorkloadType == "StatefulSet" {
			hasStatefulSet = true
		}
	}
	assert.True(t, hasDeployment, "Should have at least one Deployment")
	assert.True(t, hasStatefulSet, "Should have at least one StatefulSet")
}

func TestMockEKSProvider_IsRegistryImage(t *testing.T) {
	logger := logrus.New()
	provider := NewMockEKSProvider(logger)

	tests := []struct {
		name     string
		imageURI string
		expected bool
	}{
		{
			name:     "valid ECR image",
			imageURI: "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app:v1.0.0",
			expected: true,
		},
		{
			name:     "Docker Hub image",
			imageURI: "nginx:latest",
			expected: false,
		},
		{
			name:     "Google Container Registry",
			imageURI: "gcr.io/project/app:latest",
			expected: false,
		},
		{
			name:     "Azure Container Registry",
			imageURI: "myregistry.azurecr.io/app:latest",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := provider.IsRegistryImage(tt.imageURI)
			assert.Equal(t, tt.expected, result)
		})
	}
}
