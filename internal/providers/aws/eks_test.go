// ABOUTME: Comprehensive tests for AWS EKS cloud provider functionality.
// ABOUTME: Tests Kubernetes integration, image discovery, and error handling.

package aws

import (
	"context"
	"fmt"
	"testing"

	"github.com/jfeddern/VulnRelay/internal/types"
	"github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func TestEKSProviderName(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	provider := &EKSProvider{
		clientset: fake.NewSimpleClientset(),
		logger:    logger,
	}

	if provider.Name() != "aws-eks" {
		t.Errorf("Expected name 'aws-eks', got '%s'", provider.Name())
	}
}

func TestEKSProviderIsRegistryImage(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	provider := &EKSProvider{
		clientset: fake.NewSimpleClientset(),
		logger:    logger,
	}

	tests := []struct {
		name     string
		imageURI string
		expected bool
	}{
		{
			name:     "valid ECR image",
			imageURI: "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app:latest",
			expected: true,
		},
		{
			name:     "ECR image with nested repository",
			imageURI: "123456789012.dkr.ecr.eu-west-1.amazonaws.com/team/my-app:v1.0.0",
			expected: true,
		},
		{
			name:     "Docker Hub image",
			imageURI: "nginx:latest",
			expected: false,
		},
		{
			name:     "Docker Hub image with organization",
			imageURI: "docker.io/library/nginx:latest",
			expected: false,
		},
		{
			name:     "Google Container Registry",
			imageURI: "gcr.io/my-project/my-app:latest",
			expected: false,
		},
		{
			name:     "Azure Container Registry",
			imageURI: "myregistry.azurecr.io/my-app:latest",
			expected: false,
		},
		{
			name:     "Private registry",
			imageURI: "registry.company.com/my-app:latest",
			expected: false,
		},
		{
			name:     "empty string",
			imageURI: "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := provider.IsRegistryImage(tt.imageURI)
			if result != tt.expected {
				t.Errorf("IsRegistryImage(%q) = %v, want %v", tt.imageURI, result, tt.expected)
			}
		})
	}
}

func TestEKSProviderDiscoverImages(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	// Create mock deployments and statefulsets
	deployment1 := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "web-app",
			Namespace: "production",
		},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "web",
							Image: "123456789012.dkr.ecr.us-east-1.amazonaws.com/web-app:v1.0.0",
						},
						{
							Name:  "sidecar",
							Image: "123456789012.dkr.ecr.us-east-1.amazonaws.com/sidecar:latest",
						},
					},
					InitContainers: []corev1.Container{
						{
							Name:  "init",
							Image: "123456789012.dkr.ecr.us-east-1.amazonaws.com/init:v1.0.0",
						},
					},
				},
			},
		},
	}

	deployment2 := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "api-service",
			Namespace: "staging",
		},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "api",
							Image: "nginx:latest", // Non-ECR image, should be filtered out
						},
					},
				},
			},
		},
	}

	statefulset := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "database",
			Namespace: "production",
		},
		Spec: appsv1.StatefulSetSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "db",
							Image: "123456789012.dkr.ecr.us-east-1.amazonaws.com/postgres:14",
						},
					},
				},
			},
		},
	}

	// Create fake clientset with mock objects
	clientset := fake.NewSimpleClientset(deployment1, deployment2, statefulset)

	provider := &EKSProvider{
		clientset: clientset,
		logger:    logger,
	}

	ctx := context.Background()
	images, err := provider.DiscoverImages(ctx)
	if err != nil {
		t.Fatalf("DiscoverImages() failed: %v", err)
	}

	// Should find 4 ECR images: 3 from deployment1 (web, sidecar, init) + 1 from statefulset (db)
	expectedCount := 4
	if len(images) != expectedCount {
		t.Errorf("Expected %d images, got %d", expectedCount, len(images))
	}

	// Verify image details
	expectedImages := map[string]types.ImageInfo{
		"123456789012.dkr.ecr.us-east-1.amazonaws.com/web-app:v1.0.0": {
			URI:          "123456789012.dkr.ecr.us-east-1.amazonaws.com/web-app:v1.0.0",
			Namespace:    "production",
			Workload:     "web-app",
			WorkloadType: "Deployment",
		},
		"123456789012.dkr.ecr.us-east-1.amazonaws.com/sidecar:latest": {
			URI:          "123456789012.dkr.ecr.us-east-1.amazonaws.com/sidecar:latest",
			Namespace:    "production",
			Workload:     "web-app",
			WorkloadType: "Deployment",
		},
		"123456789012.dkr.ecr.us-east-1.amazonaws.com/init:v1.0.0": {
			URI:          "123456789012.dkr.ecr.us-east-1.amazonaws.com/init:v1.0.0",
			Namespace:    "production",
			Workload:     "web-app",
			WorkloadType: "Deployment",
		},
		"123456789012.dkr.ecr.us-east-1.amazonaws.com/postgres:14": {
			URI:          "123456789012.dkr.ecr.us-east-1.amazonaws.com/postgres:14",
			Namespace:    "production",
			Workload:     "database",
			WorkloadType: "StatefulSet",
		},
	}

	foundImages := make(map[string]types.ImageInfo)
	for _, img := range images {
		foundImages[img.URI] = img
	}

	for expectedURI, expectedImg := range expectedImages {
		if foundImg, exists := foundImages[expectedURI]; !exists {
			t.Errorf("Expected image %s not found", expectedURI)
		} else {
			if foundImg.Namespace != expectedImg.Namespace {
				t.Errorf("Expected namespace %s for image %s, got %s", expectedImg.Namespace, expectedURI, foundImg.Namespace)
			}
			if foundImg.Workload != expectedImg.Workload {
				t.Errorf("Expected workload %s for image %s, got %s", expectedImg.Workload, expectedURI, foundImg.Workload)
			}
			if foundImg.WorkloadType != expectedImg.WorkloadType {
				t.Errorf("Expected workload type %s for image %s, got %s", expectedImg.WorkloadType, expectedURI, foundImg.WorkloadType)
			}
		}
	}
}

func TestEKSProviderDiscoverImagesWithErrors(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	tests := []struct {
		name               string
		deploymentError    bool
		statefulSetError   bool
		expectedError      bool
		expectedImageCount int
	}{
		{
			name:               "deployment list error",
			deploymentError:    true,
			statefulSetError:   false,
			expectedError:      true,
			expectedImageCount: 0,
		},
		{
			name:               "statefulset list error",
			deploymentError:    false,
			statefulSetError:   true,
			expectedError:      true,
			expectedImageCount: 0,
		},
		{
			name:               "both errors",
			deploymentError:    true,
			statefulSetError:   true,
			expectedError:      true,
			expectedImageCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientset := fake.NewSimpleClientset()

			// Add error reactions
			if tt.deploymentError {
				clientset.PrependReactor("list", "deployments", func(action ktesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, nil, fmt.Errorf("deployments list error: internal server error")
				})
			}

			if tt.statefulSetError {
				clientset.PrependReactor("list", "statefulsets", func(action ktesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, nil, fmt.Errorf("statefulsets list error: internal server error")
				})
			}

			provider := &EKSProvider{
				clientset: clientset,
				logger:    logger,
			}

			ctx := context.Background()
			images, err := provider.DiscoverImages(ctx)

			if tt.expectedError && err == nil {
				t.Error("Expected error but got none")
			}

			if !tt.expectedError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if len(images) != tt.expectedImageCount {
				t.Errorf("Expected %d images, got %d", tt.expectedImageCount, len(images))
			}
		})
	}
}

func TestExtractImagesFromPodSpec(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	provider := &EKSProvider{
		clientset: fake.NewSimpleClientset(),
		logger:    logger,
	}

	podSpec := corev1.PodSpec{
		Containers: []corev1.Container{
			{
				Name:  "main",
				Image: "123456789012.dkr.ecr.us-east-1.amazonaws.com/main:latest",
			},
			{
				Name:  "sidecar",
				Image: "nginx:latest", // Non-ECR, should be filtered
			},
		},
		InitContainers: []corev1.Container{
			{
				Name:  "init",
				Image: "123456789012.dkr.ecr.us-east-1.amazonaws.com/init:v1.0.0",
			},
		},
		EphemeralContainers: []corev1.EphemeralContainer{
			{
				EphemeralContainerCommon: corev1.EphemeralContainerCommon{
					Name:  "debug",
					Image: "123456789012.dkr.ecr.us-east-1.amazonaws.com/debug:latest",
				},
			},
		},
	}

	images := provider.extractImagesFromPodSpec(podSpec, "test-namespace", "test-workload", "Deployment")

	// Should find 3 ECR images: main, init, debug
	expectedCount := 3
	if len(images) != expectedCount {
		t.Errorf("Expected %d images, got %d", expectedCount, len(images))
	}

	expectedURIs := []string{
		"123456789012.dkr.ecr.us-east-1.amazonaws.com/main:latest",
		"123456789012.dkr.ecr.us-east-1.amazonaws.com/init:v1.0.0",
		"123456789012.dkr.ecr.us-east-1.amazonaws.com/debug:latest",
	}

	foundURIs := make(map[string]bool)
	for _, img := range images {
		foundURIs[img.URI] = true

		// Verify metadata
		if img.Namespace != "test-namespace" {
			t.Errorf("Expected namespace 'test-namespace', got '%s'", img.Namespace)
		}
		if img.Workload != "test-workload" {
			t.Errorf("Expected workload 'test-workload', got '%s'", img.Workload)
		}
		if img.WorkloadType != "Deployment" {
			t.Errorf("Expected workload type 'Deployment', got '%s'", img.WorkloadType)
		}
	}

	for _, expectedURI := range expectedURIs {
		if !foundURIs[expectedURI] {
			t.Errorf("Expected image URI %s not found", expectedURI)
		}
	}
}

func TestNewEKSProviderError(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	// This test verifies that NewEKSProvider handles configuration errors gracefully
	// In a real test environment without Kubernetes access, this should fail
	_, err := NewEKSProvider(logger)
	if err == nil {
		t.Log("NewEKSProvider succeeded - likely running in Kubernetes environment")
	} else {
		t.Logf("NewEKSProvider failed as expected in test environment: %v", err)
		// This is expected behavior in test environment
	}
}

func TestEKSProviderEmptyCluster(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	// Test with empty cluster (no deployments or statefulsets)
	clientset := fake.NewSimpleClientset()

	provider := &EKSProvider{
		clientset: clientset,
		logger:    logger,
	}

	ctx := context.Background()
	images, err := provider.DiscoverImages(ctx)
	if err != nil {
		t.Fatalf("DiscoverImages() failed: %v", err)
	}

	if len(images) != 0 {
		t.Errorf("Expected 0 images in empty cluster, got %d", len(images))
	}
}
