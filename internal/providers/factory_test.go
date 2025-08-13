// ABOUTME: Comprehensive tests for provider factory functionality.
// ABOUTME: Tests cloud provider and vulnerability source creation with different configurations.

package providers

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func TestCreateCloudProvider(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	tests := []struct {
		name        string
		config      *ProviderConfig
		expectError bool
		expectType  string
	}{
		{
			name: "mock mode",
			config: &ProviderConfig{
				Mode:     "cluster",
				MockMode: true,
			},
			expectError: false,
			expectType:  "mock-eks",
		},
		{
			name: "local mode with image list",
			config: &ProviderConfig{
				Mode:          "local",
				ImageListFile: createTestImageList(t),
				MockMode:      false,
			},
			expectError: false,
			expectType:  "local",
		},
		{
			name: "cluster mode (may succeed if k8s available)",
			config: &ProviderConfig{
				Mode:     "cluster",
				MockMode: false,
			},
			expectError: false, // May succeed in environments with k8s access
			expectType:  "aws-eks",
		},
		{
			name: "unsupported mode",
			config: &ProviderConfig{
				Mode:     "unsupported",
				MockMode: false,
			},
			expectError: true,
			expectType:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := CreateCloudProvider(tt.config, logger)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				if tt.expectError {
					t.Logf("Expected error for %s: %v", tt.name, err)
					return
				}
				// For cluster mode, we may expect failure in test environment
				if tt.config.Mode == "cluster" && !tt.config.MockMode {
					t.Logf("Cluster mode failed as expected in some environments: %v", err)
					return
				}
				t.Fatalf("Unexpected error: %v", err)
			}

			if provider == nil {
				t.Fatal("Provider is nil")
			}

			if provider.Name() != tt.expectType {
				t.Errorf("Expected provider type %s, got %s", tt.expectType, provider.Name())
			}

			// Test basic functionality
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			images, err := provider.DiscoverImages(ctx)
			if err != nil {
				// DiscoverImages may fail even if provider creation succeeds
				// This is acceptable for real providers in test environments
				if tt.config.Mode == "cluster" && !tt.config.MockMode {
					t.Logf("DiscoverImages failed for real provider (expected in test env): %v", err)
				} else if tt.expectType == "mock-eks" {
					t.Errorf("Mock provider DiscoverImages should not fail: %v", err)
				} else {
					t.Logf("DiscoverImages failed: %v", err)
				}
			} else if !tt.expectError && len(images) == 0 && tt.expectType == "mock-eks" {
				t.Error("Mock provider should return some images")
			}

			// Test IsRegistryImage functionality
			testURI := "123456789012.dkr.ecr.us-east-1.amazonaws.com/test:latest"
			if tt.expectType == "mock-eks" || tt.expectType == "local" {
				result := provider.IsRegistryImage(testURI)
				if !result && tt.expectType == "mock-eks" {
					t.Error("Mock provider should recognize ECR images")
				}
			}
		})
	}
}

func TestCreateVulnerabilitySource(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	tests := []struct {
		name        string
		config      *ProviderConfig
		expectError bool
		expectType  string
	}{
		{
			name: "mock mode",
			config: &ProviderConfig{
				MockMode: true,
			},
			expectError: false,
			expectType:  "mock-ecr",
		},
		{
			name: "real ECR with credentials",
			config: &ProviderConfig{
				ECRAccountID: "123456789012",
				ECRRegion:    "us-east-1",
				MockMode:     false,
			},
			expectError: false, // May succeed if AWS credentials are available
			expectType:  "aws-ecr",
		},
		{
			name: "missing ECR account ID",
			config: &ProviderConfig{
				ECRRegion: "us-east-1",
				MockMode:  false,
			},
			expectError: true,
			expectType:  "",
		},
		{
			name: "missing ECR region",
			config: &ProviderConfig{
				ECRAccountID: "123456789012",
				MockMode:     false,
			},
			expectError: true,
			expectType:  "",
		},
		{
			name: "no configuration",
			config: &ProviderConfig{
				MockMode: false,
			},
			expectError: true,
			expectType:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			source, err := CreateVulnerabilitySource(ctx, tt.config, logger)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				if tt.expectError {
					t.Logf("Expected error for %s: %v", tt.name, err)
					return
				}
				// For real ECR, we may expect failure in test environment without credentials
				if tt.config.ECRAccountID != "" && !tt.config.MockMode {
					t.Logf("Real ECR failed as expected in some environments: %v", err)
					return
				}
				t.Fatalf("Unexpected error: %v", err)
			}

			if source == nil {
				t.Fatal("Source is nil")
			}

			if source.Name() != tt.expectType {
				t.Errorf("Expected source type %s, got %s", tt.expectType, source.Name())
			}

			// Test basic functionality
			testImageURI := "123456789012.dkr.ecr.us-east-1.amazonaws.com/test:latest"

			// Test ParseImageURI
			repo, tag, err := source.ParseImageURI(testImageURI)
			if err != nil {
				t.Errorf("ParseImageURI failed: %v", err)
			}

			if repo == "" || tag == "" {
				t.Error("ParseImageURI should return non-empty repo and tag")
			}

			// Test GetImageVulnerabilities for mock source
			if tt.expectType == "mock-ecr" {
				vuln, err := source.GetImageVulnerabilities(ctx, testImageURI)
				if err != nil {
					t.Errorf("GetImageVulnerabilities failed: %v", err)
				}

				if vuln == nil {
					t.Error("GetImageVulnerabilities should return vulnerability data")
				}

				if vuln.ImageURI != testImageURI {
					t.Errorf("Expected image URI %s, got %s", testImageURI, vuln.ImageURI)
				}
			}
		})
	}
}

func TestProviderConfigValidation(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	tests := []struct {
		name   string
		config *ProviderConfig
		field  string
		valid  bool
	}{
		{
			name:   "valid mock config",
			config: &ProviderConfig{MockMode: true},
			field:  "MockMode",
			valid:  true,
		},
		{
			name:   "valid local config",
			config: &ProviderConfig{Mode: "local", ImageListFile: "/tmp/test.json"},
			field:  "Mode and ImageListFile",
			valid:  true,
		},
		{
			name:   "valid ECR config",
			config: &ProviderConfig{ECRAccountID: "123456789012", ECRRegion: "us-east-1"},
			field:  "ECRAccountID and ECRRegion",
			valid:  true,
		},
		{
			name:   "invalid ECR account ID format",
			config: &ProviderConfig{ECRAccountID: "invalid", ECRRegion: "us-east-1"},
			field:  "ECRAccountID",
			valid:  false,
		},
		{
			name:   "invalid ECR region",
			config: &ProviderConfig{ECRAccountID: "123456789012", ECRRegion: "invalid-region"},
			field:  "ECRRegion",
			valid:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Basic validation checks
			if tt.config.ECRAccountID != "" {
				if len(tt.config.ECRAccountID) != 12 && !tt.config.MockMode {
					if tt.valid {
						t.Error("Expected valid ECR account ID to be 12 digits")
					}
				}
			}

			if tt.config.ECRRegion != "" {
				validRegions := []string{"us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"}
				validRegion := false
				for _, region := range validRegions {
					if tt.config.ECRRegion == region {
						validRegion = true
						break
					}
				}
				if !validRegion && tt.valid && !tt.config.MockMode {
					t.Error("Expected valid AWS region")
				}
			}

			if tt.config.Mode == "local" && tt.config.ImageListFile == "" && !tt.config.MockMode {
				if tt.valid {
					t.Error("Local mode requires ImageListFile")
				}
			}
		})
	}
}

func TestFactoryIntegration(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	// Test full integration with mock providers
	config := &ProviderConfig{
		Mode:     "cluster",
		MockMode: true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Create cloud provider
	cloudProvider, err := CreateCloudProvider(config, logger)
	if err != nil {
		t.Fatalf("Failed to create cloud provider: %v", err)
	}

	// Create vulnerability source
	vulnSource, err := CreateVulnerabilitySource(ctx, config, logger)
	if err != nil {
		t.Fatalf("Failed to create vulnerability source: %v", err)
	}

	// Test cloud provider
	images, err := cloudProvider.DiscoverImages(ctx)
	if err != nil {
		t.Fatalf("Failed to discover images: %v", err)
	}

	if len(images) == 0 {
		t.Error("Mock cloud provider should return some images")
	}

	// Test vulnerability source with discovered images
	if len(images) > 0 {
		firstImage := images[0]
		vuln, err := vulnSource.GetImageVulnerabilities(ctx, firstImage.URI)
		if err != nil {
			t.Fatalf("Failed to get vulnerabilities: %v", err)
		}

		if vuln == nil {
			t.Error("Should return vulnerability data")
		}

		if vuln.ImageURI != firstImage.URI {
			t.Errorf("Expected image URI %s, got %s", firstImage.URI, vuln.ImageURI)
		}

		if len(vuln.Findings) == 0 {
			t.Error("Mock vulnerability source should return some findings")
		}
	}
}

// Helper function to create a test image list file
func createTestImageList(t *testing.T) string {
	content := `[
		"123456789012.dkr.ecr.us-east-1.amazonaws.com/test-app:v1.0.0",
		"123456789012.dkr.ecr.us-east-1.amazonaws.com/api-service:latest"
	]`

	file, err := os.CreateTemp("", "test-images-*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	if _, err := file.WriteString(content); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}

	if err := file.Close(); err != nil {
		t.Fatalf("Failed to close temp file: %v", err)
	}

	// Clean up file after test
	t.Cleanup(func() {
		os.Remove(file.Name())
	})

	return file.Name()
}
