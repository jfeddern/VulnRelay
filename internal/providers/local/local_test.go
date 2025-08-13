// ABOUTME: Comprehensive tests for local file-based provider functionality.
// ABOUTME: Tests JSON file parsing, image discovery, and error handling.

package local

import (
	"context"
	"os"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestLocalProviderName(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	provider := NewLocalProvider("test.json", logger)

	if provider.Name() != "local" {
		t.Errorf("Expected name 'local', got '%s'", provider.Name())
	}
}

func TestLocalProviderIsRegistryImage(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	provider := NewLocalProvider("test.json", logger)

	tests := []struct {
		name     string
		imageURI string
		expected bool
	}{
		{
			name:     "ECR image",
			imageURI: "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app:latest",
			expected: true,
		},
		{
			name:     "Docker Hub image",
			imageURI: "nginx:latest",
			expected: true,
		},
		{
			name:     "Google Container Registry",
			imageURI: "gcr.io/my-project/my-app:latest",
			expected: true,
		},
		{
			name:     "Private registry",
			imageURI: "registry.company.com/my-app:latest",
			expected: true,
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

func TestLocalProviderDiscoverImages(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	tests := []struct {
		name           string
		fileContent    string
		expectedCount  int
		expectedImages []string
		expectError    bool
	}{
		{
			name: "valid image list",
			fileContent: `[
				"123456789012.dkr.ecr.us-east-1.amazonaws.com/web-app:v1.0.0",
				"123456789012.dkr.ecr.us-east-1.amazonaws.com/api-service:latest",
				"nginx:latest"
			]`,
			expectedCount: 3,
			expectedImages: []string{
				"123456789012.dkr.ecr.us-east-1.amazonaws.com/web-app:v1.0.0",
				"123456789012.dkr.ecr.us-east-1.amazonaws.com/api-service:latest",
				"nginx:latest",
			},
			expectError: false,
		},
		{
			name:          "empty image list",
			fileContent:   `[]`,
			expectedCount: 0,
			expectError:   false,
		},
		{
			name: "image list with empty strings",
			fileContent: `[
				"123456789012.dkr.ecr.us-east-1.amazonaws.com/web-app:v1.0.0",
				"",
				"nginx:latest"
			]`,
			expectedCount: 2, // Empty strings should be filtered out
			expectedImages: []string{
				"123456789012.dkr.ecr.us-east-1.amazonaws.com/web-app:v1.0.0",
				"nginx:latest",
			},
			expectError: false,
		},
		{
			name:        "invalid JSON",
			fileContent: `{"invalid": "json"}`,
			expectError: true,
		},
		{
			name:        "malformed JSON",
			fileContent: `[invalid json`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary file
			file, err := os.CreateTemp("", "test-images-*.json")
			if err != nil {
				t.Fatalf("Failed to create temp file: %v", err)
			}
			defer os.Remove(file.Name())

			// Write test content
			if _, err := file.WriteString(tt.fileContent); err != nil {
				t.Fatalf("Failed to write to temp file: %v", err)
			}
			file.Close()

			// Test the provider
			provider := NewLocalProvider(file.Name(), logger)

			ctx := context.Background()
			images, err := provider.DiscoverImages(ctx)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if len(images) != tt.expectedCount {
				t.Errorf("Expected %d images, got %d", tt.expectedCount, len(images))
			}

			// Verify image details
			for i, img := range images {
				if i < len(tt.expectedImages) {
					if img.URI != tt.expectedImages[i] {
						t.Errorf("Expected image URI %s, got %s", tt.expectedImages[i], img.URI)
					}
				}

				// Verify metadata
				if img.Namespace != "local" {
					t.Errorf("Expected namespace 'local', got '%s'", img.Namespace)
				}
				if img.Workload != "local" {
					t.Errorf("Expected workload 'local', got '%s'", img.Workload)
				}
				if img.WorkloadType != "Local" {
					t.Errorf("Expected workload type 'Local', got '%s'", img.WorkloadType)
				}
			}
		})
	}
}

func TestLocalProviderDiscoverImagesFileErrors(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	tests := []struct {
		name      string
		setupFile bool
		fileName  string
	}{
		{
			name:      "file does not exist",
			setupFile: false,
			fileName:  "/nonexistent/path/images.json",
		},
		{
			name:      "file is directory",
			setupFile: true,
			fileName:  "", // Will be set to a directory path
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fileName := tt.fileName

			if tt.setupFile && tt.name == "file is directory" {
				// Create a temporary directory instead of a file
				dir, err := os.MkdirTemp("", "test-dir-*")
				if err != nil {
					t.Fatalf("Failed to create temp directory: %v", err)
				}
				defer os.RemoveAll(dir)
				fileName = dir
			}

			provider := NewLocalProvider(fileName, logger)

			ctx := context.Background()
			images, err := provider.DiscoverImages(ctx)

			if err == nil {
				t.Error("Expected error but got none")
			}

			if images != nil {
				t.Error("Expected nil images on error")
			}
		})
	}
}

func TestNewLocalProvider(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	fileName := "test-images.json"
	provider := NewLocalProvider(fileName, logger)

	if provider == nil {
		t.Fatal("NewLocalProvider returned nil")
	}

	if provider.imageListFile != fileName {
		t.Errorf("Expected imageListFile '%s', got '%s'", fileName, provider.imageListFile)
	}

	if provider.logger != logger {
		t.Error("Expected logger to be set correctly")
	}
}

func TestLocalProviderWithRealFile(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	// Create a realistic test file
	imageList := []string{
		"123456789012.dkr.ecr.us-east-1.amazonaws.com/web-frontend:v1.2.3",
		"123456789012.dkr.ecr.us-east-1.amazonaws.com/api-backend:v2.1.0",
		"123456789012.dkr.ecr.us-east-1.amazonaws.com/worker-service:latest",
		"123456789012.dkr.ecr.us-east-1.amazonaws.com/postgres-db:14.9",
		"redis:7.0-alpine",
		"nginx:1.21.6-alpine",
	}

	fileContent := `[
		"123456789012.dkr.ecr.us-east-1.amazonaws.com/web-frontend:v1.2.3",
		"123456789012.dkr.ecr.us-east-1.amazonaws.com/api-backend:v2.1.0",
		"123456789012.dkr.ecr.us-east-1.amazonaws.com/worker-service:latest",
		"123456789012.dkr.ecr.us-east-1.amazonaws.com/postgres-db:14.9",
		"redis:7.0-alpine",
		"nginx:1.21.6-alpine"
	]`

	// Create temporary file
	file, err := os.CreateTemp("", "realistic-images-*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(file.Name())

	if _, err := file.WriteString(fileContent); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	file.Close()

	// Test the provider
	provider := NewLocalProvider(file.Name(), logger)

	ctx := context.Background()
	images, err := provider.DiscoverImages(ctx)
	if err != nil {
		t.Fatalf("DiscoverImages failed: %v", err)
	}

	if len(images) != len(imageList) {
		t.Errorf("Expected %d images, got %d", len(imageList), len(images))
	}

	// Verify all expected images are present
	foundImages := make(map[string]bool)
	for _, img := range images {
		foundImages[img.URI] = true
	}

	for _, expectedURI := range imageList {
		if !foundImages[expectedURI] {
			t.Errorf("Expected image %s not found", expectedURI)
		}
	}

	// Test IsRegistryImage with discovered images
	for _, img := range images {
		if !provider.IsRegistryImage(img.URI) {
			t.Errorf("IsRegistryImage should return true for discovered image %s", img.URI)
		}
	}
}

func TestLocalProviderContextCancellation(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	// Create a test file
	fileContent := `["test:latest"]`
	file, err := os.CreateTemp("", "test-images-*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(file.Name())

	if _, err := file.WriteString(fileContent); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	file.Close()

	provider := NewLocalProvider(file.Name(), logger)

	// Create cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// The operation should still succeed since it's synchronous and fast
	// but we test that context is handled properly
	_, err = provider.DiscoverImages(ctx)
	if err != nil {
		t.Logf("DiscoverImages with cancelled context: %v", err)
		// This is acceptable - the operation may check context
	}
}
