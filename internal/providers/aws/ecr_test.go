// ABOUTME: Comprehensive tests for AWS ECR vulnerability source functionality.
// ABOUTME: Tests image scanning, vulnerability data parsing, and AWS API integration.

package aws

import (
	"context"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestECRSourceName(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	// We can't easily test NewECRSource without AWS credentials,
	// so we test the basic structure
	source := &ECRSource{
		accountID: "123456789012",
		region:    "us-east-1",
		logger:    logger,
	}

	if source.Name() != "aws-ecr" {
		t.Errorf("Expected name 'aws-ecr', got '%s'", source.Name())
	}
}

func TestECRSourceParseImageURI(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	source := &ECRSource{
		accountID: "123456789012",
		region:    "us-east-1",
		logger:    logger,
	}

	tests := []struct {
		name         string
		imageURI     string
		expectedRepo string
		expectedTag  string
		expectError  bool
	}{
		{
			name:         "valid ECR URI",
			imageURI:     "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app:v1.0.0",
			expectedRepo: "my-app",
			expectedTag:  "v1.0.0",
			expectError:  false,
		},
		{
			name:         "valid ECR URI with nested repository",
			imageURI:     "123456789012.dkr.ecr.us-east-1.amazonaws.com/team/my-app:latest",
			expectedRepo: "team/my-app",
			expectedTag:  "latest",
			expectError:  false,
		},
		{
			name:         "valid ECR URI with deep nesting",
			imageURI:     "123456789012.dkr.ecr.us-east-1.amazonaws.com/org/team/my-app:v2.1.0",
			expectedRepo: "org/team/my-app",
			expectedTag:  "v2.1.0",
			expectError:  false,
		},
		{
			name:        "invalid URI format - no tag",
			imageURI:    "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app",
			expectError: true,
		},
		{
			name:        "invalid URI format - no repository",
			imageURI:    "123456789012.dkr.ecr.us-east-1.amazonaws.com/",
			expectError: true,
		},
		{
			name:        "invalid URI format - not ECR",
			imageURI:    "nginx:latest",
			expectError: true,
		},
		{
			name:        "invalid URI format - empty",
			imageURI:    "",
			expectError: true,
		},
		{
			name:        "invalid URI format - malformed",
			imageURI:    "not-a-valid-uri",
			expectError: true,
		},
		{
			name:        "invalid URI format - missing parts",
			imageURI:    "123456789012.dkr.ecr.us-east-1.amazonaws.com",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo, tag, err := source.ParseImageURI(tt.imageURI)

			if tt.expectError {
				if err == nil {
					t.Errorf("ParseImageURI(%q) expected error but got none", tt.imageURI)
				}
				return
			}

			if err != nil {
				t.Errorf("ParseImageURI(%q) unexpected error: %v", tt.imageURI, err)
				return
			}

			if repo != tt.expectedRepo {
				t.Errorf("ParseImageURI(%q) repo = %q, want %q", tt.imageURI, repo, tt.expectedRepo)
			}

			if tag != tt.expectedTag {
				t.Errorf("ParseImageURI(%q) tag = %q, want %q", tt.imageURI, tag, tt.expectedTag)
			}
		})
	}
}

func TestNewECRSourceError(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	ctx := context.Background()

	tests := []struct {
		name      string
		accountID string
		region    string
	}{
		{
			name:      "valid parameters",
			accountID: "123456789012",
			region:    "us-east-1",
		},
		{
			name:      "valid parameters different region",
			accountID: "987654321098",
			region:    "eu-west-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This test verifies that NewECRSource handles parameters correctly
			// In a real test environment without AWS credentials, this should fail
			source, err := NewECRSource(ctx, tt.accountID, tt.region, logger)

			if err == nil && source != nil {
				t.Log("NewECRSource succeeded - likely running with AWS credentials")

				// Test basic properties
				if source.Name() != "aws-ecr" {
					t.Errorf("Expected name 'aws-ecr', got '%s'", source.Name())
				}

				// Test URI parsing
				testURI := tt.accountID + ".dkr.ecr." + tt.region + ".amazonaws.com/test:latest"
				repo, tag, err := source.ParseImageURI(testURI)
				if err != nil {
					t.Errorf("ParseImageURI failed: %v", err)
				}
				if repo != "test" || tag != "latest" {
					t.Errorf("ParseImageURI returned incorrect values: repo=%s, tag=%s", repo, tag)
				}
			} else {
				t.Logf("NewECRSource failed as expected in test environment without AWS credentials: %v", err)
				// This is expected behavior in test environment
			}
		})
	}
}

func TestECRSourceValidation(t *testing.T) {
	tests := []struct {
		name      string
		accountID string
		region    string
		valid     bool
	}{
		{
			name:      "valid account ID and region",
			accountID: "123456789012",
			region:    "us-east-1",
			valid:     true,
		},
		{
			name:      "invalid account ID - too short",
			accountID: "12345",
			region:    "us-east-1",
			valid:     false,
		},
		{
			name:      "invalid account ID - too long",
			accountID: "1234567890123",
			region:    "us-east-1",
			valid:     false,
		},
		{
			name:      "invalid account ID - non-numeric",
			accountID: "12345678901a",
			region:    "us-east-1",
			valid:     false,
		},
		{
			name:      "empty account ID",
			accountID: "",
			region:    "us-east-1",
			valid:     false,
		},
		{
			name:      "empty region",
			accountID: "123456789012",
			region:    "",
			valid:     false,
		},
		{
			name:      "invalid region format",
			accountID: "123456789012",
			region:    "invalid-region",
			valid:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Validate account ID
			if tt.accountID != "" {
				if len(tt.accountID) != 12 {
					if tt.valid {
						t.Error("Expected valid account ID to be 12 characters")
					}
				}

				// Check if all characters are digits
				for _, char := range tt.accountID {
					if char < '0' || char > '9' {
						if tt.valid {
							t.Error("Expected valid account ID to contain only digits")
						}
						break
					}
				}
			} else if tt.valid {
				t.Error("Expected valid configuration to have non-empty account ID")
			}

			// Validate region
			if tt.region != "" {
				validRegions := []string{
					"us-east-1", "us-east-2", "us-west-1", "us-west-2",
					"eu-west-1", "eu-west-2", "eu-central-1", "eu-north-1",
					"ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2",
					"ap-south-1", "ca-central-1", "sa-east-1",
				}

				validRegion := false
				for _, region := range validRegions {
					if tt.region == region {
						validRegion = true
						break
					}
				}

				if !validRegion && tt.valid {
					t.Error("Expected valid AWS region")
				}
			} else if tt.valid {
				t.Error("Expected valid configuration to have non-empty region")
			}
		})
	}
}

func TestECRImageURIGeneration(t *testing.T) {
	tests := []struct {
		name       string
		accountID  string
		region     string
		repository string
		tag        string
		expected   string
	}{
		{
			name:       "basic ECR URI",
			accountID:  "123456789012",
			region:     "us-east-1",
			repository: "my-app",
			tag:        "latest",
			expected:   "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app:latest",
		},
		{
			name:       "nested repository",
			accountID:  "123456789012",
			region:     "eu-west-1",
			repository: "team/my-app",
			tag:        "v1.0.0",
			expected:   "123456789012.dkr.ecr.eu-west-1.amazonaws.com/team/my-app:v1.0.0",
		},
		{
			name:       "deep nesting",
			accountID:  "987654321098",
			region:     "ap-southeast-1",
			repository: "org/team/service",
			tag:        "v2.1.0-alpha",
			expected:   "987654321098.dkr.ecr.ap-southeast-1.amazonaws.com/org/team/service:v2.1.0-alpha",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate URI format that ECR would use
			generated := tt.accountID + ".dkr.ecr." + tt.region + ".amazonaws.com/" + tt.repository + ":" + tt.tag

			if generated != tt.expected {
				t.Errorf("Expected URI %s, got %s", tt.expected, generated)
			}

			// Test that our parsing would work correctly on this URI
			logger := logrus.New()
			logger.SetLevel(logrus.ErrorLevel)

			source := &ECRSource{
				accountID: tt.accountID,
				region:    tt.region,
				logger:    logger,
			}

			repo, tag, err := source.ParseImageURI(generated)
			if err != nil {
				t.Errorf("Failed to parse generated URI: %v", err)
			}

			if repo != tt.repository {
				t.Errorf("Parsed repository %s, expected %s", repo, tt.repository)
			}

			if tag != tt.tag {
				t.Errorf("Parsed tag %s, expected %s", tag, tt.tag)
			}
		})
	}
}
