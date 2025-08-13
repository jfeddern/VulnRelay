// ABOUTME: Unit tests for mock ECR vulnerability source.
// ABOUTME: Validates mock data generation and provider interface compliance.

package mock

import (
	"context"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMockECRSource_Name(t *testing.T) {
	logger := logrus.New()
	source := NewMockECRSource(logger)

	assert.Equal(t, "mock-ecr", source.Name())
}

func TestMockECRSource_ParseImageURI(t *testing.T) {
	logger := logrus.New()
	source := NewMockECRSource(logger)

	tests := []struct {
		name        string
		imageURI    string
		expectRepo  string
		expectTag   string
		expectError bool
	}{
		{
			name:        "valid ECR URI",
			imageURI:    "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app:v1.0.0",
			expectRepo:  "my-app",
			expectTag:   "v1.0.0",
			expectError: false,
		},
		{
			name:        "valid ECR URI with nested repo",
			imageURI:    "123456789012.dkr.ecr.us-east-1.amazonaws.com/team/my-app:latest",
			expectRepo:  "team/my-app",
			expectTag:   "latest",
			expectError: false,
		},
		{
			name:        "invalid URI format",
			imageURI:    "invalid-uri",
			expectError: true,
		},
		{
			name:        "missing tag",
			imageURI:    "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo, tag, err := source.ParseImageURI(tt.imageURI)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectRepo, repo)
				assert.Equal(t, tt.expectTag, tag)
			}
		})
	}
}

func TestMockECRSource_GetImageVulnerabilities(t *testing.T) {
	logger := logrus.New()
	source := NewMockECRSource(logger)
	ctx := context.Background()

	tests := []struct {
		name                string
		imageURI            string
		expectedMinFindings int
		expectedCritical    bool
	}{
		{
			name:                "nginx web server",
			imageURI:            "123456789012.dkr.ecr.us-east-1.amazonaws.com/nginx-proxy:1.21.6",
			expectedMinFindings: 2,
			expectedCritical:    true,
		},
		{
			name:                "postgres database",
			imageURI:            "123456789012.dkr.ecr.us-east-1.amazonaws.com/postgres-db:14.9",
			expectedMinFindings: 2,
			expectedCritical:    true,
		},
		{
			name:                "python API",
			imageURI:            "123456789012.dkr.ecr.us-east-1.amazonaws.com/python-api:dev-abc123",
			expectedMinFindings: 2,
			expectedCritical:    false,
		},
		{
			name:                "node frontend",
			imageURI:            "123456789012.dkr.ecr.us-east-1.amazonaws.com/node-frontend:staging",
			expectedMinFindings: 2,
			expectedCritical:    false,
		},
		{
			name:                "generic app",
			imageURI:            "123456789012.dkr.ecr.us-east-1.amazonaws.com/worker-service:latest",
			expectedMinFindings: 2,
			expectedCritical:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vuln, err := source.GetImageVulnerabilities(ctx, tt.imageURI)
			require.NoError(t, err)
			assert.NotNil(t, vuln)

			// Verify basic structure
			assert.Equal(t, tt.imageURI, vuln.ImageURI)
			assert.Equal(t, "COMPLETE", vuln.ScanStatus)
			assert.NotNil(t, vuln.LastScanTime)
			assert.NotEmpty(t, vuln.Vulnerabilities)
			assert.GreaterOrEqual(t, len(vuln.Findings), tt.expectedMinFindings)

			// Check for critical vulnerabilities
			hasCritical := false
			for _, finding := range vuln.Findings {
				if finding.Severity == "CRITICAL" {
					hasCritical = true
					break
				}
			}
			assert.Equal(t, tt.expectedCritical, hasCritical)

			// Verify all findings have required fields
			for _, finding := range vuln.Findings {
				assert.NotEmpty(t, finding.Name, "CVE name should not be empty")
				assert.NotEmpty(t, finding.Description, "Description should not be empty")
				assert.NotEmpty(t, finding.Severity, "Severity should not be empty")
				assert.NotEmpty(t, finding.PackageName, "Package name should not be empty")
				assert.NotEmpty(t, finding.PackageVersion, "Package version should not be empty")
				assert.NotEmpty(t, finding.FixAvailable, "Fix availability should not be empty")
				assert.NotEmpty(t, finding.ExploitAvailable, "Exploit availability should not be empty")
				assert.Greater(t, finding.Score, 0.0, "CVSS score should be positive")
			}

			// Verify vulnerability counts match findings
			criticalCount := 0
			highCount := 0
			mediumCount := 0
			lowCount := 0

			for _, finding := range vuln.Findings {
				switch finding.Severity {
				case "CRITICAL":
					criticalCount++
				case "HIGH":
					highCount++
				case "MEDIUM":
					mediumCount++
				case "LOW":
					lowCount++
				}
			}

			assert.Equal(t, criticalCount, vuln.Vulnerabilities["CRITICAL"])
			assert.Equal(t, highCount, vuln.Vulnerabilities["HIGH"])
			assert.Equal(t, mediumCount, vuln.Vulnerabilities["MEDIUM"])
			assert.Equal(t, lowCount, vuln.Vulnerabilities["LOW"])
		})
	}
}
