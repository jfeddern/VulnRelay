// ABOUTME: Unit tests for detailed vulnerability endpoint functionality.
// ABOUTME: Tests JSON response structure, filtering, and query parameter handling.

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jfeddern/VulnRelay/internal/types"

	"github.com/sirupsen/logrus"
)

func TestVulnerabilitiesHandler(t *testing.T) {
	// Create test logger
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel) // Reduce noise in tests

	// Create mock vulnerability data
	scanTime := "2025-01-01T12:00:00Z"
	mockData := map[string]*types.ImageVulnerabilityData{
		"test-image:v1": {
			ImageVulnerability: &types.ImageVulnerability{
				ImageURI: "123456789012.dkr.ecr.us-east-1.amazonaws.com/test-image:v1",
				Vulnerabilities: map[string]int{
					"CRITICAL": 2,
					"HIGH":     3,
					"MEDIUM":   1,
				},
				ScanStatus:   "COMPLETE",
				LastScanTime: &scanTime,
				Findings: []types.VulnerabilityFinding{
					{
						Name:             "CVE-2024-12345",
						Description:      "Test critical vulnerability",
						Severity:         "CRITICAL",
						PackageName:      "test-package",
						PackageVersion:   "1.0.0",
						FixVersion:       "1.0.1",
						Status:           "ACTIVE",
						URI:              "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-12345",
						ExploitAvailable: "NO",
						FixAvailable:     "YES",
						Score:            9.8,
						Type:             "PACKAGE_VULNERABILITY",
					},
					{
						Name:             "CVE-2024-67890",
						Description:      "Test high vulnerability",
						Severity:         "HIGH",
						PackageName:      "another-package",
						PackageVersion:   "2.0.0",
						FixVersion:       "2.0.1",
						Status:           "ACTIVE",
						URI:              "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-67890",
						ExploitAvailable: "YES",
						FixAvailable:     "NO",
						Score:            7.5,
						Type:             "PACKAGE_VULNERABILITY",
					},
				},
			},
			ImageInfo: types.ImageInfo{
				URI:          "123456789012.dkr.ecr.us-east-1.amazonaws.com/test-image:v1",
				Namespace:    "default",
				Workload:     "test-image",
				WorkloadType: "Deployment",
			},
		},
	}

	// Create mock collector
	mockCollector := &MockVulnerabilityCollector{
		data:        mockData,
		lastUpdated: time.Now(),
	}

	handler := NewVulnerabilitiesHandler(mockCollector, logger)

	tests := []struct {
		name         string
		queryParams  string
		expectedCode int
		checkFunc    func(*testing.T, *VulnerabilitiesResponse)
	}{
		{
			name:         "basic request",
			queryParams:  "",
			expectedCode: http.StatusOK,
			checkFunc: func(t *testing.T, resp *VulnerabilitiesResponse) {
				if len(resp.Images) != 1 {
					t.Errorf("Expected 1 image, got %d", len(resp.Images))
				}
				if resp.Summary.TotalImages != 1 {
					t.Errorf("Expected 1 total image, got %d", resp.Summary.TotalImages)
				}
				if resp.Summary.TotalVulnerabilities != 6 {
					t.Errorf("Expected 6 total vulnerabilities, got %d", resp.Summary.TotalVulnerabilities)
				}
			},
		},
		{
			name:         "severity filter",
			queryParams:  "?severity=CRITICAL",
			expectedCode: http.StatusOK,
			checkFunc: func(t *testing.T, resp *VulnerabilitiesResponse) {
				if len(resp.Images) != 1 {
					t.Errorf("Expected 1 image, got %d", len(resp.Images))
				}
				image := resp.Images[0]
				if len(image.Findings) != 1 {
					t.Errorf("Expected 1 critical finding, got %d", len(image.Findings))
				}
				if image.Findings[0].Severity != "CRITICAL" {
					t.Errorf("Expected CRITICAL severity, got %s", image.Findings[0].Severity)
				}
			},
		},
		{
			name:         "limit parameter",
			queryParams:  "?limit=1",
			expectedCode: http.StatusOK,
			checkFunc: func(t *testing.T, resp *VulnerabilitiesResponse) {
				if len(resp.Images) != 1 {
					t.Errorf("Expected 1 image, got %d", len(resp.Images))
				}
				image := resp.Images[0]
				if len(image.Findings) != 1 {
					t.Errorf("Expected 1 finding due to limit, got %d", len(image.Findings))
				}
			},
		},
		{
			name:         "image filter - no match",
			queryParams:  "?image=nonexistent",
			expectedCode: http.StatusOK,
			checkFunc: func(t *testing.T, resp *VulnerabilitiesResponse) {
				if len(resp.Images) != 0 {
					t.Errorf("Expected 0 images, got %d", len(resp.Images))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "/vulnerabilities"+tt.queryParams, nil)
			if err != nil {
				t.Fatal(err)
			}

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if status := rr.Code; status != tt.expectedCode {
				t.Errorf("Expected status code %d, got %d", tt.expectedCode, status)
			}

			if tt.expectedCode == http.StatusOK {
				var response VulnerabilitiesResponse
				if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
					t.Fatalf("Failed to unmarshal response: %v", err)
				}

				tt.checkFunc(t, &response)
			}
		})
	}
}

// Mock implementation for testing
type MockVulnerabilityCollector struct {
	data        map[string]*types.ImageVulnerabilityData
	lastUpdated time.Time
}

func (m *MockVulnerabilityCollector) GetVulnerabilityData() (map[string]*types.ImageVulnerabilityData, time.Time) {
	return m.data, m.lastUpdated
}

func (m *MockVulnerabilityCollector) Start(ctx context.Context) {
	// Mock implementation - does nothing
}
