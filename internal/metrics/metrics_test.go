// ABOUTME: Comprehensive tests for Prometheus metrics handler functionality.
// ABOUTME: Tests metrics generation, label sanitization, and HTTP response format.

package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jfeddern/VulnRelay/internal/types"

	"github.com/sirupsen/logrus"
)

func TestNewMetricsHandler(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	mockCollector := &MockVulnerabilityDataProvider{
		data:        make(map[string]*types.ImageVulnerabilityData),
		lastUpdated: time.Now(),
	}

	handler := NewMetricsHandler(mockCollector, logger)

	if handler.collector != mockCollector {
		t.Errorf("NewMetricsHandler() collector = %v, want %v", handler.collector, mockCollector)
	}

	if handler.logger != logger {
		t.Errorf("NewMetricsHandler() logger mismatch")
	}
}

func TestMetricsHandler_ServeHTTP(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	// Create mock data
	scanTime := "2025-01-15T10:30:00Z"
	mockData := map[string]*types.ImageVulnerabilityData{
		"123456789012.dkr.ecr.us-east-1.amazonaws.com/test-app:v1.0.0": {
			ImageVulnerability: &types.ImageVulnerability{
				ImageURI: "123456789012.dkr.ecr.us-east-1.amazonaws.com/test-app:v1.0.0",
				Vulnerabilities: map[string]int{
					"CRITICAL": 2,
					"HIGH":     3,
					"MEDIUM":   1,
					"LOW":      0,
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
						Description:      "Test high severity vulnerability",
						Severity:         "HIGH",
						PackageName:      "another-package",
						PackageVersion:   "2.0.0",
						FixVersion:       "2.0.1",
						Status:           "ACTIVE",
						URI:              "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-67890",
						ExploitAvailable: "YES",
						FixAvailable:     "YES",
						Score:            7.5,
						Type:             "PACKAGE_VULNERABILITY",
					},
				},
			},
			ImageInfo: types.ImageInfo{
				URI:          "123456789012.dkr.ecr.us-east-1.amazonaws.com/test-app:v1.0.0",
				Namespace:    "production",
				Workload:     "test-app",
				WorkloadType: "Deployment",
			},
		},
	}

	mockCollector := &MockVulnerabilityDataProvider{
		data:        mockData,
		lastUpdated: time.Now(),
	}

	handler := NewMetricsHandler(mockCollector, logger)

	// Create test request
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	// Call handler
	handler.ServeHTTP(w, req)

	// Check response
	if w.Code != http.StatusOK {
		t.Errorf("ServeHTTP() returned status %d, want %d", w.Code, http.StatusOK)
	}

	responseBody := w.Body.String()

	// Check that vulnerability count metrics are present
	if !strings.Contains(responseBody, `ecr_image_vulnerability_count{image_uri="123456789012.dkr.ecr.us-east-1.amazonaws.com/test-app:v1.0.0",namespace="production",repository="test-app",severity="CRITICAL",tag="v1.0.0",workload="test-app",workload_type="Deployment"} 2`) {
		t.Errorf("Expected CRITICAL vulnerability count metric not found in response")
	}

	// Check scan status metric
	if !strings.Contains(responseBody, `ecr_image_scan_status{image_uri="123456789012.dkr.ecr.us-east-1.amazonaws.com/test-app:v1.0.0",namespace="production",repository="test-app",status="COMPLETE",tag="v1.0.0",workload="test-app",workload_type="Deployment"} 1`) {
		t.Errorf("Expected scan status metric not found in response")
	}

	// Check detailed vulnerability info
	if !strings.Contains(responseBody, `ecr_vulnerability_info{cve_name="CVE-2024-12345",description="Test critical vulnerability",image_uri="123456789012.dkr.ecr.us-east-1.amazonaws.com/test-app:v1.0.0",namespace="production",repository="test-app",severity="CRITICAL"`) {
		t.Errorf("Expected vulnerability info metric not found in response")
	}

	if !strings.Contains(responseBody, `ecr_package_vulnerability{cve_name="CVE-2024-12345",fix_version="1.0.1",image_uri="123456789012.dkr.ecr.us-east-1.amazonaws.com/test-app:v1.0.0",namespace="production",package_name="test-package",package_version="1.0.0",repository="test-app",severity="CRITICAL",tag="v1.0.0",workload="test-app",workload_type="Deployment"} 9.8`) {
		t.Errorf("Expected package vulnerability metric not found in response")
	}

	if !strings.Contains(responseBody, `ecr_vulnerability_fix_available{cve_name="CVE-2024-12345",fix_status="YES",image_uri="123456789012.dkr.ecr.us-east-1.amazonaws.com/test-app:v1.0.0",namespace="production",repository="test-app",severity="CRITICAL",tag="v1.0.0",workload="test-app",workload_type="Deployment"} 1`) {
		t.Errorf("Expected fix availability metric not found in response")
	}

	if !strings.Contains(responseBody, `ecr_vulnerability_exploit_available{cve_name="CVE-2024-67890",exploit_status="YES",image_uri="123456789012.dkr.ecr.us-east-1.amazonaws.com/test-app:v1.0.0",namespace="production",repository="test-app",severity="HIGH",tag="v1.0.0",workload="test-app",workload_type="Deployment"} 1`) {
		t.Errorf("Expected exploit availability metric not found in response")
	}
}

func TestCreateMetricsHandler(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	mockCollector := &MockVulnerabilityDataProvider{
		data:        make(map[string]*types.ImageVulnerabilityData),
		lastUpdated: time.Now(),
	}

	handler := CreateMetricsHandler(mockCollector, logger)

	// Test that it's a valid HTTP handler
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("CreateMetricsHandler() returned status %d, want %d", w.Code, http.StatusOK)
	}
}

func TestSanitizeLabelValue(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "normal string",
			input:    "normal-value",
			expected: "normal-value",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "unknown",
		},
		{
			name:     "string with newlines",
			input:    "line1\nline2\rline3",
			expected: "line1 line2 line3",
		},
		{
			name:     "string with tabs",
			input:    "value\twith\ttabs",
			expected: "value with tabs",
		},
		{
			name:     "very long string",
			input:    strings.Repeat("a", 250),
			expected: strings.Repeat("a", 200) + "...",
		},
		{
			name:     "string with leading/trailing whitespace",
			input:    "  trimmed  ",
			expected: "trimmed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeLabelValue(tt.input)
			if result != tt.expected {
				t.Errorf("sanitizeLabelValue(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestParseImageURI(t *testing.T) {
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
			repo, tag, err := parseImageURI(tt.imageURI)

			if tt.expectError {
				if err == nil {
					t.Errorf("parseImageURI(%q) expected error but got none", tt.imageURI)
				}
			} else {
				if err != nil {
					t.Errorf("parseImageURI(%q) unexpected error: %v", tt.imageURI, err)
				}
				if repo != tt.expectedRepo {
					t.Errorf("parseImageURI(%q) repo = %q, want %q", tt.imageURI, repo, tt.expectedRepo)
				}
				if tag != tt.expectedTag {
					t.Errorf("parseImageURI(%q) tag = %q, want %q", tt.imageURI, tag, tt.expectedTag)
				}
			}
		})
	}
}

func TestMetricsHandler_FixAvailabilityMetrics(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	tests := []struct {
		name          string
		fixAvailable  string
		expectedValue float64
	}{
		{"fix available YES", "YES", 1.0},
		{"fix available PARTIAL", "PARTIAL", 0.5},
		{"fix available NO", "NO", 0.0},
		{"fix available unknown", "unknown", 0.0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockData := map[string]*types.ImageVulnerabilityData{
				"123456789012.dkr.ecr.us-east-1.amazonaws.com/test:latest": {
					ImageVulnerability: &types.ImageVulnerability{
						ImageURI:        "123456789012.dkr.ecr.us-east-1.amazonaws.com/test:latest",
						Vulnerabilities: map[string]int{"HIGH": 1},
						ScanStatus:      "COMPLETE",
						Findings: []types.VulnerabilityFinding{
							{
								Name:             "CVE-2024-TEST",
								Severity:         "HIGH",
								FixAvailable:     tc.fixAvailable,
								PackageName:      "test-pkg",
								PackageVersion:   "1.0.0",
								FixVersion:       "1.0.1",
								ExploitAvailable: "NO",
							},
						},
					},
					ImageInfo: types.ImageInfo{
						URI:          "123456789012.dkr.ecr.us-east-1.amazonaws.com/test:latest",
						Namespace:    "default",
						Workload:     "test",
						WorkloadType: "Deployment",
					},
				},
			}

			mockCollector := &MockVulnerabilityDataProvider{
				data:        mockData,
				lastUpdated: time.Now(),
			}

			handler := NewMetricsHandler(mockCollector, logger)
			req := httptest.NewRequest("GET", "/metrics", nil)
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("ServeHTTP() returned status %d, want %d", w.Code, http.StatusOK)
			}

			expectedMetric := `ecr_vulnerability_fix_available{cve_name="CVE-2024-TEST",fix_status="` + tc.fixAvailable + `",image_uri="123456789012.dkr.ecr.us-east-1.amazonaws.com/test:latest",namespace="default",repository="test",severity="HIGH",tag="latest",workload="test",workload_type="Deployment"} ` + formatFloat(tc.expectedValue)

			if !strings.Contains(w.Body.String(), expectedMetric) {
				t.Errorf("Expected metric not found: %s", expectedMetric)
			}
		})
	}
}

func TestMetricsHandler_ExploitAvailabilityMetrics(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	tests := []struct {
		name             string
		exploitAvailable string
		expectedValue    float64
	}{
		{"exploit available YES", "YES", 1.0},
		{"exploit available NO", "NO", 0.0},
		{"exploit available unknown", "unknown", 0.0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockData := map[string]*types.ImageVulnerabilityData{
				"123456789012.dkr.ecr.us-east-1.amazonaws.com/test:latest": {
					ImageVulnerability: &types.ImageVulnerability{
						ImageURI:        "123456789012.dkr.ecr.us-east-1.amazonaws.com/test:latest",
						Vulnerabilities: map[string]int{"HIGH": 1},
						ScanStatus:      "COMPLETE",
						Findings: []types.VulnerabilityFinding{
							{
								Name:             "CVE-2024-TEST",
								Severity:         "HIGH",
								ExploitAvailable: tc.exploitAvailable,
								PackageName:      "test-pkg",
								PackageVersion:   "1.0.0",
								FixVersion:       "1.0.1",
								FixAvailable:     "YES",
							},
						},
					},
					ImageInfo: types.ImageInfo{
						URI:          "123456789012.dkr.ecr.us-east-1.amazonaws.com/test:latest",
						Namespace:    "default",
						Workload:     "test",
						WorkloadType: "Deployment",
					},
				},
			}

			mockCollector := &MockVulnerabilityDataProvider{
				data:        mockData,
				lastUpdated: time.Now(),
			}

			handler := NewMetricsHandler(mockCollector, logger)
			req := httptest.NewRequest("GET", "/metrics", nil)
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("ServeHTTP() returned status %d, want %d", w.Code, http.StatusOK)
			}

			expectedMetric := `ecr_vulnerability_exploit_available{cve_name="CVE-2024-TEST",exploit_status="` + tc.exploitAvailable + `",image_uri="123456789012.dkr.ecr.us-east-1.amazonaws.com/test:latest",namespace="default",repository="test",severity="HIGH",tag="latest",workload="test",workload_type="Deployment"} ` + formatFloat(tc.expectedValue)

			if !strings.Contains(w.Body.String(), expectedMetric) {
				t.Errorf("Expected metric not found: %s", expectedMetric)
			}
		})
	}
}

// Mock implementation of VulnerabilityDataProvider
type MockVulnerabilityDataProvider struct {
	data        map[string]*types.ImageVulnerabilityData
	lastUpdated time.Time
}

func (m *MockVulnerabilityDataProvider) GetVulnerabilityData() (map[string]*types.ImageVulnerabilityData, time.Time) {
	return m.data, m.lastUpdated
}

// Helper function to format float values consistently
func formatFloat(f float64) string {
	if f == 1.0 {
		return "1"
	}
	if f == 0.0 {
		return "0"
	}
	if f == 0.5 {
		return "0.5"
	}
	return strings.TrimRight(strings.TrimRight(sprintf("%.1f", f), "0"), ".")
}

// Simple sprintf replacement for testing
func sprintf(format string, a ...interface{}) string {
	if format == "%.1f" && len(a) == 1 {
		if f, ok := a[0].(float64); ok {
			if f == 0.5 {
				return "0.5"
			}
		}
	}
	return "0"
}
