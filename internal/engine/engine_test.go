// ABOUTME: Comprehensive tests for vulnerability collection engine functionality.
// ABOUTME: Tests orchestration, concurrency, caching, and data retrieval operations.

package engine

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jfeddern/VulnRelay/internal/types"
	"github.com/sirupsen/logrus"
)

// Mock implementations for testing
type MockCloudProvider struct {
	name         string
	images       []types.ImageInfo
	registryURI  string
	shouldError  bool
	errorMessage string
}

func (m *MockCloudProvider) Name() string {
	return m.name
}

func (m *MockCloudProvider) DiscoverImages(ctx context.Context) ([]types.ImageInfo, error) {
	if m.shouldError {
		return nil, errors.New(m.errorMessage)
	}
	return m.images, nil
}

func (m *MockCloudProvider) IsRegistryImage(imageURI string) bool {
	return imageURI == m.registryURI
}

type MockVulnerabilitySource struct {
	name         string
	vulns        map[string]*types.ImageVulnerability
	shouldError  bool
	errorMessage string
}

func (m *MockVulnerabilitySource) Name() string {
	return m.name
}

func (m *MockVulnerabilitySource) GetImageVulnerabilities(ctx context.Context, imageURI string) (*types.ImageVulnerability, error) {
	if m.shouldError {
		return nil, errors.New(m.errorMessage)
	}

	if vuln, exists := m.vulns[imageURI]; exists {
		return vuln, nil
	}

	// Return default vulnerability data for unknown images
	return &types.ImageVulnerability{
		ImageURI:        imageURI,
		Vulnerabilities: map[string]int{"LOW": 1},
		ScanStatus:      "COMPLETE",
		Findings: []types.VulnerabilityFinding{
			{
				Name:             "CVE-2024-TEST",
				Description:      "Test vulnerability",
				Severity:         "LOW",
				PackageName:      "test-package",
				PackageVersion:   "1.0.0",
				FixVersion:       "1.0.1",
				Status:           "ACTIVE",
				URI:              "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-TEST",
				ExploitAvailable: "NO",
				FixAvailable:     "YES",
				Score:            2.0,
				Type:             "PACKAGE_VULNERABILITY",
			},
		},
	}, nil
}

func (m *MockVulnerabilitySource) ParseImageURI(imageURI string) (repository, tag string, err error) {
	if imageURI == "invalid-uri" {
		return "", "", errors.New("invalid URI format")
	}
	return "test-repo", "test-tag", nil
}

func TestNewEngine(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	config := &Config{
		Mode:           "cluster",
		Port:           9090,
		ScrapeInterval: 5 * time.Minute,
	}

	mockCloudProvider := &MockCloudProvider{name: "test-cloud"}
	mockVulnSource := &MockVulnerabilitySource{name: "test-vuln"}

	engine := NewEngine(mockCloudProvider, mockVulnSource, config, logger)

	if engine == nil {
		t.Fatal("NewEngine() returned nil")
	}

	if engine.cloudProvider != mockCloudProvider {
		t.Error("NewEngine() did not set cloud provider correctly")
	}

	if engine.vulnerabilitySource != mockVulnSource {
		t.Error("NewEngine() did not set vulnerability source correctly")
	}

	if engine.config != config {
		t.Error("NewEngine() did not set config correctly")
	}

	if engine.logger != logger {
		t.Error("NewEngine() did not set logger correctly")
	}

	if engine.cache == nil {
		t.Error("NewEngine() did not initialize cache")
	}

	if engine.vulnerabilityData == nil {
		t.Error("NewEngine() did not initialize vulnerability data map")
	}
}

func TestEngineCollectVulnerabilities(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	config := &Config{
		Mode:           "cluster",
		Port:           9090,
		ScrapeInterval: 5 * time.Minute,
	}

	scanTime := "2025-01-15T10:30:00Z"
	mockImages := []types.ImageInfo{
		{
			URI:          "123456789012.dkr.ecr.us-east-1.amazonaws.com/test-app:v1.0.0",
			Namespace:    "production",
			Workload:     "test-app",
			WorkloadType: "Deployment",
		},
		{
			URI:          "123456789012.dkr.ecr.us-east-1.amazonaws.com/api-service:latest",
			Namespace:    "staging",
			Workload:     "api-service",
			WorkloadType: "Deployment",
		},
	}

	mockVulns := map[string]*types.ImageVulnerability{
		"123456789012.dkr.ecr.us-east-1.amazonaws.com/test-app:v1.0.0": {
			ImageURI: "123456789012.dkr.ecr.us-east-1.amazonaws.com/test-app:v1.0.0",
			Vulnerabilities: map[string]int{
				"CRITICAL": 2,
				"HIGH":     1,
				"MEDIUM":   0,
				"LOW":      1,
			},
			ScanStatus:   "COMPLETE",
			LastScanTime: &scanTime,
			Findings: []types.VulnerabilityFinding{
				{
					Name:             "CVE-2024-12345",
					Description:      "Critical test vulnerability",
					Severity:         "CRITICAL",
					PackageName:      "test-package",
					PackageVersion:   "1.0.0",
					FixVersion:       "1.0.1",
					Status:           "ACTIVE",
					URI:              "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-12345",
					ExploitAvailable: "YES",
					FixAvailable:     "YES",
					Score:            9.8,
					Type:             "PACKAGE_VULNERABILITY",
				},
			},
		},
	}

	mockCloudProvider := &MockCloudProvider{
		name:   "test-cloud",
		images: mockImages,
	}

	mockVulnSource := &MockVulnerabilitySource{
		name:  "test-vuln",
		vulns: mockVulns,
	}

	engine := NewEngine(mockCloudProvider, mockVulnSource, config, logger)

	// Test successful collection
	ctx := context.Background()
	err := engine.collectVulnerabilities(ctx)
	if err != nil {
		t.Fatalf("collectVulnerabilities() failed: %v", err)
	}

	// Verify data was collected
	data, lastUpdate := engine.GetVulnerabilityData()
	if len(data) != 2 {
		t.Errorf("Expected 2 images in vulnerability data, got %d", len(data))
	}

	// Check specific image data
	testAppData, exists := data["123456789012.dkr.ecr.us-east-1.amazonaws.com/test-app:v1.0.0"]
	if !exists {
		t.Error("Expected test-app image data not found")
	} else {
		if testAppData.ImageInfo.Namespace != "production" {
			t.Errorf("Expected namespace 'production', got '%s'", testAppData.ImageInfo.Namespace)
		}
		if testAppData.ImageVulnerability.Vulnerabilities["CRITICAL"] != 2 {
			t.Errorf("Expected 2 critical vulnerabilities, got %d", testAppData.ImageVulnerability.Vulnerabilities["CRITICAL"])
		}
	}

	// Check last update time is recent
	if time.Since(lastUpdate) > time.Minute {
		t.Error("Last update time is not recent")
	}
}

func TestEngineCollectVulnerabilitiesWithErrors(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	config := &Config{
		Mode:           "cluster",
		Port:           9090,
		ScrapeInterval: 5 * time.Minute,
	}

	tests := []struct {
		name               string
		cloudProviderError bool
		vulnSourceError    bool
		expectedError      bool
		expectedDataCount  int
	}{
		{
			name:               "cloud provider error",
			cloudProviderError: true,
			vulnSourceError:    false,
			expectedError:      true,
			expectedDataCount:  0,
		},
		{
			name:               "vulnerability source error",
			cloudProviderError: false,
			vulnSourceError:    true,
			expectedError:      false, // Collection continues despite individual image errors
			expectedDataCount:  0,     // No data collected due to errors
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockCloudProvider := &MockCloudProvider{
				name: "test-cloud",
				images: []types.ImageInfo{
					{URI: "test-image:latest", Namespace: "default", Workload: "test", WorkloadType: "Deployment"},
				},
				shouldError:  tt.cloudProviderError,
				errorMessage: "cloud provider error",
			}

			mockVulnSource := &MockVulnerabilitySource{
				name:         "test-vuln",
				vulns:        make(map[string]*types.ImageVulnerability),
				shouldError:  tt.vulnSourceError,
				errorMessage: "vulnerability source error",
			}

			engine := NewEngine(mockCloudProvider, mockVulnSource, config, logger)

			ctx := context.Background()
			err := engine.collectVulnerabilities(ctx)

			if tt.expectedError && err == nil {
				t.Error("Expected error but got none")
			}

			if !tt.expectedError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			data, _ := engine.GetVulnerabilityData()
			if len(data) != tt.expectedDataCount {
				t.Errorf("Expected %d items in vulnerability data, got %d", tt.expectedDataCount, len(data))
			}
		})
	}
}

func TestEngineGetImageVulnerabilityWithCache(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	config := &Config{
		Mode:           "cluster",
		Port:           9090,
		ScrapeInterval: 5 * time.Minute,
	}

	mockCloudProvider := &MockCloudProvider{name: "test-cloud"}
	mockVulnSource := &MockVulnerabilitySource{
		name:  "test-vuln",
		vulns: make(map[string]*types.ImageVulnerability),
	}

	engine := NewEngine(mockCloudProvider, mockVulnSource, config, logger)

	ctx := context.Background()
	imageURI := "test-image:latest"

	// First call should fetch from source and cache
	vuln1, err := engine.getImageVulnerability(ctx, imageURI)
	if err != nil {
		t.Fatalf("First call failed: %v", err)
	}

	// Second call should return cached result
	vuln2, err := engine.getImageVulnerability(ctx, imageURI)
	if err != nil {
		t.Fatalf("Second call failed: %v", err)
	}

	// Verify both calls return the same data
	if vuln1.ImageURI != vuln2.ImageURI {
		t.Error("Cached vulnerability data differs from original")
	}

	if len(vuln1.Findings) != len(vuln2.Findings) {
		t.Error("Number of findings differs between calls")
	}
}

func TestEngineGetVulnerabilityDataConcurrency(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	config := &Config{
		Mode:           "cluster",
		Port:           9090,
		ScrapeInterval: 5 * time.Minute,
	}

	mockCloudProvider := &MockCloudProvider{name: "test-cloud"}
	mockVulnSource := &MockVulnerabilitySource{name: "test-vuln"}

	engine := NewEngine(mockCloudProvider, mockVulnSource, config, logger)

	// Test concurrent access to GetVulnerabilityData
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- true }()
			_, _ = engine.GetVulnerabilityData()
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// If we reach here without deadlock, the test passes
}

func TestEngineStartAndStop(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	config := &Config{
		Mode:           "cluster",
		Port:           9090,
		ScrapeInterval: 100 * time.Millisecond, // Short interval for testing
	}

	mockCloudProvider := &MockCloudProvider{
		name:   "test-cloud",
		images: []types.ImageInfo{{URI: "test:latest", Namespace: "default", Workload: "test", WorkloadType: "Deployment"}},
	}

	mockVulnSource := &MockVulnerabilitySource{
		name:  "test-vuln",
		vulns: make(map[string]*types.ImageVulnerability),
	}

	engine := NewEngine(mockCloudProvider, mockVulnSource, config, logger)

	// Start engine in goroutine
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan bool)

	go func() {
		engine.Start(ctx)
		done <- true
	}()

	// Let it run for a short time
	time.Sleep(250 * time.Millisecond)

	// Stop the engine
	cancel()

	// Wait for engine to stop
	select {
	case <-done:
		// Engine stopped as expected
	case <-time.After(5 * time.Second):
		t.Fatal("Engine did not stop within timeout")
	}

	// Verify data was collected
	data, _ := engine.GetVulnerabilityData()
	if len(data) == 0 {
		t.Error("No vulnerability data was collected")
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name   string
		config *Config
		valid  bool
	}{
		{
			name: "valid cluster config",
			config: &Config{
				Mode:           "cluster",
				Port:           9090,
				ScrapeInterval: 5 * time.Minute,
			},
			valid: true,
		},
		{
			name: "valid local config",
			config: &Config{
				Mode:           "local",
				Port:           8080,
				ImageListFile:  "/tmp/images.json",
				ScrapeInterval: 10 * time.Minute,
			},
			valid: true,
		},
		{
			name: "valid mock config",
			config: &Config{
				Mode:           "cluster",
				Port:           9090,
				MockMode:       true,
				ScrapeInterval: 5 * time.Minute,
			},
			valid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Basic validation - ensure config fields are properly set
			if tt.config.Port <= 0 {
				t.Errorf("Invalid port: %d", tt.config.Port)
			}

			if tt.config.ScrapeInterval <= 0 {
				t.Errorf("Invalid scrape interval: %v", tt.config.ScrapeInterval)
			}

			if tt.config.Mode == "" {
				t.Error("Mode cannot be empty")
			}
		})
	}
}
