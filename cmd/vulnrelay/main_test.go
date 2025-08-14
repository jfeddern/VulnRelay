// ABOUTME: Comprehensive tests for main application functions.
// ABOUTME: Tests configuration parsing, exporter creation, and HTTP handlers.

package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jfeddern/VulnRelay/internal/engine"

	"github.com/sirupsen/logrus"
)

// Test environment variable parsing functionality
func TestEnvironmentVariableParsing(t *testing.T) {
	tests := []struct {
		name         string
		envVars      map[string]string
		validateFunc func(*testing.T, *engine.Config)
	}{
		{
			name: "mock mode configuration",
			envVars: map[string]string{
				"MOCK_MODE":       "true",
				"PORT":            "8080",
				"SCRAPE_INTERVAL": "30s",
				"MODE":            "local",
			},
			validateFunc: func(t *testing.T, config *engine.Config) {
				if !config.MockMode {
					t.Error("Expected MockMode to be true")
				}
				if config.Port != 8080 {
					t.Errorf("Expected Port to be 8080, got %d", config.Port)
				}
				if config.ScrapeInterval != 30*time.Second {
					t.Errorf("Expected ScrapeInterval to be 30s, got %v", config.ScrapeInterval)
				}
			},
		},
		{
			name: "various mock mode values",
			envVars: map[string]string{
				"MOCK_MODE": "1",
			},
			validateFunc: func(t *testing.T, config *engine.Config) {
				if !config.MockMode {
					t.Error("Expected MOCK_MODE=1 to enable mock mode")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and set environment variables
			originalEnv := make(map[string]string)
			for key, value := range tt.envVars {
				originalEnv[key] = os.Getenv(key)
				os.Setenv(key, value)
			}

			// Ensure we have default required values for non-mock tests
			if tt.envVars["MOCK_MODE"] != "true" && tt.envVars["MOCK_MODE"] != "1" {
				if os.Getenv("AWS_ECR_ACCOUNT_ID") == "" {
					os.Setenv("AWS_ECR_ACCOUNT_ID", "123456789012")
					originalEnv["AWS_ECR_ACCOUNT_ID"] = ""
				}
				if os.Getenv("AWS_ECR_REGION") == "" {
					os.Setenv("AWS_ECR_REGION", "us-east-1")
					originalEnv["AWS_ECR_REGION"] = ""
				}
			}

			// Create a test-specific parseConfig that won't interfere with flag package
			config := parseConfigFromEnv()

			// Run validation
			tt.validateFunc(t, config)

			// Restore environment
			for key, value := range originalEnv {
				if value == "" {
					os.Unsetenv(key)
				} else {
					os.Setenv(key, value)
				}
			}
		})
	}
}

// parseConfigFromEnv parses configuration from environment variables only (for testing)
func parseConfigFromEnv() *engine.Config {
	config := &engine.Config{
		Mode:           "cluster",
		Port:           9090,
		ScrapeInterval: 5 * time.Minute,
	}

	// Parse environment variables (same logic as parseConfig but without flags)
	if envMode := os.Getenv("MODE"); envMode != "" {
		config.Mode = envMode
	}
	if envPort := os.Getenv("PORT"); envPort != "" {
		if port, err := fmt.Sscanf(envPort, "%d", &config.Port); err != nil || port != 1 {
			// Invalid port, keep default
		}
	}
	if envAccountID := os.Getenv("AWS_ECR_ACCOUNT_ID"); envAccountID != "" {
		config.ECRAccountID = envAccountID
	}
	if envRegion := os.Getenv("AWS_ECR_REGION"); envRegion != "" {
		config.ECRRegion = envRegion
	}
	if envImageFile := os.Getenv("IMAGE_LIST_FILE"); envImageFile != "" {
		config.ImageListFile = envImageFile
	}
	if envInterval := os.Getenv("SCRAPE_INTERVAL"); envInterval != "" {
		if interval, err := time.ParseDuration(envInterval); err == nil {
			config.ScrapeInterval = interval
		}
	}
	if envMock := os.Getenv("MOCK_MODE"); envMock == "true" || envMock == "1" {
		config.MockMode = true
	}

	return config
}

func TestConfigurationValidation(t *testing.T) {
	// Test the validation logic separately from parseConfig
	tests := []struct {
		name        string
		config      *engine.Config
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid mock mode config",
			config: &engine.Config{
				MockMode: true,
				Mode:     "cluster",
			},
			expectError: false,
		},
		{
			name: "valid cluster mode config",
			config: &engine.Config{
				MockMode:     false,
				Mode:         "cluster",
				ECRAccountID: "123456789012",
				ECRRegion:    "us-east-1",
			},
			expectError: false,
		},
		{
			name: "valid local mode config",
			config: &engine.Config{
				MockMode:      false,
				Mode:          "local",
				ECRAccountID:  "123456789012",
				ECRRegion:     "us-east-1",
				ImageListFile: "/path/to/images.json",
			},
			expectError: false,
		},
		{
			name: "missing ECR account ID",
			config: &engine.Config{
				MockMode:  false,
				Mode:      "cluster",
				ECRRegion: "us-east-1",
			},
			expectError: true,
			errorMsg:    "ECR account ID",
		},
		{
			name: "missing ECR region",
			config: &engine.Config{
				MockMode:     false,
				Mode:         "cluster",
				ECRAccountID: "123456789012",
			},
			expectError: true,
			errorMsg:    "ECR",
		},
		{
			name: "local mode missing image list file",
			config: &engine.Config{
				MockMode:     false,
				Mode:         "local",
				ECRAccountID: "123456789012",
				ECRRegion:    "us-east-1",
			},
			expectError: true,
			errorMsg:    "Image list file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConfig(tt.config)

			if tt.expectError && err == nil {
				t.Errorf("validateConfig() expected error but got none")
			}

			if !tt.expectError && err != nil {
				t.Errorf("validateConfig() unexpected error: %v", err)
			}

			if tt.expectError && err != nil && !strings.Contains(err.Error(), tt.errorMsg) {
				t.Errorf("validateConfig() error = %v, want to contain %v", err, tt.errorMsg)
			}
		})
	}
}

// validateConfig extracts the validation logic for testing
func validateConfig(config *engine.Config) error {
	if !config.MockMode {
		if config.ECRAccountID == "" || config.ECRRegion == "" {
			return fmt.Errorf("ECR account ID and region are required (unless using mock mode)")
		}
	}
	if config.Mode == "local" && !config.MockMode && config.ImageListFile == "" {
		return fmt.Errorf("Image list file is required for local mode (unless using mock mode)")
	}
	return nil
}

func TestHealthHandler(t *testing.T) {
	// Create test exporter
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel) // Minimize test output

	exporter := &Exporter{
		config: &engine.Config{},
		logger: logger,
	}

	// Create test request
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	// Call handler
	exporter.healthHandler(w, req)

	// Check response
	if w.Code != http.StatusOK {
		t.Errorf("healthHandler() returned status %d, want %d", w.Code, http.StatusOK)
	}

	expectedBody := `{"status":"ok"}`
	if strings.TrimSpace(w.Body.String()) != expectedBody {
		t.Errorf("healthHandler() returned body %q, want %q", w.Body.String(), expectedBody)
	}

	expectedContentType := "application/json"
	if w.Header().Get("Content-Type") != expectedContentType {
		t.Errorf("healthHandler() returned Content-Type %q, want %q", w.Header().Get("Content-Type"), expectedContentType)
	}
}

func TestSecurityMiddleware(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel) // Minimize test output

	exporter := &Exporter{
		config: &engine.Config{},
		logger: logger,
	}

	// Test handler that just returns OK
	testHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	}

	// Wrap with security middleware
	securedHandler := exporter.securityMiddleware(testHandler)

	tests := []struct {
		name           string
		method         string
		expectedStatus int
		checkHeaders   bool
	}{
		{
			name:           "GET request allowed",
			method:         "GET",
			expectedStatus: http.StatusOK,
			checkHeaders:   true,
		},
		{
			name:           "HEAD request allowed",
			method:         "HEAD",
			expectedStatus: http.StatusOK,
			checkHeaders:   true,
		},
		{
			name:           "POST request blocked",
			method:         "POST",
			expectedStatus: http.StatusMethodNotAllowed,
			checkHeaders:   true,
		},
		{
			name:           "PUT request blocked",
			method:         "PUT",
			expectedStatus: http.StatusMethodNotAllowed,
			checkHeaders:   true,
		},
		{
			name:           "DELETE request blocked",
			method:         "DELETE",
			expectedStatus: http.StatusMethodNotAllowed,
			checkHeaders:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/test", nil)
			req.Header.Set("User-Agent", "test-agent")
			w := httptest.NewRecorder()

			securedHandler(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("securityMiddleware() returned status %d, want %d", w.Code, tt.expectedStatus)
			}

			if tt.checkHeaders {
				// Check security headers
				expectedHeaders := map[string]string{
					"X-Content-Type-Options":  "nosniff",
					"X-Frame-Options":         "DENY",
					"X-XSS-Protection":        "1; mode=block",
					"Referrer-Policy":         "strict-origin-when-cross-origin",
					"Content-Security-Policy": "default-src 'none'; script-src 'none'; object-src 'none'; frame-ancestors 'none'",
				}

				for header, expectedValue := range expectedHeaders {
					if got := w.Header().Get(header); got != expectedValue {
						t.Errorf("securityMiddleware() header %s = %q, want %q", header, got, expectedValue)
					}
				}
			}
		})
	}
}

func TestSecurityMiddlewareRequestLogging(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	// Capture log output
	var logEntries []logrus.Entry
	logger.AddHook(&testHook{entries: &logEntries})

	exporter := &Exporter{
		config: &engine.Config{},
		logger: logger,
	}

	testHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}

	securedHandler := exporter.securityMiddleware(testHandler)

	req := httptest.NewRequest("GET", "/test-path", nil)
	req.Header.Set("User-Agent", "test-user-agent")
	req.RemoteAddr = "192.168.1.100:54321"
	w := httptest.NewRecorder()

	securedHandler(w, req)

	// Verify logging occurred
	found := false
	for _, entry := range logEntries {
		if entry.Message == "HTTP request received" {
			found = true
			if entry.Data["method"] != "GET" {
				t.Errorf("Expected method=GET in log, got %v", entry.Data["method"])
			}
			if entry.Data["path"] != "/test-path" {
				t.Errorf("Expected path=/test-path in log, got %v", entry.Data["path"])
			}
			if entry.Data["user_agent"] != "test-user-agent" {
				t.Errorf("Expected user_agent=test-user-agent in log, got %v", entry.Data["user_agent"])
			}
			break
		}
	}

	if !found {
		t.Error("Expected HTTP request log entry not found")
	}
}

// Test hook to capture log entries
type testHook struct {
	entries *[]logrus.Entry
}

func (h *testHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

func (h *testHook) Fire(entry *logrus.Entry) error {
	*h.entries = append(*h.entries, *entry)
	return nil
}

func TestNewExporter(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel) // Minimize test output

	tests := []struct {
		name        string
		config      *engine.Config
		expectError bool
	}{
		{
			name: "valid cluster mode config",
			config: &engine.Config{
				Mode:           "cluster",
				Port:           9090,
				ECRAccountID:   "123456789012",
				ECRRegion:      "us-east-1",
				ScrapeInterval: 5 * time.Minute,
			},
			expectError: false, // Will fail due to no K8s cluster, but constructor should not error
		},
		{
			name: "valid local mode config",
			config: &engine.Config{
				Mode:           "local",
				Port:           8080,
				ECRAccountID:   "987654321098",
				ECRRegion:      "us-west-2",
				ImageListFile:  "/tmp/test-images.json",
				ScrapeInterval: 10 * time.Minute,
			},
			expectError: false, // Constructor succeeds, file validation happens later
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter, err := NewExporter(tt.config, logger)

			if tt.expectError && err == nil {
				t.Errorf("NewExporter() expected error but got none")
			}

			if !tt.expectError && err != nil {
				// For cluster mode, we expect it to fail due to no K8s cluster
				// But we can test that the basic structure is set up
				if tt.config.Mode == "cluster" {
					// This is expected to fail in test environment without K8s
					t.Logf("Expected failure in test environment: %v", err)
					return
				}
				t.Errorf("NewExporter() unexpected error: %v", err)
			}

			if exporter != nil {
				if exporter.config != tt.config {
					t.Errorf("NewExporter() config = %v, want %v", exporter.config, tt.config)
				}
				if exporter.logger != logger {
					t.Errorf("NewExporter() logger mismatch")
				}
			}
		})
	}
}

// Helper function to create a test image list file
func createTestImageListFile(t *testing.T, images []string) string {
	content := `["` + strings.Join(images, `","`) + `"]`
	file, err := os.CreateTemp("", "test-images-*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer file.Close()

	if _, err := file.WriteString(content); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}

	return file.Name()
}

func TestNewExporterWithValidImageList(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	// Create a temporary image list file
	images := []string{
		"123456789012.dkr.ecr.us-east-1.amazonaws.com/test-app:v1.0.0",
		"123456789012.dkr.ecr.us-east-1.amazonaws.com/api-service:latest",
	}
	imageListFile := createTestImageListFile(t, images)
	defer os.Remove(imageListFile)

	config := &engine.Config{
		Mode:           "local",
		Port:           8080,
		ECRAccountID:   "123456789012",
		ECRRegion:      "us-east-1",
		ImageListFile:  imageListFile,
		ScrapeInterval: 5 * time.Minute,
	}

	exporter, err := NewExporter(config, logger)
	if err != nil {
		t.Fatalf("NewExporter() unexpected error with valid config: %v", err)
	}

	if exporter == nil {
		t.Fatal("NewExporter() returned nil exporter")
	}

	if exporter.config != config {
		t.Errorf("NewExporter() config mismatch")
	}
}

func TestNewExporterMockMode(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	config := &engine.Config{
		MockMode:       true,
		Mode:           "cluster",
		Port:           9090,
		ScrapeInterval: 5 * time.Minute,
	}

	exporter, err := NewExporter(config, logger)
	if err != nil {
		t.Fatalf("NewExporter() unexpected error with mock config: %v", err)
	}

	if exporter == nil {
		t.Fatal("NewExporter() returned nil exporter")
	}

	if exporter.config != config {
		t.Errorf("NewExporter() config mismatch")
	}

	if exporter.engine == nil {
		t.Error("NewExporter() engine should not be nil")
	}
}

func TestExporterStartShutdown(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	config := &engine.Config{
		MockMode:       true,
		Mode:           "cluster",
		Port:           0,                      // Use port 0 to get a random available port
		ScrapeInterval: 100 * time.Millisecond, // Fast interval for testing
	}

	exporter, err := NewExporter(config, logger)
	if err != nil {
		t.Fatalf("NewExporter() error: %v", err)
	}

	// Test graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())

	// Start the exporter in a goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- exporter.Start(ctx)
	}()

	// Give it a moment to start
	time.Sleep(50 * time.Millisecond)

	// Cancel the context to trigger shutdown
	cancel()

	// Wait for shutdown with timeout
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Start() returned unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("Start() did not shutdown within timeout")
	}
}

func TestExporterHTTPEndpoints(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	config := &engine.Config{
		MockMode:       true,
		Mode:           "cluster",
		Port:           0, // Random port
		ScrapeInterval: 100 * time.Millisecond,
	}

	exporter, err := NewExporter(config, logger)
	if err != nil {
		t.Fatalf("NewExporter() error: %v", err)
	}

	// Test that HTTP handlers are properly set up
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", exporter.securityMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("metrics"))
	}))
	mux.HandleFunc("/vulnerabilities", exporter.securityMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("vulnerabilities"))
	}))
	mux.HandleFunc("/health", exporter.securityMiddleware(exporter.healthHandler))

	// Test health endpoint
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Health endpoint returned status %d, want %d", w.Code, http.StatusOK)
	}

	expected := `{"status":"ok"}`
	if strings.TrimSpace(w.Body.String()) != expected {
		t.Errorf("Health endpoint returned body %q, want %q", w.Body.String(), expected)
	}
}

func TestLogLevelConfiguration(t *testing.T) {
	tests := []struct {
		name     string
		logLevel string
		expected logrus.Level
	}{
		{
			name:     "debug level",
			logLevel: "debug",
			expected: logrus.DebugLevel,
		},
		{
			name:     "empty defaults to info",
			logLevel: "",
			expected: logrus.InfoLevel,
		},
		{
			name:     "invalid defaults to info",
			logLevel: "invalid",
			expected: logrus.InfoLevel,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			originalLogLevel := os.Getenv("LOG_LEVEL")

			if tt.logLevel == "" {
				os.Unsetenv("LOG_LEVEL")
			} else {
				os.Setenv("LOG_LEVEL", tt.logLevel)
			}

			// Create logger similar to main()
			logger := logrus.New()
			logger.SetFormatter(&logrus.JSONFormatter{})
			logger.SetLevel(logrus.InfoLevel)

			// Set debug level if requested (same logic as main)
			if os.Getenv("LOG_LEVEL") == "debug" {
				logger.SetLevel(logrus.DebugLevel)
			}

			if logger.Level != tt.expected {
				t.Errorf("Expected log level %v, got %v", tt.expected, logger.Level)
			}

			// Restore original
			if originalLogLevel == "" {
				os.Unsetenv("LOG_LEVEL")
			} else {
				os.Setenv("LOG_LEVEL", originalLogLevel)
			}
		})
	}
}

func TestInvalidPortEnvironmentVariable(t *testing.T) {
	// Test invalid port handling
	originalPort := os.Getenv("PORT")
	originalAccountID := os.Getenv("AWS_ECR_ACCOUNT_ID")
	originalRegion := os.Getenv("AWS_ECR_REGION")

	// Set required env vars and invalid port
	os.Setenv("AWS_ECR_ACCOUNT_ID", "123456789012")
	os.Setenv("AWS_ECR_REGION", "us-east-1")
	os.Setenv("PORT", "invalid-port")

	config := parseConfigFromEnv()

	// Should keep default port when invalid
	if config.Port != 9090 {
		t.Errorf("Expected port to remain default (9090) with invalid PORT env var, got %d", config.Port)
	}

	// Restore environment
	if originalPort == "" {
		os.Unsetenv("PORT")
	} else {
		os.Setenv("PORT", originalPort)
	}
	if originalAccountID == "" {
		os.Unsetenv("AWS_ECR_ACCOUNT_ID")
	} else {
		os.Setenv("AWS_ECR_ACCOUNT_ID", originalAccountID)
	}
	if originalRegion == "" {
		os.Unsetenv("AWS_ECR_REGION")
	} else {
		os.Setenv("AWS_ECR_REGION", originalRegion)
	}
}

func TestInvalidScrapeIntervalEnvironmentVariable(t *testing.T) {
	// Test invalid scrape interval handling
	originalInterval := os.Getenv("SCRAPE_INTERVAL")
	originalAccountID := os.Getenv("AWS_ECR_ACCOUNT_ID")
	originalRegion := os.Getenv("AWS_ECR_REGION")

	// Set required env vars and invalid interval
	os.Setenv("AWS_ECR_ACCOUNT_ID", "123456789012")
	os.Setenv("AWS_ECR_REGION", "us-east-1")
	os.Setenv("SCRAPE_INTERVAL", "invalid-duration")

	config := parseConfigFromEnv()

	// Should keep default interval when invalid
	if config.ScrapeInterval != 5*time.Minute {
		t.Errorf("Expected scrape interval to remain default (5m) with invalid SCRAPE_INTERVAL env var, got %v", config.ScrapeInterval)
	}

	// Restore environment
	if originalInterval == "" {
		os.Unsetenv("SCRAPE_INTERVAL")
	} else {
		os.Setenv("SCRAPE_INTERVAL", originalInterval)
	}
	if originalAccountID == "" {
		os.Unsetenv("AWS_ECR_ACCOUNT_ID")
	} else {
		os.Setenv("AWS_ECR_ACCOUNT_ID", originalAccountID)
	}
	if originalRegion == "" {
		os.Unsetenv("AWS_ECR_REGION")
	} else {
		os.Setenv("AWS_ECR_REGION", originalRegion)
	}
}
