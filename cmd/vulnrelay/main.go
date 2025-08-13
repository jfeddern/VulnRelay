// ABOUTME: Entry point for the VulnRelay vulnerability collection service.
// ABOUTME: Handles initialization, configuration parsing, and starts the HTTP server.

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jfeddern/VulnRelay/internal/engine"
	"github.com/jfeddern/VulnRelay/internal/metrics"
	"github.com/jfeddern/VulnRelay/internal/providers"
	"github.com/jfeddern/VulnRelay/internal/server"

	"github.com/sirupsen/logrus"
)

func main() {
	config := parseConfig()

	// Set up structured logging
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetLevel(logrus.InfoLevel)

	// Set debug level if requested
	if os.Getenv("LOG_LEVEL") == "debug" {
		logger.SetLevel(logrus.DebugLevel)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown gracefully
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		logger.Info("Received shutdown signal")
		cancel()
	}()

	// Start the exporter
	exporter, err := NewExporter(config, logger)
	if err != nil {
		logger.WithError(err).Fatal("Failed to create exporter")
	}

	if err := exporter.Start(ctx); err != nil {
		logger.WithError(err).Fatal("Failed to start exporter")
	}
}

func parseConfig() *engine.Config {
	config := &engine.Config{}

	flag.StringVar(&config.Mode, "mode", "cluster", "Operation mode: cluster or local")
	flag.IntVar(&config.Port, "port", 9090, "Port to expose metrics on")
	flag.StringVar(&config.ECRAccountID, "ecr-account-id", "", "AWS account ID for ECR registry")
	flag.StringVar(&config.ECRRegion, "ecr-region", "", "AWS region for ECR registry")
	flag.StringVar(&config.ImageListFile, "image-list-file", "", "Path to JSON file with image list (required for local mode)")
	flag.DurationVar(&config.ScrapeInterval, "scrape-interval", 5*time.Minute, "Interval to refresh data from ECR")
	flag.BoolVar(&config.MockMode, "mock", false, "Enable mock mode for local testing (no external API calls)")
	flag.Parse()

	// Override with environment variables if set
	if envMode := os.Getenv("MODE"); envMode != "" {
		config.Mode = envMode
	}
	if envPort := os.Getenv("PORT"); envPort != "" {
		if port, err := fmt.Sscanf(envPort, "%d", &config.Port); err != nil || port != 1 {
			log.Printf("Invalid PORT environment variable: %s", envPort)
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

	// Validate configuration
	if !config.MockMode {
		if config.ECRAccountID == "" || config.ECRRegion == "" {
			log.Fatal("ECR account ID and region are required (unless using mock mode)")
		}
	}
	if config.Mode == "local" && !config.MockMode && config.ImageListFile == "" {
		log.Fatal("Image list file is required for local mode (unless using mock mode)")
	}

	return config
}

type Exporter struct {
	config *engine.Config
	logger *logrus.Logger
	engine *engine.Engine
}

func NewExporter(config *engine.Config, logger *logrus.Logger) (*Exporter, error) {
	logger.WithFields(logrus.Fields{
		"mode":            config.Mode,
		"port":            config.Port,
		"ecr_region":      config.ECRRegion,
		"scrape_interval": config.ScrapeInterval,
	}).Info("Initializing VulnRelay")

	// Create providers using factory
	providerConfig := &providers.ProviderConfig{
		Mode:          config.Mode,
		ECRAccountID:  config.ECRAccountID,
		ECRRegion:     config.ECRRegion,
		ImageListFile: config.ImageListFile,
		MockMode:      config.MockMode,
	}

	cloudProvider, err := providers.CreateCloudProvider(providerConfig, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create cloud provider: %w", err)
	}

	vulnSource, err := providers.CreateVulnerabilitySource(context.Background(), providerConfig, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create vulnerability source: %w", err)
	}

	// Create vulnerability engine
	vulnEngine := engine.NewEngine(cloudProvider, vulnSource, config, logger)

	return &Exporter{
		config: config,
		logger: logger,
		engine: vulnEngine,
	}, nil
}

func (e *Exporter) Start(ctx context.Context) error {
	// Start the vulnerability engine
	go e.engine.Start(ctx)

	// Create HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", e.securityMiddleware(metrics.CreateMetricsHandler(e.engine, e.logger)))
	mux.HandleFunc("/vulnerabilities", e.securityMiddleware(server.CreateVulnerabilitiesHandler(e.engine, e.logger)))
	mux.HandleFunc("/health", e.securityMiddleware(e.healthHandler))

	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", e.config.Port),
		Handler:           mux,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MB
	}

	go func() {
		<-ctx.Done()
		e.logger.Info("Shutting down HTTP server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		server.Shutdown(shutdownCtx)
	}()

	e.logger.WithFields(logrus.Fields{
		"port": e.config.Port,
		"mode": e.config.Mode,
	}).Info("Starting HTTP server")

	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		return err
	}

	return nil
}

func (e *Exporter) securityMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'none'; object-src 'none'; frame-ancestors 'none'")

		// Only allow specific HTTP methods
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Log the request
		e.logger.WithFields(logrus.Fields{
			"method":     r.Method,
			"path":       r.URL.Path,
			"remote_ip":  r.RemoteAddr,
			"user_agent": r.UserAgent(),
		}).Debug("HTTP request received")

		next(w, r)
	}
}

func (e *Exporter) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"ok"}`)
}
